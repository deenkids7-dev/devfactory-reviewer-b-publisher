import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root=path.resolve(import.meta.dirname,'..');
const src=path.join(root,'src');
const workflows=path.join(root,'.github','workflows');

test('prototype has no privileged runtime entrypoint or secret access',()=>{
  const sources=readdirSync(src).filter(name=>name.endsWith('.mjs'));
  assert.ok(sources.length>=4);
  for(const filename of sources){
    const text=readFileSync(path.join(src,filename),'utf8');
    assert.doesNotMatch(text,/\bprocess\.env\b/);
    assert.doesNotMatch(text,/\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/);
    assert.doesNotMatch(text,/\b(?:exec|execFile|spawn|fork|eval)\s*\(/);
    assert.doesNotMatch(text,/\b(?:Octokit|createAppAuth|createTokenAuth)\s*\(/);
    assert.doesNotMatch(text,/\b(?:PRIVATE_KEY|APP_TOKEN|GITHUB_TOKEN|GH_TOKEN)\b\s*=/);
    assert.doesNotMatch(text,/\bhttps?:\/\/api\.github\.com\/repos\/.*\/reviews\b/);
    assert.doesNotMatch(text,/\bimport\s*\(/);
    assert.doesNotMatch(text,/from\s*['"](?:node:(?:child_process|https|http|net|tls)|@octokit|axios)/);
  }
});

test('no workflow has access to private App secrets, write token or privileged triggers',()=>{
  const files=readdirSync(workflows).filter(name=>/\.ya?ml$/.test(name));
  assert.ok(files.length>=2);
  for(const filename of files){
    const contents=readFileSync(path.join(workflows,filename),'utf8');
    // GitHub job-level permissions can OVERRIDE a safe workflow-level block.
    // Permit exactly one root permissions mapping; reject ANY nested one.
    assert.equal((contents.match(/^permissions\s*:/gm)||[]).length,1);
    assert.doesNotMatch(contents,/^[ \t]+permissions\s*:/m);
    if(filename==='reviewer-b-private-readonly-preflight.yml'){
      // ONLY this separately reviewed, operator-held job may receive
      // a private App PEM, and it can only read the PRIVATE target.
      const granted=contents.match(/^permissions:\n((?: {2}[^\n]+\n)+)/m)?.[1];
      assert.equal(granted,'  contents: read\n');
      const guard=contents.match(/^    if: (.+)$/m)?.[1];
      assert.equal(guard,"\${{ github.repository == 'devfactory-reviewer-trust/devfactory-reviewer-b-publisher' && github.ref == 'refs/heads/main' && github.actor == 'devfactory-reviewer-service' && github.event_name == 'workflow_dispatch' }}");
      assert.match(contents,/^on:\n  workflow_dispatch:/m);
      assert.match(contents,/environment:\s*reviewer-b-publish/);
      assert.equal((contents.match(/secrets\./g)||[]).length,1);
      assert.match(contents,/secrets\.REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM/);
      assert.match(contents,/tarball\/\$\{GH_SHA\}/);
      assert.match(contents,/node scripts\/protected-private-read-entrypoint\.mjs/);
      assert.equal((contents.match(/^      - name:/gm)||[]).length,2);
      assert.doesNotMatch(contents,/\b(?:pull_request|pull_request_target|workflow_run|workflow_call|push|schedule)\s*:/);
      assert.doesNotMatch(contents,/\b[A-Za-z-]+\s*:\s*write\b/);
      assert.doesNotMatch(contents,/\b(?:actions\/checkout|id-token|attestations)\b/);
      continue;
    }
    if(filename==='reviewer-b-keyless-synthetic-proof.yml'){
      // One audited manual synthetic OIDC probe: no PR trigger or private
      // source, pinned official action, no publisher signing credentials.
      const granted=contents.match(/^permissions:\n((?: {2}[^\n]+\n)+)/m)?.[1];
      assert.equal(granted,'  id-token: write\n  attestations: write\n');
      assert.match(contents,/workflow_dispatch\s*:/);
      assert.match(contents,/environment:\s*reviewer-b-publish/);
      assert.match(contents,/github\.ref == 'refs\/heads\/main'/);
      assert.match(contents,/github\.event_name == 'workflow_dispatch'/);
      assert.match(contents,/github\.actor == 'devfactory-reviewer-service'/);
      assert.match(contents,/github\.repository == 'devfactory-reviewer-trust\/devfactory-reviewer-b-publisher'/);
      const events=contents.match(/^on:\n((?: {2}[^\n]+\n)+)/m)?.[1];
      assert.equal(events,'  workflow_dispatch:\n');
      const gate=contents.match(/^    if: (.+)$/m)?.[1];
      assert.equal(gate,"\${{ github.repository == 'devfactory-reviewer-trust/devfactory-reviewer-b-publisher' && github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && github.actor == 'devfactory-reviewer-service' }}");
      assert.match(contents,/actions\/attest@1e69f48acb82d1966a394da916b4c1698aa569d6/);
      assert.equal((contents.match(/^      - name:/gm)||[]).length,2);
      assert.match(contents,/create-storage-record:\s*false/);
      assert.match(contents,/not_a_review/);
      assert.doesNotMatch(contents,/\b(?:pull_request|pull_request_target|workflow_run|workflow_call|schedule|push)\s*:/);
      assert.doesNotMatch(contents,/\b(?:secrets\.|GITHUB_TOKEN|GH_TOKEN|checkout|curl|wget|gh api)\b/);
      assert.doesNotMatch(contents,/\b(?:contents|pull-requests|issues|actions|checks|administration)\s*:\s*write\b/);
      continue;
    }
    assert.doesNotMatch(contents,/\b[A-Za-z][A-Za-z-]*\s*:\s*write\b/);
    assert.doesNotMatch(contents,/\bpermissions\s*:\s*write-all\b/);
    if(filename==='reviewer-b-environment-hold-probe.yml'){
      // This one workflow is intentionally deployed to the protected
      // environment AFTER independent review on protected main. No secret,
      // PR trigger, token, checkout or network access is permitted.
      assert.match(contents,/permissions:\s*\{\s*\}/);
      assert.match(contents,/workflow_dispatch\s*:/);
      assert.match(contents,/environment:\s*reviewer-b-publish/);
      assert.doesNotMatch(contents,/\b(?:pull_request|pull_request_target|workflow_run|workflow_call|push|schedule)\s*:/);
      assert.doesNotMatch(contents,/(?:secrets\.|github\.token|GITHUB_TOKEN|GH_TOKEN|\bcurl\b|\bwget\b|\bcheckout\b|\bfetch\b)/);
      assert.doesNotMatch(contents,/\b(?:id-token|pull-requests|contents)\s*:\s*write\b/);
      continue;
    }
    assert.match(contents,/permissions:\s*\n\s*contents:\s*read\b/);
    assert.doesNotMatch(contents,/\bpull_request_target\s*:/);
    assert.doesNotMatch(contents,/\bworkflow_run\s*:/);
    assert.doesNotMatch(contents,/\bworkflow_call\s*:/);
    assert.doesNotMatch(contents,/\bsecrets\s*\./);
    assert.doesNotMatch(contents,/\bpermissions:\s*(?:write-all|\{)/);
    assert.doesNotMatch(contents,/\b(?:id-token|pull-requests|contents)\s*:\s*write\b/);
    assert.doesNotMatch(contents,/\benvironment\s*:/);
    assert.doesNotMatch(contents,/\b(?:push|schedule)\s*:/);
  }
});
