import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root=resolve(import.meta.dirname,'..');
const workflow=readFileSync(resolve(root,
  '.github/workflows/reviewer-b-keyless-synthetic-proof.yml'),'utf8');
const runbook=readFileSync(resolve(root,
  'docs/KEYLESS-PROVENANCE-SYNTHETIC.md'),'utf8');
const manual=readFileSync(resolve(root,
  'docs/REVIEWER-B-MANUAL-RELEASE-GATES.md'),'utf8');
const repo='devfactory-reviewer-trust/devfactory-reviewer-b-publisher';

test('synthetic subject byte construction matches verification instructions',()=>{
  const getPrint=(source)=>source.split('\n').find(line=>
    line.trimStart().startsWith('printf ') &&
    line.includes('reviewer-b-synthetic-proof.json'))?.trim();
  const command=getPrint(workflow);
  assert.ok(command,'workflow must create a known synthetic subject');
  assert.equal(command,getPrint(runbook));
  const pattern=/^printf '%s\\n' '(\{.*\})' > reviewer-b-synthetic-proof\.json$/;
  const match=command.match(pattern);
  assert.ok(match,'use one canonical printf with newline');
  assert.deepEqual(JSON.parse(match[1]),{
    schema:'devfactory.synthetic-provenance.v1',
    not_a_review:true,private_code:false
  });
  assert.match(runbook,/gh attestation verify reviewer-b-synthetic-proof\.json/);
  assert.ok(runbook.includes('--signer-workflow '+
    repo+'/.github/workflows/reviewer-b-keyless-synthetic-proof.yml'));
});

test('manual release plan never asserts live Reviewer B success',()=>{
  assert.match(manual,/two GitHub accounts only/);
  assert.match(manual,/co-owned/);
  assert.match(manual,/not.*independent human judgment/i);
  assert.match(manual,/Current PR #900 does \*\*not\*\* implement it/);
  assert.match(manual,/No model comments, owner review/);
  assert.match(manual,/Contents: Read/);
  assert.match(manual,/Issues: Read/);
  assert.match(manual,/canonical HUMAN_GO/);
  assert.match(manual,/STOP/);
  assert.doesNotMatch(workflow,/secrets\.|pull_request_target:|workflow_run:/);
});
