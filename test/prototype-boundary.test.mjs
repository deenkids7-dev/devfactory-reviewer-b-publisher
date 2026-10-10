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
    assert.doesNotMatch(text,/\b(?:import|export)\s*\(\s*[^)]/);
    assert.doesNotMatch(text,/from\s*['"](?:node:(?:child_process|https|http|net|tls)|@octokit|axios)/);
  }
});

test('no workflow has access to private App secrets, write token or privileged triggers',()=>{
  const files=readdirSync(workflows).filter(name=>/\.ya?ml$/.test(name));
  assert.ok(files.length>=2);
  for(const filename of files){
    const contents=readFileSync(path.join(workflows,filename),'utf8');
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
