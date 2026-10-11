import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root=path.resolve(import.meta.dirname,'..');
const candidate=path.join(root,'candidate');
const names=readdirSync(candidate).filter(x=>x.endsWith('.mjs'));
const networkFiles=new Set([
  'github-app-auth.mjs',
  'github-read-only.mjs',
  'github-review-readback.mjs'
]);

test('candidate source cannot execute OS commands, log secrets or acquire ambient credentials',()=>{
  assert.ok(names.length>=9);
  for(const filename of names){
    const content=readFileSync(path.join(candidate,filename),'utf8');
    assert.doesNotMatch(content,/\bprocess\.(?:env|stdout|stderr)\b/,filename);
    assert.doesNotMatch(content,/\bconsole\.(?:log|debug|info|warn|error)\s*\(/,filename);
    assert.doesNotMatch(content,/\b(?:eval|exec|execFile|spawn|fork)\s*\(/,filename);
    assert.doesNotMatch(content,/\bimport\s*\(/,filename);
    assert.doesNotMatch(content,/(?:^|\n)\s*import\s+.*\b(?:child_process|https|http|net|tls)\b/,filename);
    assert.doesNotMatch(content,/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,filename);
  }
});

test('candidate network requests are restricted to scoped GitHub adapters',()=>{
  for(const filename of names){
    const content=readFileSync(path.join(candidate,filename),'utf8');
    if(!networkFiles.has(filename)){
      assert.doesNotMatch(content,/\b(?:fetchImpl|globalThis\.fetch|fetch)\s*\(/,
        filename+' must not access the network');
    } else {
      assert.match(content,/api\.github\.com/,filename);
    }
  }
});

test('production publisher mutation cannot be introduced to PR prototype',()=>{
  for(const filename of names){
    const content=readFileSync(path.join(candidate,filename),'utf8');
    assert.doesNotMatch(content,/(?:\bmerge_pull_request\b|\bcreateReview\s*\(|\bsubmitReview\s*\()/,
      filename);
    assert.doesNotMatch(content,/\b(?:APPROVE|REQUEST_CHANGES)\b\s*\)/,
      filename+' cannot select a native GitHub review action');
  }
});

test('no executable candidate is invoked directly by public PR CI',()=>{
  const workflow=readFileSync(path.join(root,
    '.github/workflows/reviewer-b-attestation-tests.yml'),'utf8');
  assert.match(workflow,/node --test test\/\*\.test\.mjs/);
  assert.doesNotMatch(workflow,/(?:node\s+candidate\/|secrets\.|environment\s*:)/);
});
