import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const file=path.resolve(import.meta.dirname,
  '../.github/workflows/reviewer-b-environment-hold-probe.yml');
const raw=readFileSync(file,'utf8');
const deny=(pattern,name)=>assert.doesNotMatch(raw,pattern,name);

test('no-secret environment gate is manual-only and scoped to protected main',()=>{
  assert.match(raw,/workflow_dispatch\s*:/);
  assert.match(raw,/permissions:\s*\{\s*\}/);
  assert.match(raw,/environment:\s*reviewer-b-publish/);
  assert.match(raw,/github\.repository == 'devfactory-reviewer-trust\/devfactory-reviewer-b-publisher'/);
  assert.match(raw,/github\.ref == 'refs\/heads\/main'/);
  assert.match(raw,/github\.actor == 'devfactory-reviewer-service'/);
  assert.match(raw,/github\.event_name/);
  assert.match(raw,/runs-on:\s*ubuntu-latest/);
  deny(/\b(?:pull_request|pull_request_target|workflow_run|workflow_call|schedule|push)\s*:/,
    'Only manually dispatched workflow may request approval');
});
test('no-secret environment gate cannot checkout, fetch or print private data',()=>{
  for(const [pattern,name] of [
    [/\bsecrets\b/,'secret variable'],
    [/\bGITHUB_TOKEN\b/,'default token access'],
    [/\bid-token\s*:/,'OIDC minting'],
    [/\b(?:curl|wget|gh api|git clone|actions\/checkout)\b/i,'network or checkout'],
    [/\b(?:uses:|container:|services:)\b/,'privileged jobs or dependencies'],
    [/\$\{\{\s*inputs\./,'untrusted workflow inputs'],
    [/\b(?:APPROVE|REQUEST_CHANGES|merge)\b/,'live review or merge']
  ]) deny(pattern,name);
  assert.match(raw,/NO_SECRETS_APPROVAL_GATE_RELEASED/);
});
