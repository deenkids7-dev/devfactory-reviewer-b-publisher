import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {approvedReadOnlyExecutionContext,executeProtectedReadOnlyPreflight}
  from '../scripts/protected-private-read-entrypoint.mjs';
const workflow=readFileSync(resolve(import.meta.dirname,
 '../.github/workflows/reviewer-b-private-readonly-preflight.yml'),'utf8');
const context=()=>({
 GITHUB_REPOSITORY:'devfactory-reviewer-trust/devfactory-reviewer-b-publisher',
 GITHUB_REF:'refs/heads/main',
 GITHUB_ACTOR:'devfactory-reviewer-service',
 GITHUB_EVENT_NAME:'workflow_dispatch',
 GITHUB_SHA:'a'.repeat(40),
 GITHUB_RUN_ID:'123456789',GITHUB_RUN_ATTEMPT:'1',
 REVIEWER_B_TARGET_PR:'898'
});
test('manual, actor, protected branch and immutable identity are required',()=>{
 assert.equal(approvedReadOnlyExecutionContext(context()),true);
 const patches=[
  {GITHUB_REPOSITORY:'attacker/public'},
  {GITHUB_REF:'refs/heads/feature'},
  {GITHUB_ACTOR:'deenkids7-dev'},
  {GITHUB_EVENT_NAME:'pull_request'},
  {GITHUB_SHA:'bad'},
  {GITHUB_RUN_ID:'1; echo secret'},
  {GITHUB_RUN_ATTEMPT:'0'},
  {REVIEWER_B_TARGET_PR:'../898'},
  {REVIEWER_B_TARGET_PR:'0'},
  {REVIEWER_B_TARGET_PR:'2147483648'}
 ];
 for(const patch of patches)
  assert.equal(approvedReadOnlyExecutionContext({...context(),...patch}),false);
});
test('explicit null and invalid context never throw or access ambient credentials',async()=>{
 for(const invalid of [null,undefined,[],true,'text',42]){
  assert.equal(approvedReadOnlyExecutionContext(invalid),false);
  assert.deepEqual(await executeProtectedReadOnlyPreflight(invalid),{
   code:'CONTEXT_DENIED',ok:false
  });
  assert.deepEqual(await executeProtectedReadOnlyPreflight({env:invalid}),{
   code:'CONTEXT_DENIED',ok:false
  });
 }
});
test('null options with a valid protected context are denied before PEM access',async()=>{
 const values=[{...context(),REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM:null},context()];
 for(const env of values){
  const result=await executeProtectedReadOnlyPreflight({env,fetchImpl:null});
  assert.equal(result.code,'CREDENTIAL_NOT_PROVISIONED');
  assert.equal(result.ok,false);
 }
});
test('no secret refuses and invokes neither HTTP nor model',async()=>{
 let calls=0;
 const result=await executeProtectedReadOnlyPreflight({
  env:context(),fetchImpl:async()=>{calls++;throw Error('forbidden');}
 });
 assert.deepEqual(result,{code:'CREDENTIAL_NOT_PROVISIONED',ok:false});
 assert.equal(calls,0);
});
test('malformed key is sanitized; no private failure reason leaks',async()=>{
 const result=await executeProtectedReadOnlyPreflight({
  env:{...context(),REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM:'fake'.repeat(80)},
  fetchImpl:async()=>{throw Error('never include token: SENSITIVE_VALUE');}
 });
 assert.deepEqual(result,{code:'READ_PROOF_FAILED',ok:false});
 assert.ok(!JSON.stringify(result).includes('SENSITIVE_VALUE'));
});
test('failed identity cannot even attempt to parse private credentials',async()=>{
 const result=await executeProtectedReadOnlyPreflight({
  env:{...context(),GITHUB_ACTOR:'other',
    REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM:'fake'.repeat(80)},
  fetchImpl:async()=>{throw Error('MUST_NOT_CALL_NETWORK');}
 });
 assert.deepEqual(result,{code:'CONTEXT_DENIED',ok:false});
});
test('protected workflow triggers only from main and a fixed actor',()=>{
 assert.match(workflow,/^on:\n  workflow_dispatch:/m);
 assert.match(workflow,/environment:\s*reviewer-b-publish/);
 assert.match(workflow,/github\.ref == 'refs\/heads\/main'/);
 assert.match(workflow,/github\.actor == 'devfactory-reviewer-service'/);
 assert.match(workflow,/github\.repository == 'devfactory-reviewer-trust\/devfactory-reviewer-b-publisher'/);
 assert.match(workflow,/github\.event_name == 'workflow_dispatch'/);
 assert.match(workflow,/^permissions:\n  contents: read\n/m);
 assert.doesNotMatch(workflow,/\b(?:pull_request_target|workflow_run|push|schedule)\s*:/);
 assert.doesNotMatch(workflow,/\b[A-Za-z-]+\s*:\s*write\b/);
 assert.doesNotMatch(workflow,/\b(?:actions\/checkout|secrets\.GITHUB_TOKEN|id-token|attestations)\b/);
});
test('only one protected PEM secret and no PR source checkout or GitHub reviews',()=>{
 assert.equal((workflow.match(/secrets\./g)||[]).length,1);
 assert.match(workflow,/secrets\.REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM/);
 assert.match(workflow,/tarball\/\$\{GH_SHA\}/);
 assert.doesNotMatch(workflow,/(?:POST|PATCH|PUT|DELETE)\s+https:\/\/api\.github\.com/);
 assert.doesNotMatch(workflow,/\b(?:merg|approve|review POST|curl -X)\b/i);
});
