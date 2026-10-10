import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspect} from 'node:util';
import {readFileSync} from 'node:fs';
import {validateOfflineSemgrepCEFindings as verify}
 from '../candidate/semgrep-ce-offline-contract.mjs';
const path='src/PRIVATE-SYNTHETIC-demo.mjs';
const diff=Buffer.from('diff --git a/'+path+' b/'+path+'\n'+
 'index 1111111..2222222 100644\n--- a/'+path+'\n+++ b/'+path+
 '\n@@ -2 +2 @@\n-const x = 1;\n+eval(untrusted);\n');
const h=x=>createHash('sha256').update(x).digest('hex');
const make=(findings=[],errors=[])=>JSON.stringify({
 version:'1.136.0',results:findings,errors
});
const finding=(line=2,extra={})=>({
 check_id:'devfactory.javascript-dynamic-eval',path,
 start:{line,col:1},end:{line,col:10},
 extra:{severity:'ERROR',message:'SYNTHETIC_PRIVATE_SOURCE_TEXT',
  lines:'SECRET_SOURCE_NEVER_SHOW',...extra}
});
const ctx=rawJson=>({
 rawJson,runId:'semgrep-ce-synthetic-run-0001',
 trustedDiffBytes:diff,expectedDiffSha256:h(diff),
 trustedChangedPaths:[path],rulePackSha256:'a'.repeat(64),scanExitCode:0
});
test('Semgrep rules are bound to added source; private output never serialized',()=>{
 const x=verify(ctx(make([finding()])));
 assert.equal(x.provisionalState,'FAIL');
 assert.equal(x.blockingFindings,1);
 assert.equal(x.ruleFindings,1);
 assert.equal(x.approvalAuthorized,false);
 assert.equal(x.independentReviewVerified,false);
 assert.equal(x.semgrepExecutedByThisModule,false);
 const report=JSON.parse(x.privateCanonicalReportBytes);
 assert.equal(report.findings[0].path,path);
 assert.equal(report.findings[0].line,2);
 assert.match(report.findings[0].fingerprint,/^[0-9a-f]{64}$/);
 for(const value of [JSON.stringify(x),JSON.stringify({...x}),inspect(x),
   x.privateCanonicalReportBytes.toString('utf8')])
   assert.doesNotMatch(value,/SYNTHETIC_PRIVATE_SOURCE_TEXT|SECRET_SOURCE_NEVER_SHOW/);
 assert.doesNotMatch(JSON.stringify(x),/PRIVATE-SYNTHETIC/);
 const copy=x.privateCanonicalReportBytes;copy.fill(0);
 assert.ok(x.privateCanonicalReportBytes.toString().includes(path));
});
test('empty scan is INCONCLUSIVE, old findings are only counted',()=>{
 const empty=verify(ctx(make([])));
 assert.equal(empty.provisionalState,'INCONCLUSIVE');
 assert.equal(empty.approvalAuthorized,false);
 const prior=verify(ctx(make([finding(1)])));
 assert.equal(prior.provisionalState,'INCONCLUSIVE');
 assert.equal(prior.ruleFindings,0);
 assert.equal(prior.excludedPreexistingCount,1);
});
test('Semgrep scan errors, incorrect path/severity and duplicate findings fail closed',()=>{
 for(const bad of [
  make([finding()],[{type:'ParseError'}]),
  make([{...finding(),path:'../../secret.mjs'}]),
  make([{...finding(),check_id:'p/ci'}]),
  make([finding(2,{severity:'BANANAS'})]),
  make([finding(2,{is_ignored:true})]),
  make([finding(),finding()]),
  make([{...finding(),end:{line:1,col:1}}]),
  make([finding()]).replace('1.136.0','unknown'),
  'not-json'
 ]) assert.throws(()=>verify(ctx(bad)),/SEMGREP_CE_/);
});
test('bad content hash, process exit, path coverage, or rule bundle is forbidden',()=>{
 for(const patch of [
  {expectedDiffSha256:'b'.repeat(64)},
  {trustedChangedPaths:['elsewhere.mjs']},
  {rulePackSha256:'bad'},
  {scanExitCode:2}
 ])assert.throws(()=>verify({...ctx(make([])),...patch}),/SEMGREP_CE_/);
});
test('local Semgrep CE rule pack has no remote dependencies',()=>{
 const rules=readFileSync(new URL('../rules/reviewer-b-semgrep-ce.yml',import.meta.url),'utf8');
 assert.match(rules,/devfactory\.javascript-dynamic-eval/);
 assert.match(rules,/devfactory\.javascript-dynamic-function/);
 assert.doesNotMatch(rules,/https?:\/\/|p\/ci|secrets\.|api\.semgrep/);
});
