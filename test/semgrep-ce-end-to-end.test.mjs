import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspect} from 'node:util';
import {runFailOnlyStaticDiffAudit}
 from '../candidate/fail-only-static-audit.mjs';
import {normalizeUntrustedModelFindings}
 from '../candidate/semantic-review-request.mjs';
import {validateOfflineSemgrepCEFindings}
 from '../candidate/semgrep-ce-offline-contract.mjs';
import {combineReviewerFindings}
 from '../candidate/combine-findings.mjs';

const runId='synthetic-triple-review-001';
const path='src/private-synthetic-example.mjs';
const diff=Buffer.from('diff --git a/'+path+' b/'+path+'\n'+
 'index 1111111..2222222 100644\n--- a/'+path+'\n+++ b/'+path+
 '\n@@ -1 +1 @@\n-const ok = true;\n+eval(untrusted);\n');
const hash=x=>createHash('sha256').update(x).digest('hex');
function run(semgrepFindings=[]){
 const p=[path],sha=hash(diff);
 const stat=runFailOnlyStaticDiffAudit({diffBytes:diff,runId});
 const llm=normalizeUntrustedModelFindings({
   rawModelOutput:JSON.stringify({summary:'Synthetic, no clear model issue',findings:[]}),
   runId,trustedChangedPaths:p
 });
 const sg=validateOfflineSemgrepCEFindings({
   rawJson:JSON.stringify({version:'1.136.0',errors:[],results:semgrepFindings}),
   runId,trustedDiffBytes:diff,expectedDiffSha256:sha,
   trustedChangedPaths:p,rulePackSha256:'b'.repeat(64)
 });
 return combineReviewerFindings({
   staticReportBytes:stat.reportBytes,
   semanticReportBytes:llm.reportBytes,
   semgrepReportBytes:sg.privateCanonicalReportBytes,
   requireSemgrepCE:true,changedPaths:p
 });
}
const semgrepHit={
 check_id:'devfactory.javascript-dynamic-eval',
 path,start:{line:1,col:1},end:{line:1,col:8},
 extra:{severity:'ERROR',message:'SYNTHETIC_PRIVATE_ADDED_CODE',
   lines:'DO_NOT_ECHO_SYNTHETIC_PRIVATE_SOURCE'}
};
test('Semgrep CE provisional finding survives clean model and empty static audit',()=>{
 const x=run([semgrepHit]);
 assert.equal(x.provisionalState,'FAIL');
 assert.equal(x.blockingFindings,1);
 assert.equal(x.semgrepReportIncluded,true);
 assert.equal(x.independentReviewVerified,false);
 assert.equal(x.approvalAuthorized,false);
 const full=JSON.parse(x.reportBytes);
 assert.equal(full.findings[0].path,path);
 assert.equal(full.findings[0].line,1);
 assert.equal(full.findings.length,1);
 for(const serialized of [JSON.stringify(x),JSON.stringify({...x}),inspect(x),
    x.reportBytes.toString('utf8')]){
   assert.doesNotMatch(serialized,/SYNTHETIC_PRIVATE_ADDED_CODE|DO_NOT_ECHO_SYNTHETIC_PRIVATE_SOURCE/);
 }
});
test('three clean synthetic reports remain INCONCLUSIVE rather than APPROVED',()=>{
 const x=run([]);
 assert.equal(x.provisionalState,'INCONCLUSIVE');
 assert.equal(x.blockingFindings,0);
 assert.equal(x.approvalAuthorized,false);
 assert.equal(x.publishEvent,null);
});
