import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { canonicalJson } from '../src/canonical.mjs';
import { combineReviewerFindings } from '../candidate/combine-findings.mjs';

const runId='synthetic-run-898';
const path='src/demo.mjs';
const make=(findings=[],summary='Synthetic findings',id=runId)=>
  Buffer.from(canonicalJson({
    schema:'devfactory.reviewer-b.findings.v1',
    run_id:id,summary,findings
  }));
const item=(hex='a',severity='high')=>({
  fingerprint:hex.repeat(64),severity,path,line:1,
  message:'Synthetic concern',evidence:'Synthetic evidence'
});
const call=(staticFindings=[],semanticFindings=[],extra={})=>
  combineReviewerFindings({
    staticReportBytes:make(staticFindings),
    semanticReportBytes:make(semanticFindings),
    changedPaths:[path],...extra
  });

test('a blocking static finding cannot be erased by a clean semantic claim',()=>{
  const result=call([item('a')],[]);
  assert.equal(result.provisionalState,'FAIL');
  assert.equal(result.blockingFindings,1);
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.independentReviewVerified,false);
  assert.equal(result.publishEvent,null);
  assert.equal(JSON.parse(result.reportBytes).findings.length,1);
});
test('a semantic blocker cannot be erased by a clear static audit',()=>{
  const result=call([],[item('b')]);
  assert.equal(result.provisionalState,'FAIL');
  assert.equal(result.blockingFindings,1);
});
test('no findings does not result in a PASS or publish authorization',()=>{
  const result=call([],[]);
  assert.equal(result.provisionalState,'INCONCLUSIVE');
  assert.equal(result.blockingFindings,0);
  assert.equal(result.approvalAuthorized,false);
});
test('combines unique findings in deterministic fingerprint order',()=>{
  const result=call([item('c')],[item('b')]);
  assert.deepEqual(JSON.parse(result.reportBytes).findings.map(f=>f.fingerprint),
    ['b'.repeat(64),'c'.repeat(64)]);
  assert.equal(result.findingCount,2);
});
test('identical duplicate finding is deduplicated',()=>{
  const result=call([item('a')],[item('a')]);
  assert.equal(result.findingCount,1);
});
test('conflicting findings for the same fingerprint fail closed',()=>{
  assert.throws(()=>call([item('a')],[{...item('a'),message:'Conflicting'}]),
    /COMBINED_REVIEW_FINDING_CONFLICT/);
});
test('run ID mismatch, missing signal and unsupported scope fail closed',()=>{
  assert.throws(()=>call([],[item('a')],{semanticReportBytes:make([],'Text','other-run')}),
    /COMBINED_REVIEW_RUN_MISMATCH/);
  assert.throws(()=>call([],[item('a')],{staticReportBytes:null}),
    /REVIEW_INPUT_UNTRUSTED/);
  assert.throws(()=>call([],[item('a')],{changedPaths:['unrelated/path']}),
    /REVIEW_FINDING_INVALID/);
});
test('too many combined findings cannot drop evidence silently',()=>{
  const statics=Array.from({length:30},(_,i)=>item(i.toString(16).padStart(2,'0').repeat(32).slice(0,1)));
  // Assign unique exact fingerprints; no individual report exceeds 50 items.
  const a=statics.map((f,i)=>({...f,fingerprint:i.toString(16).padStart(64,'0')}));
  const b=Array.from({length:30},(_,i)=>({
    ...item('f'),fingerprint:(i+30).toString(16).padStart(64,'0')
  }));
  assert.throws(()=>call(a,b),/COMBINED_REVIEW_TOO_MANY_FINDINGS/);
});

test('combined private findings cannot escape via JSON or object inspection',()=>{
 const secret='SYNTHETIC_PRIVATE_FINDING_DONT_LOG';
 const finding={...item('b'),message:secret};
 const result=call([],[finding]);
 assert.ok(result.reportBytes.toString('utf8').includes(secret));
 for(const text of [JSON.stringify(result),JSON.stringify({...result}),inspect(result)])
  assert.ok(!text.includes(secret));
 assert.ok(JSON.stringify(result).includes('REDACTED'));
 const copy=result.reportBytes;copy.fill(0);
 assert.ok(result.reportBytes.toString('utf8').includes(secret));
 assert.equal(result.approvalAuthorized,false);
});

test('third offline Semgrep stage adds blockers without new approval path',()=>{
 const c=call([],[],{
   requireSemgrepCE:true,
   semgrepReportBytes:make([item('d')],'Local Semgrep rule matched')
 });
 assert.equal(c.provisionalState,'FAIL');
 assert.equal(c.blockingFindings,1);
 assert.equal(c.findingCount,1);
 assert.equal(c.semgrepReportIncluded,true);
 assert.equal(c.approvalAuthorized,false);
 assert.equal(c.independentReviewVerified,false);
 assert.ok(JSON.parse(c.reportBytes).summary.includes('Offline Semgrep CE'));
});
test('Semgrep cannot vanish silently or mix a different reviewer run',()=>{
 assert.throws(()=>call([],[],{requireSemgrepCE:true}),
  /COMBINED_SEMGREP_STAGE_UNVERIFIED/);
 assert.throws(()=>call([],[],{semgrepReportBytes:make([])}),
  /COMBINED_SEMGREP_STAGE_UNVERIFIED/);
 assert.throws(()=>call([],[],{requireSemgrepCE:true,
  semgrepReportBytes:make([],'LOCAL SCAN','other-run')}),
  /COMBINED_REVIEW_RUN_MISMATCH/);
});
test('Semgrep duplicate fingerprints must match or be refused',()=>{
 const okay=call([item('a')],[],{requireSemgrepCE:true,
   semgrepReportBytes:make([item('a')])});
 assert.equal(okay.findingCount,1);
 assert.throws(()=>call([item('a')],[],{requireSemgrepCE:true,
   semgrepReportBytes:make([{...item('a'),message:'different'}])}),
  /COMBINED_REVIEW_FINDING_CONFLICT/);
});
