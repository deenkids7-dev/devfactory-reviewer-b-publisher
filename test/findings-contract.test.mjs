import test from 'node:test';
import assert from 'node:assert/strict';
import { validateReviewerFindings } from '../src/findings-contract.mjs';

const changedPaths=['src/compute.mjs','test/compute.test.mjs'];
const finding=()=>({
  fingerprint:'a'.repeat(64),
  severity:'high',
  path:'src/compute.mjs',
  line:42,
  message:'Synthetic finding; no private code',
  evidence:'Synthetic fixture only'
});
const payload=()=>({
  schema:'devfactory.reviewer-b.findings.v1',
  run_id:'synthetic-run-001',
  summary:'This is only a fixture, not an independent reviewer.',
  findings:[finding()]
});
const report = overrides => Buffer.from(JSON.stringify({...payload(),...overrides}),'utf8');
function evaluate(bytes,other={}) {
  return validateReviewerFindings({reportBytes:bytes,changedPaths,...other});
}
function denies(name,bytes,reason,other={}){
  test(name,()=>assert.throws(()=>evaluate(bytes,other),e=>e.message===reason));
}
test('high severity finding is a provisional FAIL, not approval',()=>{
  const r=evaluate(report());
  assert.equal(r.provisionalState,'FAIL');
  assert.equal(r.blockingFindingCount,1);
  assert.equal(r.approvalAuthorized,false);
  assert.equal(r.independenceVerified,false);
});
test('empty findings cannot produce independent PASS',()=>{
  const r=evaluate(report({findings:[]}));
  assert.equal(r.provisionalState,'INCONCLUSIVE');
  assert.equal(r.approvalAuthorized,false);
});
test('low severity finding is INCONCLUSIVE, not PASS',()=>{
  const r=evaluate(report({findings:[{...finding(),severity:'low'}]}));
  assert.equal(r.provisionalState,'INCONCLUSIVE');
  assert.equal(r.approvalAuthorized,false);
});
denies('rejects reviewer-supplied PASS',report({claimedVerdict:'PASS'}),
  'REVIEW_INVALID_FIELDS');
denies('rejects changed path not in trusted GitHub changed-files set',
  report({findings:[{...finding(),path:'src/unseen.mjs'}]}),'REVIEW_FINDING_INVALID');
denies('rejects path traversal',report({findings:[{...finding(),path:'../private.txt'}]}),
  'REVIEW_FINDING_INVALID');
denies('rejects absolute path',report({findings:[{...finding(),path:'/etc/passwd'}]}),
  'REVIEW_FINDING_INVALID');
denies('rejects duplicate fingerprint',report({findings:[finding(),finding()]}),
  'REVIEW_FINDING_INVALID');
denies('rejects unknown severity',report({findings:[{...finding(),severity:'GOOD'}]}),
  'REVIEW_FINDING_INVALID');
denies('rejects invalid source line',report({findings:[{...finding(),line:-1}]}),
  'REVIEW_FINDING_INVALID');
denies('rejects unproven report signer field',report({signerApproved:true}),
  'REVIEW_INVALID_FIELDS');
denies('rejects forged trusted paths',report(), 'REVIEW_INPUT_UNTRUSTED',
  {changedPaths:['../secrets.env']});
denies('rejects missing trusted path scope',report(), 'REVIEW_INPUT_UNTRUSTED',
  {changedPaths:[]});
denies('rejects invalid JSON',Buffer.from('{'), 'REVIEW_INVALID_JSON');
denies('rejects invalid UTF8',Buffer.from([0xff,0xff,0xff]),'REVIEW_INVALID_UTF8');
denies('rejects oversized report',Buffer.alloc(64*1024+1,0x20),'REVIEW_INPUT_UNTRUSTED');
denies('rejects empty summary',report({summary:''}),'REVIEW_INVALID_FIELDS');
denies('rejects duplicate report fields with unapproved key',
  Buffer.from(JSON.stringify({...payload(),auth:'verified'})),
  'REVIEW_INVALID_FIELDS');
