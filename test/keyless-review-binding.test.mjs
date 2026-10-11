import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { prepareKeylessReviewSubject, compareKeylessReviewSubject }
  from '../candidate/keyless-review-binding.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const scoped=()=>({
  target:{
    repository:'deenkids7-dev/deenkids',repository_id:1282086207,
    pr_number:900,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
    diff_sha256:'c'.repeat(64)
  },
  reportSha256:'d'.repeat(64),
  runId:'trusted-run-123',engine:'local-qwen',
  analyzerSha256:'e'.repeat(64),builderSourceSha:'f'.repeat(40)
});
const get=()=>prepareKeylessReviewSubject(scoped());

test('binds exact synthetic private PR metadata, report, runner and code digest',()=>{
  const prepared=get();
  const checked=compareKeylessReviewSubject({
    subjectBytes:prepared.subjectBytes,expected:scoped()
  });
  assert.equal(prepared.subjectSha256,hash(prepared.subjectBytes));
  assert.equal(checked.subjectSha256,prepared.subjectSha256);
  assert.equal(checked.boundToExpectedScope,true);
  assert.equal(checked.hasVerifiedGitHubAttestation,false);
  assert.equal(checked.executionOriginVerified,false);
  assert.equal(checked.reviewIndependenceVerified,false);
  assert.equal(checked.approvalAuthorized,false);
  assert.equal(checked.publishEvent,null);
});
test('bound subject carries only digests and scoped identifiers, no code',()=>{
  const candidate=JSON.parse(get().subjectBytes.toString('utf8'));
  assert.equal(candidate.schema,'devfactory.reviewer-b.keyless-subject.v1');
  assert.equal(candidate.builder_repository,
    'devfactory-reviewer-trust/devfactory-reviewer-b-publisher');
  assert.equal(candidate.builder_workflow,
    '.github/workflows/reviewer-b-live-review.yml');
  assert.equal(candidate.report_sha256,scoped().reportSha256);
  assert.equal(candidate.target.pr_number,900);
  assert.ok(!JSON.stringify(candidate).includes('privateDiff'));
});
test('rejects foreign repository, unknown PR or changed metadata types',()=>{
  const orig=scoped();
  for(const patch of [
    {repository:'other/deenkids'}, {repository_id:123}, {pr_number:'900'},
    {pr_number:[]}, {head_sha:['a'.repeat(40)]},
    {base_sha:'bad'}, {diff_sha256:[]}, {diff_sha256:'g'.repeat(64)}
  ]){
    assert.throws(()=>prepareKeylessReviewSubject({
      ...orig,target:{...orig.target,...patch}
    }),/KEYLESS_TARGET_INVALID/);
  }
});
test('rejects coerced run, engine, code hashes and workflow commit',()=>{
  for(const patch of [
    {reportSha256:['d'.repeat(64)]}, {runId:[]},{runId:'other run'},
    {engine:'self-approved'},{engine:['local-qwen']},
    {analyzerSha256:null},{analyzerSha256:[]},
    {builderSourceSha:['f'.repeat(40)]},{builderSourceSha:'bad'}
  ]) assert.throws(()=>prepareKeylessReviewSubject({...scoped(),...patch}),
    /KEYLESS_REVIEW_SCOPE_INVALID/);
});
test('rechecks the trusted HEAD, BASE, diff, report, runner, engine and builder',()=>{
  const p=get();
  const o=scoped();
  for(const changed of [
    {...o,target:{...o.target,head_sha:'1'.repeat(40)}},
    {...o,target:{...o.target,base_sha:'2'.repeat(40)}},
    {...o,target:{...o.target,diff_sha256:'3'.repeat(64)}},
    {...o,reportSha256:'4'.repeat(64)},
    {...o,runId:'other-run-123'},
    {...o,engine:'gemini-code-assist'},
    {...o,analyzerSha256:'5'.repeat(64)},
    {...o,builderSourceSha:'6'.repeat(40)}
  ]) assert.throws(()=>compareKeylessReviewSubject({
    subjectBytes:p.subjectBytes,expected:changed
  }),/KEYLESS_SUBJECT_SCOPE_MISMATCH/);
});
test('untrusted subject extra fields, noncanonical bytes and malformed content denied',()=>{
  const p=get(),orig=JSON.parse(p.subjectBytes.toString());
  const variants=[
    Buffer.from(JSON.stringify({...orig,approvalAuthorized:true})),
    Buffer.from(JSON.stringify(orig)+'\n'),
    Buffer.from(JSON.stringify({...orig,target:{...orig.target,extra:true}})),
    Buffer.from('not-json'),
    Buffer.from([0xC0,0x80]),
    Buffer.concat([p.subjectBytes,Buffer.from('\u0000')])
  ];
  for(const value of variants)assert.throws(()=>compareKeylessReviewSubject({
    subjectBytes:value,expected:scoped()
  }),/KEYLESS_SUBJECT_/);
});
test('public JSON and inspection cannot accidentally expose subject details',()=>{
  const p=get();
  assert.equal(Object.isFrozen(p),true);
  assert.ok(!Object.keys(p).includes('subjectBytes'));
  assert.ok(!JSON.stringify(p).includes('deenkids'));
  assert.ok(!inspect(p).includes('deenkids'));
  assert.ok(JSON.stringify(p).includes('UNVERIFIED_ATTESTATION_SUBJECT'));
  const raw=p.subjectBytes;raw.fill(0);
  assert.equal(compareKeylessReviewSubject({
    subjectBytes:p.subjectBytes,expected:scoped()
  }).boundToExpectedScope,true);
});
test('random forgery never upgrades to native approval',()=>{
  const p=get();
  for(let i=0;i<12;i++){
    const bytes=p.subjectBytes;
    bytes[bytes.length-20]^=1;
    assert.throws(()=>compareKeylessReviewSubject({
      subjectBytes:bytes,expected:scoped()
    }));
  }
  assert.equal(p.approvalAuthorized,false);
  assert.equal(p.reviewIndependenceVerified,false);
});
