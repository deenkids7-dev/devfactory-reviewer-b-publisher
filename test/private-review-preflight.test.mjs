import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { runReadOnlyReviewPreflight }
  from '../candidate/private-review-preflight.mjs';

const TOKEN='ghs_SYNTHETIC_ONLY_NOT_A_REAL_SECRET_123';
const RUN='synthetic-readonly-898';
const PATH='https://api.github.com/repos/deenkids7-dev/deenkids/pulls/898';
const COMPARE='https://api.github.com/repos/deenkids7-dev/deenkids/compare/'+'b'.repeat(40)+'...'+'a'.repeat(40);
const PRIVATE='SYNTHETIC_PRIVATE_CODE_LITERAL_NEVER_LOG_ME';
const DIFF=Buffer.from(
  'diff --git a/.github/workflows/check.yml b/.github/workflows/check.yml\n'+
  'index aaaa..bbbb 100644\n'+
  '--- a/.github/workflows/check.yml\n'+
  '+++ b/.github/workflows/check.yml\n'+
  '@@ -1 +1 @@\n-old\n'+
  '+permissions: write-all  # '+PRIVATE+'\n'
);
const meta=()=>({
  number:898,state:'open',merged_at:null,draft:false,changed_files:1,
  head:{sha:'a'.repeat(40),repo:{full_name:'deenkids7-dev/deenkids',id:1282086207}},base:{sha:'b'.repeat(40),ref:'master',
    repo:{full_name:'deenkids7-dev/deenkids',id:1282086207}}
});
function streamResponse(url,bytes,type){
  return {
    url,status:200,redirected:false,
    headers:new Headers({'content-type':type,'content-length':String(bytes.length)}),
    body:new ReadableStream({start(c){c.enqueue(new Uint8Array(bytes));c.close();}})
  };
}
function service(options={}){
  const calls=[];
  const fetchImpl=async(url,opts)=>{
    calls.push({url,method:opts.method,accept:opts.headers.Accept});
    if(options.error)throw new Error('secret='+TOKEN);
    const isDiff=opts.headers.Accept==='application/vnd.github.diff';
    const isAfter=calls.length===3;
    const bytes=isDiff?(options.diff||DIFF):
      Buffer.from(JSON.stringify(isAfter?(options.after||meta()):(options.before||meta())));
    return streamResponse(url,bytes,isDiff?'text/plain; charset=utf-8':'application/json');
  };
  return {calls,fetchImpl};
}
test('authenticated-style read gives only target metadata and redacted fail-only report',async()=>{
  const fake=service();
  const result=await runReadOnlyReviewPreflight({
    prNumber:898,runId:RUN,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  });
  assert.equal(fake.calls.length,3);
  assert.deepEqual(fake.calls.map(c=>c.accept),[
    'application/vnd.github+json','application/vnd.github.diff',
    'application/vnd.github+json'
  ]);
  assert.deepEqual(fake.calls.map(c=>c.url),[PATH,COMPARE,PATH]);
  assert.ok(fake.calls.every(c=>c.method==='GET'));
  assert.equal(fake.calls[1].accept,'application/vnd.github.diff');
  assert.equal(result.target.repository,'deenkids7-dev/deenkids');
  assert.equal(result.target.diffSha256,
    createHash('sha256').update(DIFF).digest('hex'));
  assert.equal(result.blockingFindings,1);
  assert.equal(result.staticDisposition,'FAIL');
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.independentReviewVerified,false);
  assert.equal(result.semanticAnalysisCompleted,false);
  assert.equal(result.publishEvent,null);
  const serialized=JSON.stringify(result);
  assert.ok(!serialized.includes(PRIVATE),'Private code leaked into output');
  assert.ok(!serialized.includes(TOKEN),'Installation token leaked into output');
  assert.equal(Object.isFrozen(result),true);
});
test('no static matches yields INCONCLUSIVE not PASS',async()=>{
  const safe=Buffer.from(
    'diff --git a/src/demo.mjs b/src/demo.mjs\n'+
    'index aa..bb 100644\n--- a/src/demo.mjs\n+++ b/src/demo.mjs\n'+
    '@@ -1 +1 @@\n-before\n+after\n'
  );
  const fake=service({diff:safe});
  const result=await runReadOnlyReviewPreflight({
    prNumber:898,runId:RUN,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  });
  assert.equal(result.staticDisposition,'INCONCLUSIVE');
  assert.equal(result.approvalAuthorized,false);
});
test('a changed HEAD between metadata reads prevents findings emission',async()=>{
  const fake=service({after:{...meta(),head:{...meta().head,sha:'c'.repeat(40)}}});
  await assert.rejects(()=>runReadOnlyReviewPreflight({
    prNumber:898,runId:RUN,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  }),/GITHUB_PR_CHANGED_DURING_READ/);
});
test('a network error never exposes an installation token',async()=>{
  const fake=service({error:true});
  await assert.rejects(()=>runReadOnlyReviewPreflight({
    prNumber:898,runId:RUN,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  }),e=>!e.message.includes(TOKEN));
});
