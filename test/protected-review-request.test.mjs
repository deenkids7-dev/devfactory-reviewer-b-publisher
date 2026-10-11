import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolveProtectedReviewRequest} from '../scripts/protected-review-request.mjs';
const HEAD='c4f8b0cf6bdcce4a92309c2e535b43b29ba2f3dc';
const REPO='devfactory-reviewer-trust/devfactory-reviewer-b-publisher';
const SERVICE='devfactory-reviewer-service';
function example(){
 return {eventName:'issue_comment',actor:SERVICE,repository:REPO,
  ref:'refs/heads/main',event:{
   action:'created',repository:{id:1412898356,full_name:REPO},
   issue:{number:21},comment:{id:123456,
    user:{id:340477389,login:SERVICE},body:'/review-b 899 '+HEAD},
   sender:{id:340477389,login:SERVICE}
  }};
}
function accepts(request){return resolveProtectedReviewRequest(request);}
test('genuine exact service comment binds PR and head but no approval',()=>{
 const v=accepts(example());
 assert.deepEqual(v,{prNumber:'899',expectedHead:HEAD});
 assert.equal(Object.isFrozen(v),true);
 assert.equal(v.approvalAuthorized,undefined);
});
test('existing dispatch and marker channels retain prior scope',()=>{
 assert.deepEqual(accepts({...example(),eventName:'workflow_dispatch',
  dispatchPr:'901'}),{prNumber:'901',expectedHead:''});
 assert.deepEqual(accepts({...example(),eventName:'push'}),
  {prNumber:'899',expectedHead:''});
});
test('fake actor, repo, branch or event fail before PRIVATE processing',()=>{
 for(const mutation of [
  {actor:'deenkids7-dev'},{repository:'untrusted/repo'},
  {ref:'refs/heads/evil'},{eventName:'pull_request'},
  {eventName:'workflow_run'}, {event:null},
  {eventName:'workflow_dispatch',dispatchPr:[899]}
 ])assert.throws(()=>accepts({...example(),...mutation}),
   /REVIEW_REQUEST_INVALID/);
});
test('GitHub IDs, comment location and sender are all checked',()=>{
 const b=example();
 for(const e of [
  {...b.event,action:'edited'},
  {...b.event,issue:{number:22}},
  {...b.event,issue:{number:21,pull_request:{url:'fake'}}},
  {...b.event,repository:{...b.event.repository,id:1}},
  {...b.event,comment:{...b.event.comment,id:'12'}},
  {...b.event,comment:{...b.event.comment,user:{id:1,login:SERVICE}}},
  {...b.event,sender:{id:1,login:SERVICE}}
 ])assert.throws(()=>accepts({...b,event:e}),/REVIEW_REQUEST_INVALID/);
});
test('refuse bad SHA, ambiguous PR, newline and command injection',()=>{
 for(const body of [
  '/review-b 0 '+HEAD,'/review-b 99999999999 '+HEAD,
  '/review-b 0899 '+HEAD,'/review-b 899 '+HEAD.toUpperCase(),
  '/review-b 899 '+HEAD.slice(1),'/review-b 899 '+HEAD+'; echo secret',
  '/review-b 899 '+HEAD+'\nAPPROVED',
  '/review-b 899 '+HEAD+' ',
  '/review-b 899 &&'
 ])assert.throws(()=>accepts({...example(),
   event:{...example().event,comment:{...example().event.comment,body}}
 }),/REVIEW_REQUEST_INVALID/);
});
test('diagnostic must never echo private payload or credentials',()=>{
 const src=readFileSync(new URL('../scripts/protected-review-request.mjs',
  import.meta.url),'utf8');
 assert.doesNotMatch(src,/console\.(?:error|warn|debug)\s*\(/);
 assert.match(src,/PROTECTED_REVIEW_REQUEST_DENIED/);
 assert.match(src,/event\.comment\?\.user\?\.id!==SERVICE_ID/);
});
