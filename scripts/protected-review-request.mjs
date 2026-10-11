/**
 * One protected Publisher workflow, no new scheduler:
 * authenticate one service-owned issue comment before loading PRIVATE keys.
 * PR body/source and model output can never set workflow event authority.
 */
import {readFileSync,statSync,appendFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
const REPO='devfactory-reviewer-trust/devfactory-reviewer-b-publisher';
const REPO_ID=1412898356;
const SERVICE='devfactory-reviewer-service',SERVICE_ID=340477389;
const ISSUE=21;
const SHA40=/^[a-f0-9]{40}$/,PR=/^[1-9][0-9]{0,9}$/;
const MAX_PR=2147483647;
const CMD=/^\/review-b ([1-9][0-9]{0,9}) ([a-f0-9]{40})$/;
function deny(){throw Error('REVIEW_REQUEST_INVALID');}
function validPr(value){
  return typeof value==='string'&&PR.test(value)&&
    Number(value)<=MAX_PR;
}
function verifiedTarget(target){
  if(!validPr(target.prNumber)||(
    target.expectedHead!==''&&
    (typeof target.expectedHead!=='string'||!SHA40.test(target.expectedHead))
  ))deny();
  return Object.freeze({prNumber:target.prNumber,
    expectedHead:target.expectedHead});
}
/** The caller passes GitHub-generated event identity, NOT PR content. */
export function resolveProtectedReviewRequest({
  eventName,actor,repository,ref,event,dispatchPr
}={}){
  if(repository!==REPO||ref!=='refs/heads/main'||actor!==SERVICE)
    deny();
  if(eventName==='workflow_dispatch'){
    return verifiedTarget({prNumber:dispatchPr,expectedHead:''});
  }
  if(eventName==='push'){
    // Historical R56–R59 one-shot marker; never change its fixed scope.
    return verifiedTarget({prNumber:'899',expectedHead:''});
  }
  if(eventName!=='issue_comment'||!event||
     typeof event!=='object'||Array.isArray(event)||
     event.action!=='created'||event.repository?.full_name!==REPO||
     event.repository?.id!==REPO_ID||
     event.issue?.number!==ISSUE||
     Object.hasOwn(event.issue||{},'pull_request')||
     event.comment?.user?.login!==SERVICE||
     event.comment?.user?.id!==SERVICE_ID||
     event.sender?.login!==SERVICE||
     event.sender?.id!==SERVICE_ID||
     !Number.isSafeInteger(event.comment.id)||event.comment.id<1||
     typeof event.comment.body!=='string'||event.comment.body.length>150)
     deny();
  const match=event.comment.body.match(CMD);
  if(!match)deny();
  return verifiedTarget({prNumber:match[1],expectedHead:match[2]});
}
function main(){
  try{
    const e=process.env;
    const eventName=e.GITHUB_EVENT_NAME;
    let event=null;
    if(eventName==='issue_comment'){
      if(typeof e.GITHUB_EVENT_PATH!=='string'||
         !e.GITHUB_EVENT_PATH.startsWith('/home/runner/work/_temp/'))
        deny();
      const stat=statSync(e.GITHUB_EVENT_PATH);
      if(!stat.isFile()||stat.size<50||stat.size>128*1024)deny();
      event=JSON.parse(readFileSync(e.GITHUB_EVENT_PATH,'utf8'));
    }
    const request=resolveProtectedReviewRequest({
      eventName,actor:e.GITHUB_ACTOR,repository:e.GITHUB_REPOSITORY,
      ref:e.GITHUB_REF,event,dispatchPr:e.REVIEWER_B_DISPATCH_PR
    });
    if(typeof e.GITHUB_OUTPUT!=='string'||!e.GITHUB_OUTPUT||
       !e.GITHUB_OUTPUT.startsWith('/home/runner/work/_temp/'))
      deny();
    appendFileSync(e.GITHUB_OUTPUT,
      'pr_number='+request.prNumber+'\n'+
      'expected_head='+request.expectedHead+'\n',
      {encoding:'utf8'});
    console.log('PROTECTED_REVIEW_REQUEST_ACCEPTED');
  }catch{
    // PUBLIC logs never show event JSON, private SHA, path or untrusted text.
    console.log('PROTECTED_REVIEW_REQUEST_DENIED');
    process.exitCode=1;
  }
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1]))
  main();
