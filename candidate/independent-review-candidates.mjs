// Deterministic, NO-NETWORK filter for GitHub review CANDIDATES.
// A GitHub account different from the developer does not by itself prove
// reviewer independence or provide an independent security certification.
const SHA=/^[0-9a-f]{40}$/;
const LOGIN=/^[A-Za-z0-9-]{1,39}$/;
const OWNED=new Set(['devfactory-reviewer-service','deenkids7-dev']);
const REPO='devfactory-reviewer-trust/devfactory-reviewer-b-publisher';
function deny(code){throw Error(code);}
function validReview(r){
  return r&&typeof r==='object'&&!Array.isArray(r)&&
    Number.isSafeInteger(r.id)&&r.id>0&&
    typeof r.state==='string'&&typeof r.commit_id==='string'&&
    typeof r.user?.login==='string'&&LOGIN.test(r.user.login)&&
    r.user?.type==='User'&&Number.isSafeInteger(r.user.id)&&r.user.id>0;
}
/**
 * Input MUST come from independently authenticated GitHub REST, never from
 * a PR body, model text, private issue, or generated witness.
 * Even matching real API reviews are only account-level CANDIDATES.
 *
 * No positive securityReviewVerified or approvalAuthorized path exists.
 */
export function assessIndependentReviewCandidates({
  repository,prNumber,expectedHeadSha,reviews,eligibleReviewerLogins
}={}){
  if(repository!==REPO||!Number.isSafeInteger(prNumber)||prNumber<1||
    !SHA.test(expectedHeadSha)||!Array.isArray(reviews)||reviews.length>500||
    !Array.isArray(eligibleReviewerLogins)||eligibleReviewerLogins.length>20||
    eligibleReviewerLogins.some(x=>!LOGIN.test(x)||OWNED.has(x))||
    new Set(eligibleReviewerLogins).size!==eligibleReviewerLogins.length)
    deny('REVIEW_CANDIDATES_SCOPE_INVALID');
  const eligible=new Set(eligibleReviewerLogins);
  const last=new Map();
  for(const r of reviews){
    if(!validReview(r))deny('REVIEW_CANDIDATES_GITHUB_FORMAT_INVALID');
    const login=r.user.login;
    if(OWNED.has(login)||login.endsWith('[bot]')||!eligible.has(login))continue;
    if(!SHA.test(r.commit_id))deny('REVIEW_CANDIDATES_SHA_INVALID');
    if(!Number.isFinite(Date.parse(r.submitted_at||'')))
      deny('REVIEW_CANDIDATES_TIMESTAMP_INVALID');
    const prev=last.get(login);
    const time=Date.parse(r.submitted_at);
    if(!prev||time>prev.time||(time===prev.time&&r.id>prev.id))
      last.set(login,{id:r.id,time,state:r.state,head:r.commit_id});
  }
  const candidates=[...last.entries()].filter(([_,x])=>
    x.state==='APPROVED'&&x.head===expectedHeadSha)
    .map(([login,x])=>Object.freeze({login,reviewId:x.id,headSha:x.head}))
    .sort((a,b)=>a.login<b.login?-1:a.login>b.login?1:0);
  return Object.freeze({
    repository:REPO,prNumber,headSha:expectedHeadSha,
    externalAccountApprovalCandidates:Object.freeze(candidates),
    freshExternalAccountApprovalPresent:candidates.length>0,
    githubOriginAuthenticated:false,
    actualHumanIndependenceVerified:false,
    securityReviewVerified:false,
    approvalAuthorized:false,
    publishEvent:null
  });
}
