const BOT_ID=340237276;
const BOT_LOGIN='devfactory-reviewer-b[bot]';
const REPO='deenkids7-dev/deenkids';
const SHA40=/^[0-9a-f]{40}$/;
const NATIVE_MARKER=/^<!-- devfactory-reviewer-b-native:v1:[A-Za-z0-9_-]+ -->\r?\n/;
function deny(code){throw Error(code);}

/**
 * GitHub native reviews are the sole authoritative review-existence record.
 * This function is deliberately more conservative than PR #900's signature
 * validator: ANY review already attributed to the Reviewer B bot on the
 * current HEAD blocks a repeat publication, valid or invalid. Never erase
 * or replace a review automatically in order to get a green result.
 *
 * There is still a race between check and POST! Future privileged publisher
 * MUST use a GitHub workflow concurrency group scoped to exact repo+PR,
 * re-fetch immediately before write, then independently verify the result.
 */
export function assessNativeReviewUniqueness({
  observed,prNumber,currentHeadSha
}={}){
  if(!observed||!Array.isArray(observed.reviews)||
     observed.reviews.length>250||
     !Number.isSafeInteger(prNumber)||prNumber<1||
     typeof currentHeadSha!=='string'||!SHA40.test(currentHeadSha)||
     observed.targetHeadSha!==currentHeadSha)
    deny('REVIEW_UNIQUENESS_CONTEXT_INVALID');
  const matched=[];
  const seen=new Set();
  for(const review of observed.reviews){
    if(!review||!Number.isSafeInteger(review.id)||review.id<=0||
       seen.has(review.id)||!review.user||
       !Number.isSafeInteger(review.user.id)||
       typeof review.user.login!=='string'||
       typeof review.commit_id!=='string'||!SHA40.test(review.commit_id)||
       review.pull_request_url!==
       `https://api.github.com/repos/${REPO}/pulls/${prNumber}`||
       typeof review.body!=='string'){
      deny('REVIEW_UNIQUENESS_DATA_UNTRUSTED');
    }
    seen.add(review.id);
    // A partial match of the canonical bot identity is conflicting evidence,
    // never a justification to publish a second native review.
    if((review.user.id===BOT_ID)!==(review.user.login===BOT_LOGIN)){
      deny('REVIEW_BOT_IDENTITY_CONFLICT');
    }
    if(review.user.id===BOT_ID&&review.user.login===BOT_LOGIN&&
       review.commit_id===currentHeadSha){
      // An incomplete, malformed or unsigned bot review also blocks repeats.
      // This avoids manufacturing new PASS reviews around contradictory proof.
      matched.push(Object.freeze({
        reviewId:review.id,
        state:review.state,
        hasNativeMarker:NATIVE_MARKER.test(review.body)
      }));
    }
  }
  return Object.freeze({
    blocked:matched.length>0,
    reason:matched.length>0?'BOT_ALREADY_REVIEWED_THIS_HEAD':'NO_REVIEW_OBSERVED',
    existing:Object.freeze(matched),
    // Absence of prior review is not an approval to publish.
    independentReviewVerified:false,approvalAuthorized:false
  });
}
