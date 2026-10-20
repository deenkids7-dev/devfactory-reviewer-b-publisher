/**
 * Synthetic and OFFLINE evidence coverage inventory.
 * No authenticated OpenRouter bills, complete key enumeration, secret
 * access, API calls, FX valuation, release of holds, or payment authority.
 * No production module imports this fixture checker.
 */
const MAX_BYTES=65536,MAX_KEYS=20,MAX_ATTEMPTS=200,MAX_STATEMENTS=240;
const ROOT=['schema','scope','watermark','window','keys','attempts','statements'];
const WINDOW=['first_month_utc','last_month_utc'];
const KEY=['key_id','role','valid_from_month_utc','retired_after_month_utc'];
const ATTEMPT=['request_id','key_id','initiated_month_utc','state'];
const STATEMENT=['statement_id','key_id','month_utc','source','digest_sha256','request_ids'];
const ID=/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/;
const MONTH=/^\d{4}-(0[1-9]|1[0-2])$/;
const DIGEST=/^[a-f0-9]{64}$/;
const ROLES=new Set(['development','reviewer_b']);
const STATES=new Set(['pending','ambiguous','settled_fixture']);
const exact=(obj,fields)=>obj!==null&&typeof obj==='object'&&
  !Array.isArray(obj)&&Object.keys(obj).length===fields.length&&
  fields.every(key=>Object.hasOwn(obj,key));
const month=v=>typeof v==='string'&&MONTH.test(v);
const id=v=>typeof v==='string'&&ID.test(v);
const index=v=>Number(v.slice(0,4))*12+Number(v.slice(5,7))-1;
const denied=(reason,summary={})=>Object.freeze({
  status:'BLOCKED',reason,syntheticOnly:true,verified:false,
  maySpend:false,mayReserve:false,mayRetryAmbiguousRequest:false,
  mayReleaseHold:false,providerBillingAuthenticated:false,
  accountCoverageAuthenticated:false,keyInventoryAuthenticated:false,
  statementProvenanceAuthenticated:false,fxAuthenticated:false,
  ...summary,
});

/**
 * Audits only internal consistency of a user-supplied synthetic fixture.
 * Missing keys from the fixture CANNOT be detected. A SHA256-shaped string
 * is NOT a signature, a provenance chain, or an authentic provider receipt.
 */
export function assessSyntheticEvidenceCoverageOffline(json){
  if(process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY!=='1')
    return denied('SHADOW_COVERAGE_SYNTHETIC_SWITCH_REQUIRED');
  if(typeof json!=='string'||Buffer.byteLength(json,'utf8')>MAX_BYTES)
    return denied('SHADOW_COVERAGE_INPUT_UNTRUSTED');
  let s;
  try{s=JSON.parse(json)}catch{
    return denied('SHADOW_COVERAGE_INPUT_UNTRUSTED');
  }
  if(!exact(s,ROOT)||s.schema!=='devfactory.shadow-evidence-coverage.synthetic.v1'||
     s.scope!=='illustrative-only'||s.watermark!=='unverified-fixture'||
     !exact(s.window,WINDOW)||
     !month(s.window.first_month_utc)||!month(s.window.last_month_utc)||
     !Array.isArray(s.keys)||s.keys.length<1||s.keys.length>MAX_KEYS||
     !Array.isArray(s.attempts)||s.attempts.length>MAX_ATTEMPTS||
     !Array.isArray(s.statements)||s.statements.length>MAX_STATEMENTS)
    return denied('SHADOW_COVERAGE_INPUT_UNTRUSTED');
  const begin=index(s.window.first_month_utc),end=index(s.window.last_month_utc);
  if(end<begin||end-begin>=12)
    return denied('SHADOW_COVERAGE_WINDOW_INVALID');

  const keys=new Map(),required=new Set(),observed=new Set(),attempts=new Map();
  for(const k of s.keys){
    if(!exact(k,KEY)||!id(k.key_id)||keys.has(k.key_id)||
       !ROLES.has(k.role)||!month(k.valid_from_month_utc)||
       !(k.retired_after_month_utc===null||month(k.retired_after_month_utc)))
      return denied('SHADOW_COVERAGE_KEY_INVALID_OR_DUPLICATE');
    const first=index(k.valid_from_month_utc);
    const last=k.retired_after_month_utc===null?end:index(k.retired_after_month_utc);
    if(first>end||last<begin||last<first||first>last)
      return denied('SHADOW_COVERAGE_KEY_LIFECYCLE_INVALID');
    keys.set(k.key_id,{first,last});
    for(let m=Math.max(begin,first);m<=Math.min(end,last);m++)
      required.add(k.key_id+'@'+m);
  }
  for(const a of s.attempts){
    if(!exact(a,ATTEMPT)||!id(a.request_id)||attempts.has(a.request_id)||
       !id(a.key_id)||!keys.has(a.key_id)||!month(a.initiated_month_utc)||
       !STATES.has(a.state))
      return denied('SHADOW_COVERAGE_ATTEMPT_INVALID_OR_DUPLICATE');
    const m=index(a.initiated_month_utc);
    const lifecycle=keys.get(a.key_id);
    if(m<begin||m>end||m<lifecycle.first||m>lifecycle.last)
      return denied('SHADOW_COVERAGE_ATTEMPT_OUTSIDE_KEY_LIFECYCLE');
    attempts.set(a.request_id,{key_id:a.key_id,month:m,state:a.state});
  }

  const statementIds=new Set(),digests=new Set(),matched=new Set();
  for(const srow of s.statements){
    if(!exact(srow,STATEMENT)||!id(srow.statement_id)||
       statementIds.has(srow.statement_id)||
       !id(srow.key_id)||!keys.has(srow.key_id)||
       !month(srow.month_utc)||srow.source!=='unverified-fixture'||
       typeof srow.digest_sha256!=='string'||
       !DIGEST.test(srow.digest_sha256)||digests.has(srow.digest_sha256)||
       !Array.isArray(srow.request_ids)||srow.request_ids.length>MAX_ATTEMPTS)
      return denied('SHADOW_COVERAGE_STATEMENT_UNTRUSTED_OR_DUPLICATE');
    const m=index(srow.month_utc),pair=srow.key_id+'@'+m;
    if(!required.has(pair))
      return denied('SHADOW_COVERAGE_STATEMENT_OUTSIDE_KEY_LIFECYCLE');
    if(observed.has(pair))
      return denied('SHADOW_COVERAGE_MULTIPLE_STATEMENTS_SAME_KEY_MONTH');
    observed.add(pair);statementIds.add(srow.statement_id);
    digests.add(srow.digest_sha256);
    const perStatement=new Set();
    for(const requestId of srow.request_ids){
      if(!id(requestId)||perStatement.has(requestId))
        return denied('SHADOW_COVERAGE_STATEMENT_REQUEST_INVALID_OR_DUPLICATE');
      perStatement.add(requestId);
      const a=attempts.get(requestId);
      if(!a)return denied('SHADOW_COVERAGE_ORPHAN_INVOICE_REQUEST');
      if(a.key_id!==srow.key_id||m<a.month)
        return denied('SHADOW_COVERAGE_CROSS_KEY_OR_PREDATED_INVOICE');
      // One request can appear in later months due to late/partial charges;
      // a matching mock line NEVER resolves an ambiguous billable outcome.
      matched.add(requestId);
    }
  }
  const missingPairs=Array.from(required).filter(k=>!observed.has(k));
  const unmatched=Array.from(attempts.keys()).filter(k=>!matched.has(k));
  const unknown=Array.from(attempts.values()).filter(
    a=>a.state==='ambiguous'||a.state==='pending').length;
  return denied(missingPairs.length?
    'SHADOW_COVERAGE_MISSING_KEY_MONTH_FIXTURES':
    unmatched.length?'SHADOW_COVERAGE_UNMATCHED_REQUEST_FIXTURES':
    'SHADOW_COVERAGE_ALL_FIXTURES_STILL_UNVERIFIED',{
    simulatedDeclaredKeyCount:keys.size,
    simulatedRequiredKeyMonthPairs:required.size,
    simulatedObservedKeyMonthPairs:observed.size,
    simulatedMissingKeyMonthPairs:missingPairs.length,
    simulatedUnmatchedRequestCount:unmatched.length,
    simulatedUnknownOutcomeCount:unknown,
    simulatedStatementCount:statementIds.size,
    simulatedAttemptCount:attempts.size,
  });
}
