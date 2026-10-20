/**
 * SYNTHETIC ONLY: verify an untrusted mock audit SHA-256 hash chain.
 * A self-anchored chain can be completely forged and rehashed:
 * consistency is NOT authenticity, external witnessing, or authorization.
 *
 * No sockets, credentials, invoice verification, durable journal or keys.
 */
import {createHash} from 'node:crypto';
import {assessSyntheticIncidentAuditOffline as assessAudit}
  from './openrouter-shadow-readonly-acquisition-plan-offline.mjs';

const ROOT=['schema','scope','transport','incident','entries','checkpoint'];
const INCIDENT=['incident_id','head_sha','request_digest_sha256','key_role'];
const ENTRY=['sequence','event_id','type','occurred_utc',
  'evidence_digest_sha256','previous_hash','entry_hash'];
const CHECKPOINT=['kind','root_hash','witness','externalProofAuthenticated',
  'durableStoreVerified'];
const ID=/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$/;
const HEX40=/^[a-f0-9]{40}$/;
const HEX64=/^[a-f0-9]{64}$/;
const GENESIS='0'.repeat(64),MAX_BYTES=16384,MAX_EVENTS=24;
const exact=(v,keys)=>v!==null&&typeof v==='object'&&
  !Array.isArray(v)&&Object.keys(v).length===keys.length&&
  keys.every(k=>Object.hasOwn(v,k));
const blocked=(reason,summary={})=>Object.freeze({
  status:'BLOCKED',reason,syntheticOnly:true,verified:false,
  providerEvidenceAuthenticated:false,externalWitnessAuthenticated:false,
  durableJournalVerified:false,independentReviewerApproved:false,
  actualHumanGo:false,actualMergeGo:false,maySpend:false,
  mayReserve:false,mayRetryAmbiguousRequest:false,mayReleaseHold:false,
  mayDeploy:false,mayStartRunner:false,mayCloseIncident:false,
  ...summary,
});
const payload=(incident,entry)=>JSON.stringify([
  'devfactory.shadow-audit-link.synthetic.v1',
  incident.incident_id,incident.head_sha,
  incident.request_digest_sha256,incident.key_role,
  entry.sequence,entry.event_id,entry.type,entry.occurred_utc,
  entry.evidence_digest_sha256,entry.previous_hash,
]);
const digest=(string)=>createHash('sha256').update(string,'utf8').digest('hex');

/**
 * This intentionally exports no signing, approval, spend or persistence.
 * Recomputing all hashes after tampering will pass structural validation,
 * which is exactly why a future independent external checkpoint is needed.
 */
export function assessSyntheticAuditAnchorOffline(json){
  if(process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY!=='1')
    return blocked('SHADOW_ANCHOR_SYNTHETIC_SWITCH_REQUIRED');
  if(typeof json!=='string'||Buffer.byteLength(json,'utf8')>MAX_BYTES)
    return blocked('SHADOW_ANCHOR_FIXTURE_UNTRUSTED');
  let s;
  try{s=JSON.parse(json)}catch{
    return blocked('SHADOW_ANCHOR_FIXTURE_UNTRUSTED');
  }
  if(!exact(s,ROOT)||
     s.schema!=='devfactory.shadow-audit-anchor.synthetic.v1'||
     s.scope!=='illustrative-only'||s.transport!=='no-network'||
     !exact(s.incident,INCIDENT)||
     typeof s.incident.incident_id!=='string'||
     !ID.test(s.incident.incident_id)||
     typeof s.incident.head_sha!=='string'||
     !HEX40.test(s.incident.head_sha)||
     typeof s.incident.request_digest_sha256!=='string'||
     !HEX64.test(s.incident.request_digest_sha256)||
     !['development','reviewer_b'].includes(s.incident.key_role)||
     !Array.isArray(s.entries)||s.entries.length<2||
     s.entries.length>MAX_EVENTS||
     !exact(s.checkpoint,CHECKPOINT))
    return blocked('SHADOW_ANCHOR_FIXTURE_UNTRUSTED');

  if(s.checkpoint.kind!=='self-declared-fixture'||
     s.checkpoint.witness!=='unverified-fixture'||
     s.checkpoint.externalProofAuthenticated!==false||
     s.checkpoint.durableStoreVerified!==false||
     typeof s.checkpoint.root_hash!=='string'||
     !HEX64.test(s.checkpoint.root_hash))
    return blocked('SHADOW_ANCHOR_EXTERNAL_AUTHORITY_FORGED');

  const simplified=[];
  for(const entry of s.entries){
    if(!exact(entry,ENTRY)||
       typeof entry.previous_hash!=='string'||
       !HEX64.test(entry.previous_hash)||
       typeof entry.entry_hash!=='string'||
       !HEX64.test(entry.entry_hash))
      return blocked('SHADOW_ANCHOR_ENTRY_UNTRUSTED');
    simplified.push({
      sequence:entry.sequence,event_id:entry.event_id,
      type:entry.type,occurred_utc:entry.occurred_utc,
      evidence_digest_sha256:entry.evidence_digest_sha256,
    });
  }

  // Reuse the pre-existing strict redacted incident/event validator.
  const audit={
    schema:'devfactory.shadow-incident-audit.synthetic.v1',
    scope:'illustrative-only',transport:'no-network',
    ...s.incident,events:simplified,
    review:{status:'pending',providerEvidenceAuthenticated:false,
      independentReviewerApproved:false,humanGoGranted:false,
      holdReleaseApproved:false},
  };
  const prior=assessAudit(JSON.stringify(audit));
  if(prior.reason!=='SHADOW_AUDIT_PENDING_HUMAN_REVIEW_NO_AUTHORITY')
    return blocked('SHADOW_ANCHOR_EVENT_HISTORY_UNTRUSTED');

  let last=GENESIS;
  for(const e of s.entries){
    if(e.previous_hash!==last)
      return blocked('SHADOW_ANCHOR_PREVIOUS_LINK_MISMATCH');
    const computed=digest(payload(s.incident,e));
    if(e.entry_hash!==computed)
      return blocked('SHADOW_ANCHOR_ENTRY_DIGEST_MISMATCH');
    last=e.entry_hash;
  }
  if(last!==s.checkpoint.root_hash)
    return blocked('SHADOW_ANCHOR_SELF_DECLARED_CHECKPOINT_MISMATCH');

  return blocked('SHADOW_ANCHOR_INTERNALLY_CONSISTENT_UNWITNESSED',{
    simulatedEntryCount:s.entries.length,
    simulatedChainInternallyConsistent:true,
    simulatedRootMatchesSelfDeclaredCheckpoint:true,
    simulatedIndependentExternalCheckpointFound:false,
    simulatedNativeReviewerApprovalFound:false,
  });
}
