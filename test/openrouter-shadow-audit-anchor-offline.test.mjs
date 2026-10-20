import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessSyntheticAuditAnchorOffline as assess}
  from '../scripts/openrouter-shadow-audit-anchor-offline.mjs';

const sha=s=>createHash('sha256').update(s,'utf8').digest('hex');
const entry=(sequence,event_id,type,occurred_utc,evidence_digest_sha256=null)=>({
  sequence,event_id,type,occurred_utc,evidence_digest_sha256,
  previous_hash:'0'.repeat(64),entry_hash:'0'.repeat(64),
});
const mock=()=>({
  schema:'devfactory.shadow-audit-anchor.synthetic.v1',
  scope:'illustrative-only',transport:'no-network',
  incident:{incident_id:'incident:fixture-1',
    head_sha:'a'.repeat(40),request_digest_sha256:'b'.repeat(64),
    key_role:'reviewer_b'},
  entries:[
    entry(1,'event:detected','detected','2026-10-20T15:00:00Z'),
    entry(2,'event:triaged','triaged','2026-10-20T15:01:00Z'),
    entry(3,'event:evidence','evidence_noted','2026-10-20T15:02:00Z',
      'c'.repeat(64)),
    entry(4,'event:manual-review','manual_review_requested',
      '2026-10-20T15:03:00Z'),
  ],
  checkpoint:{kind:'self-declared-fixture',
    root_hash:'0'.repeat(64),witness:'unverified-fixture',
    externalProofAuthenticated:false,durableStoreVerified:false},
});
const rehash=s=>{
  let prior='0'.repeat(64);
  for(const e of s.entries){
    e.previous_hash=prior;
    e.entry_hash=sha(JSON.stringify([
      'devfactory.shadow-audit-link.synthetic.v1',
      s.incident.incident_id,s.incident.head_sha,
      s.incident.request_digest_sha256,s.incident.key_role,
      e.sequence,e.event_id,e.type,e.occurred_utc,
      e.evidence_digest_sha256,e.previous_hash,
    ]));
    prior=e.entry_hash;
  }
  s.checkpoint.root_hash=prior;
  return s;
};
const encode=s=>JSON.stringify(s);
const fixture=()=>rehash(mock());
const withSwitch=fn=>{
  const prior=process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY='1';
  try{return fn()}finally{
    if(prior===undefined)delete process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
    else process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY=prior;
  }
};
const blocked=(result,reason)=>{
  assert.equal(result.status,'BLOCKED');
  assert.equal(result.syntheticOnly,true);
  for(const k of ['verified','providerEvidenceAuthenticated',
    'externalWitnessAuthenticated','durableJournalVerified',
    'independentReviewerApproved','actualHumanGo','actualMergeGo',
    'maySpend','mayReserve','mayRetryAmbiguousRequest','mayReleaseHold',
    'mayDeploy','mayStartRunner','mayCloseIncident'])
    assert.equal(result[k],false,k);
  assert.ok(Object.isFrozen(result));
  if(reason)assert.equal(result.reason,reason);
};
test('offline switch mandatory before even self-declared checking',()=>{
  const saved=process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  delete process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  try{blocked(assess(encode(fixture())),
    'SHADOW_ANCHOR_SYNTHETIC_SWITCH_REQUIRED');}
  finally{if(saved!==undefined)
    process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY=saved;}
});
test('self-matching SHA chain is never authenticated external proof',()=>withSwitch(()=>{
  const r=assess(encode(fixture()));
  blocked(r,'SHADOW_ANCHOR_INTERNALLY_CONSISTENT_UNWITNESSED');
  assert.equal(r.simulatedEntryCount,4);
  assert.equal(r.simulatedChainInternallyConsistent,true);
  assert.equal(r.simulatedRootMatchesSelfDeclaredCheckpoint,true);
  assert.equal(r.simulatedIndependentExternalCheckpointFound,false);
  assert.equal(r.simulatedNativeReviewerApprovalFound,false);
}));
test('editing an event without rebuilding hashes is detected',()=>withSwitch(()=>{
  const s=fixture();s.entries[2].occurred_utc='2026-10-20T15:02:01Z';
  blocked(assess(encode(s)),'SHADOW_ANCHOR_ENTRY_DIGEST_MISMATCH');
}));
test('missing or swapped previous hash is detected',()=>withSwitch(()=>{
  const s=fixture();s.entries[1].previous_hash='f'.repeat(64);
  blocked(assess(encode(s)),'SHADOW_ANCHOR_PREVIOUS_LINK_MISMATCH');
}));
test('tampered final self-checkpoint root is detected',()=>withSwitch(()=>{
  const s=fixture();s.checkpoint.root_hash='f'.repeat(64);
  blocked(assess(encode(s)),
    'SHADOW_ANCHOR_SELF_DECLARED_CHECKPOINT_MISMATCH');
}));
test('fully forged/rehashed chain still appears internally consistent only',()=>withSwitch(()=>{
  const s=fixture();s.entries[2].evidence_digest_sha256='d'.repeat(64);
  rehash(s);
  const r=assess(encode(s));
  blocked(r,'SHADOW_ANCHOR_INTERNALLY_CONSISTENT_UNWITNESSED');
  assert.equal(r.externalWitnessAuthenticated,false);
}));
test('dropped final event with entirely new root cannot be authenticated',()=>withSwitch(()=>{
  const s=fixture();s.entries.pop();rehash(s);
  const r=assess(encode(s));
  blocked(r,'SHADOW_ANCHOR_INTERNALLY_CONSISTENT_UNWITNESSED');
  assert.equal(r.simulatedEntryCount,3);
}));
test('claimed provider-signed witness or durable storage proof is rejected',()=>withSwitch(()=>{
  const edits=[
    s=>{s.checkpoint.witness='signed-by-provider';},
    s=>{s.checkpoint.kind='production';},
    s=>{s.checkpoint.externalProofAuthenticated=true;},
    s=>{s.checkpoint.durableStoreVerified=true;},
    s=>{s.checkpoint.signature='untrusted';},
    s=>{s.approved=true;},
  ];
  for(const edit of edits){
    const s=fixture();edit(s);
    const r=assess(encode(s));blocked(r);
    assert.match(r.reason,/EXTERNAL_AUTHORITY_FORGED|FIXTURE_UNTRUSTED/);
  }
}));
test('invalid event schema, secret field or improper entry digest denied',()=>withSwitch(()=>{
  const a=fixture();a.entries[1].headers={Authorization:'secret'};
  blocked(assess(encode(a)),'SHADOW_ANCHOR_ENTRY_UNTRUSTED');
  const b=fixture();b.entries[1].entry_hash='g'.repeat(64);
  blocked(assess(encode(b)),'SHADOW_ANCHOR_ENTRY_UNTRUSTED');
  const c=fixture();c.entries[1].previous_hash=null;
  blocked(assess(encode(c)),'SHADOW_ANCHOR_ENTRY_UNTRUSTED');
}));
test('duplicate IDs, reordered events, invalid UTC and sequence gaps denied',()=>withSwitch(()=>{
  const edits=[
    s=>{s.entries[2].event_id='event:triaged';},
    s=>{s.entries[2].sequence=7;},
    s=>{s.entries[2].occurred_utc='2026-02-30T15:02:00Z';},
    s=>{s.entries[0].type='evidence_noted';},
    s=>{s.entries[1].type='manual_review_requested';},
  ];
  for(const edit of edits){
    const s=fixture();edit(s);rehash(s);
    blocked(assess(encode(s)),'SHADOW_ANCHOR_EVENT_HISTORY_UNTRUSTED');
  }
}));
test('altering HEAD, role or request identity without recomputing is detected',()=>withSwitch(()=>{
  const changes=[
    s=>{s.incident.head_sha='e'.repeat(40);},
    s=>{s.incident.key_role='development';},
    s=>{s.incident.request_digest_sha256='e'.repeat(64);},
  ];
  for(const change of changes){
    const s=fixture();change(s);
    blocked(assess(encode(s)),'SHADOW_ANCHOR_ENTRY_DIGEST_MISMATCH');
  }
}));
test('malformed oversized input, bad HEAD and unexpected actor fields denied',()=>withSwitch(()=>{
  const examples=[
    null,{},'broken-json',' '.repeat(16385),
    encode({...fixture(),readRealProvider:true}),
    encode({...fixture(),incident:{...fixture().incident,
      actor:'reviewer-b-bot'}}),
    encode({...fixture(),entries:[]}),
    encode({...fixture(),checkpoint:null}),
    encode({...fixture(),incident:{...fixture().incident,
      head_sha:'wrong-sha'}}),
  ];
  for(const x of examples)
    blocked(assess(x),'SHADOW_ANCHOR_FIXTURE_UNTRUSTED');
}));
test('paid Publisher and real gate cannot import chain mock verifier',()=>{
  const paid=readFileSync(new URL(
    '../scripts/protected-real-openrouter-review.mjs',import.meta.url),'utf8');
  const gate=readFileSync(new URL(
    '../scripts/openrouter-only-spend-gate.mjs',import.meta.url),'utf8');
  const module=readFileSync(new URL(
    '../scripts/openrouter-shadow-audit-anchor-offline.mjs',
    import.meta.url),'utf8');
  for(const content of [paid,gate])
    assert.doesNotMatch(content,/openrouter-shadow-audit-anchor-offline/);
  assert.match(gate,/OPENROUTER_MONTHLY_RESERVATION_AND_IDEMPOTENCY_NOT_IMPLEMENTED/);
  assert.doesNotMatch(module,/OPENROUTER_API_KEY|https?:\/\/|fetch\s*\(/);
});
