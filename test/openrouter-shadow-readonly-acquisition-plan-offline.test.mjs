import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessSyntheticReadOnlyAcquisitionPlanOffline as assess}
  from '../scripts/openrouter-shadow-readonly-acquisition-plan-offline.mjs';

const plan=()=>({
  schema:'devfactory.openrouter-readonly-plan.synthetic.v1',
  scope:'illustrative-only',
  transport:'no-network',
  credential:{kind:'management-key-capability',
    status:'not-provisioned',storage:'none'},
  workspaces:['default','fixture:second'],
  operations:[
    {kind:'keys',method:'GET',path:'/api/v1/keys',
      workspace:'default',offset:0,include_disabled:true},
    {kind:'keys',method:'GET',path:'/api/v1/keys',
      workspace:'default',offset:20,include_disabled:true},
    {kind:'keys',method:'GET',path:'/api/v1/keys',
      workspace:'fixture:second',offset:0,include_disabled:true},
    {kind:'credits',method:'GET',path:'/api/v1/credits'},
  ],
});
const encode=v=>JSON.stringify(v);
const withSwitch=fn=>{
  const previous=process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY='1';
  try{return fn()}finally{
    if(previous===undefined)
      delete process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
    else process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY=previous;
  }
};
const blocked=(response,reason)=>{
  assert.equal(response.status,'BLOCKED');
  assert.equal(response.syntheticOnly,true);
  for(const key of [
    'verified','managementCredentialPresent','providerDataFetched',
    'providerBillingAuthenticated','accountCoverageAuthenticated',
    'readOnlyEnforcedInProduction','mayReadProviderData',
    'mayMutateProvider','maySpend','mayReserve',
    'mayRetryAmbiguousRequest','mayReleaseHold','mayDeploy',
  ])assert.equal(response[key],false,key);
  assert.ok(Object.isFrozen(response));
  if(reason)assert.equal(response.reason,reason);
};
test('without explicit synthetic switch, even valid descriptor is rejected',()=>{
  const prev=process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  delete process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  try{blocked(assess(encode(plan())),
    'SHADOW_READONLY_SYNTHETIC_SWITCH_REQUIRED');}
  finally{
    if(prev!==undefined)process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY=prev;
  }
});
test('two-workspace GET-only descriptor still has no authenticated authority',()=>withSwitch(()=>{
  const r=assess(encode(plan()));
  blocked(r,'SHADOW_READONLY_STRUCTURAL_PLAN_ONLY');
  assert.equal(r.simulatedDeclaredWorkspaceCount,2);
  assert.equal(r.simulatedKeyListOperations,3);
  assert.equal(r.simulatedCreditsReadOperations,1);
  assert.equal(r.simulatedPaginationExhaustionVerified,false);
  assert.equal(r.simulatedAccountEnumerationVerified,false);
}));
test('default workspace alone cannot prove complete provider account coverage',()=>withSwitch(()=>{
  const s=plan();
  s.workspaces=['default'];
  s.operations.splice(2,1);
  const r=assess(encode(s));
  blocked(r,'SHADOW_READONLY_STRUCTURAL_PLAN_ONLY');
  assert.equal(r.simulatedDeclaredWorkspaceCount,1);
  assert.equal(r.accountCoverageAuthenticated,false);
}));
test('no actual provider credentials, token or network transport accepted',()=>withSwitch(()=>{
  const mutations=[
    s=>{s.credential.status='active';},
    s=>{s.credential.storage='github-secret';},
    s=>{s.credential.token='synthetic';},
    s=>{s.authorization='Bearer fake';},
    s=>{s.transport='https-client';},
    s=>{s.scope='account-wide-verified';},
    s=>{s.verified=true;},
  ];
  for(const mutate of mutations){
    const s=plan();mutate(s);
    blocked(assess(encode(s)),'SHADOW_READONLY_PLAN_UNTRUSTED');
  }
}));
test('mutation verbs and chat/completions API are never allowlisted',()=>withSwitch(()=>{
  const variants=[
    {kind:'keys',method:'PATCH',path:'/api/v1/keys',
      workspace:'default',offset:0,include_disabled:true},
    {kind:'keys',method:'POST',path:'/api/v1/chat/completions',
      workspace:'default',offset:0,include_disabled:true},
    {kind:'keys',method:'DELETE',path:'/api/v1/keys',
      workspace:'default',offset:0,include_disabled:true},
    {kind:'credits',method:'POST',path:'/api/v1/credits'},
    {kind:'credits',method:'GET',path:'/api/v1/keys'},
  ];
  for(const op of variants){
    const s=plan();s.operations[0]=op;
    const r=assess(encode(s));
    blocked(r);
    assert.match(r.reason,/OPERATION_FORBIDDEN/);
  }
}));
test('unknown, computed and mutation-capable endpoints stay denied',()=>withSwitch(()=>{
  const operations=[
    {kind:'generation',method:'GET',path:'/api/v1/generation'},
    {kind:'key_update',method:'PATCH',path:'/api/v1/keys/fake'},
    {kind:'keys',method:'GET',path:'/api/v1/keys?offset=0',
      workspace:'default',offset:0,include_disabled:true},
    {kind:'keys',method:'GET',path:'/api/v1/keys/',
      workspace:'default',offset:0,include_disabled:true},
  ];
  for(const op of operations){
    const s=plan();s.operations[0]=op;
    const r=assess(encode(s));blocked(r);
    assert.match(r.reason,/NOT_ALLOWLISTED|OPERATION_FORBIDDEN/);
  }
}));
test('disabled and rotated-key omission cannot be described as complete',()=>withSwitch(()=>{
  const s=plan();s.operations[0].include_disabled=false;
  blocked(assess(encode(s)),'SHADOW_READONLY_KEY_LIST_OPERATION_FORBIDDEN');
}));
test('missing workspace first page or offset 0 is detected',()=>withSwitch(()=>{
  const s=plan();
  s.operations.splice(2,1);
  blocked(assess(encode(s)),'SHADOW_READONLY_WORKSPACE_FIRST_PAGE_MISSING');
  const t=plan();t.operations[2].offset=50;
  blocked(assess(encode(t)),'SHADOW_READONLY_WORKSPACE_FIRST_PAGE_MISSING');
}));
test('pagination duplication, unordered offsets and invalid limits blocked',()=>withSwitch(()=>{
  for(const offset of [0,-1,1.5,100001,'20',null]){
    const s=plan();s.operations[1].offset=offset;
    const r=assess(encode(s));blocked(r);
    assert.match(r.reason,/PAGINATION_REUSED_OR_UNSORTED|OPERATION_FORBIDDEN/);
  }
}));
test('missing or duplicate aggregate credits descriptor fails closed',()=>withSwitch(()=>{
  const s=plan();s.operations.pop();
  blocked(assess(encode(s)),'SHADOW_READONLY_CREDITS_READ_MISSING_OR_DUPLICATE');
  const t=plan();t.operations.push(
    {kind:'credits',method:'GET',path:'/api/v1/credits'});
  blocked(assess(encode(t)),'SHADOW_READONLY_CREDITS_READ_MISSING_OR_DUPLICATE');
}));
test('user cannot forge workspace enumeration or insert foreign workspace',()=>withSwitch(()=>{
  const s=plan();s.workspaces.push('default');
  blocked(assess(encode(s)),'SHADOW_READONLY_WORKSPACE_INVALID_OR_DUPLICATE');
  const t=plan();t.operations[2].workspace='fixture:unknown';
  blocked(assess(encode(t)),'SHADOW_READONLY_KEY_LIST_OPERATION_FORBIDDEN');
  const u=plan();u.workspaces=['fixture:second'];
  blocked(assess(encode(u)),'SHADOW_READONLY_DEFAULT_WORKSPACE_NOT_DECLARED');
  const v=plan();v.workspaces.push('https://evil.invalid');
  blocked(assess(encode(v)),'SHADOW_READONLY_WORKSPACE_INVALID_OR_DUPLICATE');
}));
test('strict field typing denies runnable hostnames, headers and HTTP bodies',()=>withSwitch(()=>{
  const cases=[
    s=>{s.operations[0].url='https://openrouter.ai';},
    s=>{s.operations[0].headers={Authorization:'Bearer hidden'};},
    s=>{s.operations[0].body={model:'paid'};},
    s=>{s.operations[0].offset=true;},
    s=>{s.operations[0].include_disabled='true';},
    s=>{s.operations[3].workspace='default';},
  ];
  for(const change of cases){
    const s=plan();change(s);
    const r=assess(encode(s));blocked(r);
    assert.match(r.reason,/OPERATION_FORBIDDEN/);
  }
}));
test('malformed JSON and oversized declarations remain denied',()=>withSwitch(()=>{
  const inputs=[
    null,{},'not-json',' '.repeat(16385),
    encode({...plan(),workspaces:[]}),
    encode({...plan(),operations:[]}),
    encode({...plan(),workspaces:Array(13).fill('default')}),
    encode({...plan(),operations:Array(61).fill(plan().operations[0])}),
  ];
  for(const input of inputs){
    const r=assess(input);blocked(r);
    assert.equal(r.reason,'SHADOW_READONLY_PLAN_UNTRUSTED');
  }
}));
test('design checker stays unimported by protected paid paths',()=>{
  const protectedFile=readFileSync(new URL(
    '../scripts/protected-real-openrouter-review.mjs',import.meta.url),'utf8');
  const gate=readFileSync(new URL(
    '../scripts/openrouter-only-spend-gate.mjs',import.meta.url),'utf8');
  const self=readFileSync(new URL(
    '../scripts/openrouter-shadow-readonly-acquisition-plan-offline.mjs',
    import.meta.url),'utf8');
  for(const s of [protectedFile,gate])
    assert.doesNotMatch(s,/openrouter-shadow-readonly-acquisition-plan-offline/);
  assert.match(gate,/OPENROUTER_MONTHLY_RESERVATION_AND_IDEMPOTENCY_NOT_IMPLEMENTED/);
  assert.doesNotMatch(self,/OPENROUTER_API_KEY|https?:\/\/|fetch\s*\(/);
});
