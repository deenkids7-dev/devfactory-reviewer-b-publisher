import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessSyntheticReadOnlyAcquisitionPlanOffline as assess,
  assessSyntheticProxyBoundaryOffline as probe}
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

const proxyFixture=()=>({
  schema:'devfactory.shadow-get-boundary.synthetic.v1',
  scope:'illustrative-only',transport:'no-network',
  credential:{tokenPresent:false,secretStoreConnected:false},
  request:{kind:'keys',method:'GET',workspace:'default',
    offset:0,include_disabled:true},
  upstream:{target:'symbolic-fixed-openrouter-api',
    tls:'required-unverified',redirects:'deny',
    forwardedHeaders:'none',dnsVerification:'not-performed'},
  response:{source:'unverified-fixture',httpStatus:200,
    contentType:'application/json',sizeBytes:1234,
    redirected:false,unexpectedSecrets:false},
  audit:{rawAuthorization:false,rawHeaders:false,rawResponse:false,
    unredactedProviderIds:false,automaticReplay:false},
});
test('proxy fixture that matches offline shape still has no real authority',()=>withSwitch(()=>{
  const r=probe(encode(proxyFixture()));
  blocked(r,'SHADOW_PROXY_FIXTURE_POLICY_MATCH_NOT_AUTHORITY');
  assert.equal(r.simulatedRequestKind,'keys');
  assert.equal(r.simulatedResponseBytes,1234);
  assert.equal(r.proxyDeployed,false);
  assert.equal(r.actualEgressRestricted,false);
  assert.equal(r.secretRedactionVerified,false);
  assert.equal(r.providerResponseAuthenticated,false);
}));
test('without synthetic opt-in, proxy model denies even harmless fixture',()=>{
  const prev=process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  delete process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY;
  try{blocked(probe(encode(proxyFixture())),
    'SHADOW_PROXY_SYNTHETIC_SWITCH_REQUIRED');}
  finally{
    if(prev!==undefined)process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY=prev;
  }
});
test('symbolic credits GET is the only other acceptable mock operation',()=>withSwitch(()=>{
  const s=proxyFixture();s.request={kind:'credits',method:'GET'};
  blocked(probe(encode(s)),'SHADOW_PROXY_FIXTURE_POLICY_MATCH_NOT_AUTHORITY');
  for(const method of ['HEAD','POST','PATCH','PUT','DELETE','OPTIONS']){
    const item=proxyFixture();item.request.method=method;
    blocked(probe(encode(item)),'SHADOW_PROXY_READ_OPERATION_FORBIDDEN');
  }
}));
test('caller-controlled URL, host, path, query, port and headers rejected',()=>withSwitch(()=>{
  const changes=[
    s=>{s.request.url='https://other.invalid';},
    s=>{s.request.host='localhost';},
    s=>{s.request.path='/api/v1/keys';},
    s=>{s.request.query='offset=0';},
    s=>{s.request.port=443;},
    s=>{s.request.headers={Authorization:'Bearer fake'};},
    s=>{s.request.body={model:'paid'};},
    s=>{s.request.kind='generation';},
    s=>{s.request.workspace='..';},
  ];
  for(const change of changes){
    const s=proxyFixture();change(s);
    blocked(probe(encode(s)),'SHADOW_PROXY_READ_OPERATION_FORBIDDEN');
  }
}));
test('proxy cannot receive a real token, secret or runnable transport',()=>withSwitch(()=>{
  const changes=[
    s=>{s.credential.tokenPresent=true;},
    s=>{s.credential.secretStoreConnected=true;},
    s=>{s.credential.token='not-a-real-key';},
    s=>{s.transport='network';},
    s=>{s.scope='provider-authenticated';},
    s=>{s.credential.secretName='LIVE_KEY';},
    s=>{s.managementKey='untrusted';},
  ];
  for(const change of changes){
    const s=proxyFixture();change(s);
    blocked(probe(encode(s)),'SHADOW_PROXY_ENVELOPE_UNTRUSTED');
  }
}));
test('upstream SSRF, redirect and TLS design tampering is blocked',()=>withSwitch(()=>{
  const changes=[
    s=>{s.upstream.target='other-host';},
    s=>{s.upstream.target='127.0.0.1';},
    s=>{s.upstream.tls='http';},
    s=>{s.upstream.redirects='follow';},
    s=>{s.upstream.forwardedHeaders='all';},
    s=>{s.upstream.dnsVerification='proved';},
    s=>{s.upstream.proxy='attacker';},
    s=>{s.upstream.path='/api/v1/chat/completions';},
  ];
  for(const change of changes){
    const s=proxyFixture();change(s);
    blocked(probe(encode(s)),'SHADOW_PROXY_UPSTREAM_POLICY_UNTRUSTED');
  }
}));
test('logs may not retain credentials, raw responses or identifiers',()=>withSwitch(()=>{
  for(const field of [
    'rawAuthorization','rawHeaders','rawResponse',
    'unredactedProviderIds','automaticReplay']){
    const s=proxyFixture();s.audit[field]=true;
    blocked(probe(encode(s)),'SHADOW_PROXY_AUDIT_OR_REPLAY_UNSAFE');
  }
  const t=proxyFixture();t.audit.destination='user-controlled';
  blocked(probe(encode(t)),'SHADOW_PROXY_AUDIT_OR_REPLAY_UNSAFE');
}));
test('3xx response or simulated redirection is always blocked',()=>withSwitch(()=>{
  for(const status of [301,302,307,308]){
    const s=proxyFixture();s.response.httpStatus=status;
    blocked(probe(encode(s)),'SHADOW_PROXY_REDIRECT_FORBIDDEN');
  }
  const s=proxyFixture();s.response.redirected=true;
  blocked(probe(encode(s)),'SHADOW_PROXY_REDIRECT_FORBIDDEN');
}));
test('HTTP 401, 403, 404, 429 and 5xx never prove a free request',()=>withSwitch(()=>{
  for(const status of [0,204,401,403,404,408,409,429,500,502,503]){
    const s=proxyFixture();s.response.httpStatus=status;
    blocked(probe(encode(s)),'SHADOW_PROXY_UPSTREAM_OUTCOME_UNKNOWN_NO_RETRY');
  }
}));
test('mock response containing a secret marker is quarantined',()=>withSwitch(()=>{
  const s=proxyFixture();s.response.unexpectedSecrets=true;
  blocked(probe(encode(s)),'SHADOW_PROXY_RESPONSE_SECRET_MARKER');
}));
test('untrusted MIME or empty success response cannot imply completeness',()=>withSwitch(()=>{
  for(const contentType of ['text/html','application/x-ndjson',
    'application/json; charset=utf-8',null]){
    const s=proxyFixture();s.response.contentType=contentType;
    blocked(probe(encode(s)),'SHADOW_PROXY_RESPONSE_TYPE_OR_SIZE_INVALID');
  }
  const s=proxyFixture();s.response.sizeBytes=0;
  blocked(probe(encode(s)),'SHADOW_PROXY_RESPONSE_TYPE_OR_SIZE_INVALID');
}));
test('oversize, wrong-type and surprising reply fields fail closed',()=>withSwitch(()=>{
  const changes=[
    s=>{s.response.sizeBytes=65537;},
    s=>{s.response.sizeBytes=-1;},
    s=>{s.response.sizeBytes=1.5;},
    s=>{s.response.httpStatus='200';},
    s=>{s.response.redirected='false';},
    s=>{s.response.source='provider-signed';},
    s=>{s.response.headers={'set-cookie':'secret'};},
    s=>{s.response.body='raw-secret';},
    s=>{s.response.unexpectedSecrets=null;},
  ];
  for(const change of changes){
    const s=proxyFixture();change(s);
    blocked(probe(encode(s)),'SHADOW_PROXY_RESPONSE_UNTRUSTED');
  }
}));
test('synthetic proxy envelope is strictly bounded and reject unknown keys',()=>withSwitch(()=>{
  const malformed=[
    null,{},'bad json',' '.repeat(8193),
    encode({...proxyFixture(),proxyAuthorization:true}),
    encode({...proxyFixture(),request:null}),
    encode({...proxyFixture(),response:null}),
  ];
  for(const item of malformed){
    const r=probe(item);blocked(r);
    assert.match(r.reason,/ENVELOPE_UNTRUSTED|RESPONSE_UNTRUSTED|REQUEST_UNTRUSTED/);
  }
}));
test('protected paid Publisher still cannot import synthetic proxy model',()=>{
  const paid=readFileSync(new URL(
    '../scripts/protected-real-openrouter-review.mjs',import.meta.url),'utf8');
  const gate=readFileSync(new URL(
    '../scripts/openrouter-only-spend-gate.mjs',import.meta.url),'utf8');
  for(const s of [paid,gate])
    assert.doesNotMatch(s,/assessSyntheticProxyBoundaryOffline|shadow-readonly-acquisition-plan-offline/);
  assert.match(gate,/OPENROUTER_MONTHLY_RESERVATION_AND_IDEMPOTENCY_NOT_IMPLEMENTED/);
});
