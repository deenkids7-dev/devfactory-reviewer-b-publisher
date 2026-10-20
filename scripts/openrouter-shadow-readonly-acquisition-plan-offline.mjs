/**
 * SYNTHETIC DESIGN CHECK ONLY — never a provider HTTP client.
 *
 * A management credential can also invoke administrative operations.
 * Restricting a future caller to a GET-only egress proxy is a separate
 * production task. This module never holds tokens or makes requests.
 */
const MAX_BYTES=16384,MAX_WORKSPACES=12,MAX_STEPS=60,MAX_OFFSET=100000;
const ROOT=['schema','scope','transport','credential','workspaces','operations'];
const CREDENTIAL=['kind','status','storage'];
const KEY_OP=['kind','method','path','workspace','offset','include_disabled'];
const CREDIT_OP=['kind','method','path'];
const WORKSPACE=/^(default|fixture:[a-z0-9][a-z0-9_-]{0,39})$/;
const object=(value,fields)=>value!==null&&typeof value==='object'&&
  !Array.isArray(value)&&Object.keys(value).length===fields.length&&
  fields.every(k=>Object.hasOwn(value,k));
const denial=(reason,extra={})=>Object.freeze({
  status:'BLOCKED',reason,syntheticOnly:true,verified:false,
  managementCredentialPresent:false,providerDataFetched:false,
  providerBillingAuthenticated:false,accountCoverageAuthenticated:false,
  readOnlyEnforcedInProduction:false,mayReadProviderData:false,
  mayMutateProvider:false,maySpend:false,mayReserve:false,
  mayRetryAmbiguousRequest:false,mayReleaseHold:false,mayDeploy:false,
  ...extra,
});

/**
 * Audit only an untrusted manifest of hypothetical read operations.
 * Never returns a runnable network request, URL, Authorization header,
 * API key, or authority of any kind, including on a structurally valid plan.
 */
export function assessSyntheticReadOnlyAcquisitionPlanOffline(json){
  if(process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY!=='1')
    return denial('SHADOW_READONLY_SYNTHETIC_SWITCH_REQUIRED');
  if(typeof json!=='string'||Buffer.byteLength(json,'utf8')>MAX_BYTES)
    return denial('SHADOW_READONLY_PLAN_UNTRUSTED');
  let data;
  try{data=JSON.parse(json)}catch{
    return denial('SHADOW_READONLY_PLAN_UNTRUSTED');
  }
  if(!object(data,ROOT)||
     data.schema!=='devfactory.openrouter-readonly-plan.synthetic.v1'||
     data.scope!=='illustrative-only'||data.transport!=='no-network'||
     !object(data.credential,CREDENTIAL)||
     data.credential.kind!=='management-key-capability'||
     data.credential.status!=='not-provisioned'||
     data.credential.storage!=='none'||
     !Array.isArray(data.workspaces)||data.workspaces.length<1||
     data.workspaces.length>MAX_WORKSPACES||
     !Array.isArray(data.operations)||data.operations.length<1||
     data.operations.length>MAX_STEPS)
    return denial('SHADOW_READONLY_PLAN_UNTRUSTED');

  const declared=new Set();
  for(const w of data.workspaces){
    if(typeof w!=='string'||!WORKSPACE.test(w)||declared.has(w))
      return denial('SHADOW_READONLY_WORKSPACE_INVALID_OR_DUPLICATE');
    declared.add(w);
  }
  // A default-only list does NOT prove there are no other workspaces.
  if(!declared.has('default'))
    return denial('SHADOW_READONLY_DEFAULT_WORKSPACE_NOT_DECLARED');

  const pages=new Map(),credits=[];let keyCount=0;
  for(const step of data.operations){
    if(!step||typeof step!=='object'||Array.isArray(step))
      return denial('SHADOW_READONLY_OPERATION_UNTRUSTED');
    if(step.kind==='keys'){
      if(!object(step,KEY_OP)||step.method!=='GET'||
         step.path!=='/api/v1/keys'||step.include_disabled!==true||
         typeof step.workspace!=='string'||
         !declared.has(step.workspace)||
         !Number.isSafeInteger(step.offset)||step.offset<0||
         step.offset>MAX_OFFSET)
        return denial('SHADOW_READONLY_KEY_LIST_OPERATION_FORBIDDEN');
      const existing=pages.get(step.workspace)??[];
      // Monotonic offsets reject duplicate pages, but do not prove
      // actual provider pagination exhaustion or include past keys.
      if(existing.length>0&&step.offset<=existing[existing.length-1])
        return denial('SHADOW_READONLY_PAGINATION_REUSED_OR_UNSORTED');
      existing.push(step.offset);pages.set(step.workspace,existing);
      keyCount++;
    }else if(step.kind==='credits'){
      if(!object(step,CREDIT_OP)||step.method!=='GET'||
         step.path!=='/api/v1/credits')
        return denial('SHADOW_READONLY_CREDITS_OPERATION_FORBIDDEN');
      credits.push(step);
    }else{
      // No create/update/delete, chat/completions or dynamic endpoints.
      return denial('SHADOW_READONLY_OPERATION_NOT_ALLOWLISTED');
    }
  }
  if(credits.length!==1)
    return denial('SHADOW_READONLY_CREDITS_READ_MISSING_OR_DUPLICATE');
  for(const workspace of declared){
    const offsets=pages.get(workspace);
    if(!offsets||offsets[0]!==0)
      return denial('SHADOW_READONLY_WORKSPACE_FIRST_PAGE_MISSING');
  }
  return denial('SHADOW_READONLY_STRUCTURAL_PLAN_ONLY',{
    simulatedDeclaredWorkspaceCount:declared.size,
    simulatedKeyListOperations:keyCount,
    simulatedCreditsReadOperations:credits.length,
    simulatedPaginationExhaustionVerified:false,
    simulatedAccountEnumerationVerified:false,
  });
}

/**
 * Offline threat-model fixture for the FUTURE token-isolating GET proxy.
 * An attacker controls the entire JSON. No symbolic field enforces
 * real DNS, TLS, permissions, egress or log redaction; those will need
 * independent production integration and proof.
 */
const PROXY_ROOT=['schema','scope','transport','credential','request',
  'upstream','response','audit'];
const PROXY_CREDENTIAL=['tokenPresent','secretStoreConnected'];
const PROXY_UPSTREAM=['target','tls','redirects','forwardedHeaders',
  'dnsVerification'];
const PROXY_KEYS=['kind','method','workspace','offset','include_disabled'];
const PROXY_CREDITS=['kind','method'];
const PROXY_RESPONSE=['source','httpStatus','contentType','sizeBytes',
  'redirected','unexpectedSecrets'];
const PROXY_AUDIT=['rawAuthorization','rawHeaders','rawResponse',
  'unredactedProviderIds','automaticReplay'];
const MAX_PROXY_BYTES=8192;
const MAX_RESPONSE_BYTES=65536;

/**
 * Pure refusal-oriented model. A "matching" fixture still grants ZERO
 * network, secret, read, dispatch or financial authority.
 */
export function assessSyntheticProxyBoundaryOffline(json){
  if(process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY!=='1')
    return denial('SHADOW_PROXY_SYNTHETIC_SWITCH_REQUIRED');
  if(typeof json!=='string'||Buffer.byteLength(json,'utf8')>MAX_PROXY_BYTES)
    return denial('SHADOW_PROXY_ENVELOPE_UNTRUSTED');
  let s;
  try{s=JSON.parse(json)}catch{
    return denial('SHADOW_PROXY_ENVELOPE_UNTRUSTED');
  }
  if(!object(s,PROXY_ROOT)||
     s.schema!=='devfactory.shadow-get-boundary.synthetic.v1'||
     s.scope!=='illustrative-only'||s.transport!=='no-network'||
     !object(s.credential,PROXY_CREDENTIAL)||
     s.credential.tokenPresent!==false||
     s.credential.secretStoreConnected!==false)
    return denial('SHADOW_PROXY_ENVELOPE_UNTRUSTED');

  const r=s.request;
  if(!r||typeof r!=='object'||Array.isArray(r))
    return denial('SHADOW_PROXY_REQUEST_UNTRUSTED');
  if(r.kind==='keys'){
    if(!object(r,PROXY_KEYS)||r.method!=='GET'||
       typeof r.workspace!=='string'||!WORKSPACE.test(r.workspace)||
       !Number.isSafeInteger(r.offset)||r.offset<0||
       r.offset>MAX_OFFSET||r.include_disabled!==true)
      return denial('SHADOW_PROXY_READ_OPERATION_FORBIDDEN');
  }else if(r.kind==='credits'){
    if(!object(r,PROXY_CREDITS)||r.method!=='GET')
      return denial('SHADOW_PROXY_READ_OPERATION_FORBIDDEN');
  }else return denial('SHADOW_PROXY_READ_OPERATION_FORBIDDEN');

  // No caller-controlled host, path, URI, port, redirects or HTTP headers.
  // These are symbolic requirements, NOT runtime enforcement claims.
  const u=s.upstream;
  if(!object(u,PROXY_UPSTREAM)||
     u.target!=='symbolic-fixed-openrouter-api'||
     u.tls!=='required-unverified'||
     u.redirects!=='deny'||
     u.forwardedHeaders!=='none'||
     u.dnsVerification!=='not-performed')
    return denial('SHADOW_PROXY_UPSTREAM_POLICY_UNTRUSTED');

  const audit=s.audit;
  if(!object(audit,PROXY_AUDIT)||
     PROXY_AUDIT.some(k=>audit[k]!==false))
    return denial('SHADOW_PROXY_AUDIT_OR_REPLAY_UNSAFE');

  const reply=s.response;
  if(!object(reply,PROXY_RESPONSE)||reply.source!=='unverified-fixture'||
     !Number.isSafeInteger(reply.httpStatus)||
     !Number.isSafeInteger(reply.sizeBytes)||reply.sizeBytes<0||
     reply.sizeBytes>MAX_RESPONSE_BYTES||
     typeof reply.redirected!=='boolean'||
     typeof reply.unexpectedSecrets!=='boolean')
    return denial('SHADOW_PROXY_RESPONSE_UNTRUSTED');
  if(reply.redirected||reply.httpStatus>=300&&reply.httpStatus<400)
    return denial('SHADOW_PROXY_REDIRECT_FORBIDDEN');
  if(reply.unexpectedSecrets)
    return denial('SHADOW_PROXY_RESPONSE_SECRET_MARKER');
  // HTTP failures/timeout/ratelimits are NOT empty billing or free calls.
  if(reply.httpStatus!==200)
    return denial('SHADOW_PROXY_UPSTREAM_OUTCOME_UNKNOWN_NO_RETRY');
  if(reply.contentType!=='application/json'||reply.sizeBytes===0)
    return denial('SHADOW_PROXY_RESPONSE_TYPE_OR_SIZE_INVALID');

  return denial('SHADOW_PROXY_FIXTURE_POLICY_MATCH_NOT_AUTHORITY',{
    simulatedRequestKind:r.kind,
    simulatedResponseBytes:reply.sizeBytes,
    proxyDeployed:false,actualEgressRestricted:false,
    secretRedactionVerified:false,providerResponseAuthenticated:false,
  });
}

/**
 * Table of decisions for *untrusted hypothetical* GET-proxy incidents.
 * No secret, socket, actual OpenRouter status, provider reconciliation,
 * session scheduling, billing operation or automatic retry is involved.
 *
 * A "200" mock is NOT evidence of authentic, complete billing.
 */
const INCIDENT_KEYS=['schema','scope','transport','operation','event',
  'httpStatus','bodyBytes','contentType','responseComplete',
  'source','hasSecretMarker','retryAfterSeconds','audit'];
const INCIDENT_AUDIT=['rawAuthorization','rawBody','unredactedIds',
  'autoRetry','autoReleaseHold','autoResumeRunner'];
const INCIDENT_EVENTS=new Set(['response','timeout','connection_reset',
  'dns_failure','tls_failure','redirect','truncated','invalid_json']);
const MAX_INCIDENT_BYTES=4096;
const incident=(code,incidentClass)=>denial(code,{
  simulatedIncidentClass:incidentClass,
  simulatedManualInvestigationRequired:true,
  syntheticIncidentOnly:true,
  automaticRetryScheduled:false,
  simulatedBillIsSettled:false,
  simulatedProviderEvidenceVerified:false,
});

/**
 * All routes return BLOCKED. Operators must investigate outside this
 * synthetic classifier, and any paid incident remains quarantined.
 */
export function assessSyntheticProxyIncidentOffline(json){
  if(process.env.REVIEWER_B_SYNTHETIC_SHADOW_ONLY!=='1')
    return incident('SHADOW_INCIDENT_SYNTHETIC_SWITCH_REQUIRED','invalid');
  if(typeof json!=='string'||Buffer.byteLength(json,'utf8')>MAX_INCIDENT_BYTES)
    return incident('SHADOW_INCIDENT_FIXTURE_UNTRUSTED','invalid');
  let s;
  try{s=JSON.parse(json)}catch{
    return incident('SHADOW_INCIDENT_FIXTURE_UNTRUSTED','invalid');
  }
  if(!object(s,INCIDENT_KEYS)||
     s.schema!=='devfactory.shadow-get-incident.synthetic.v1'||
     s.scope!=='illustrative-only'||s.transport!=='no-network'||
     !['keys','credits'].includes(s.operation)||
     !INCIDENT_EVENTS.has(s.event)||
     !Number.isSafeInteger(s.httpStatus)||s.httpStatus<0||
     s.httpStatus>599||
     !Number.isSafeInteger(s.bodyBytes)||s.bodyBytes<0||
     s.bodyBytes>MAX_RESPONSE_BYTES||
     !['application/json','other','none'].includes(s.contentType)||
     typeof s.responseComplete!=='boolean'||
     s.source!=='unverified-fixture'||
     typeof s.hasSecretMarker!=='boolean'||
     !(s.retryAfterSeconds===null||
       (Number.isSafeInteger(s.retryAfterSeconds)&&
        s.retryAfterSeconds>=0&&s.retryAfterSeconds<=86400))||
     !object(s.audit,INCIDENT_AUDIT))
    return incident('SHADOW_INCIDENT_FIXTURE_UNTRUSTED','invalid');

  // Only a simulated complete on-wire HTTP response has a status.
  // Redirects are represented separately so that no 3xx can be followed.
  if((s.event==='response'&&s.httpStatus<100)||
     (s.event==='redirect'&&
      !(s.httpStatus>=300&&s.httpStatus<=399))||
     (!['response','redirect'].includes(s.event)&&s.httpStatus!==0))
    return incident('SHADOW_INCIDENT_EVENT_STATUS_CONTRADICTORY','invalid');
  if(s.audit.rawAuthorization||s.audit.rawBody||
     s.audit.unredactedIds||s.audit.autoRetry||
     s.audit.autoReleaseHold||s.audit.autoResumeRunner)
    return incident('SHADOW_INCIDENT_AUDIT_OR_AUTOMATION_FORBIDDEN','security');
  if(s.hasSecretMarker)
    return incident('SHADOW_INCIDENT_SECRET_EXPOSURE_REVIEW','security');
  if(s.event==='redirect'||s.httpStatus>=300&&s.httpStatus<=399)
    return incident('SHADOW_INCIDENT_REDIRECT_FORBIDDEN','network');
  if(s.event==='timeout'||s.event==='connection_reset'||
     s.event==='dns_failure'||s.event==='tls_failure')
    return incident('SHADOW_INCIDENT_NETWORK_UNKNOWN_NO_RETRY','network');
  if(s.event==='truncated'||s.event==='invalid_json'||
     !s.responseComplete)
    return incident('SHADOW_INCIDENT_RESPONSE_INCOMPLETE','provenance');
  if(s.httpStatus===401)
    return incident('SHADOW_INCIDENT_AUTHENTICATION_REVIEW','identity');
  if(s.httpStatus===403)
    return incident('SHADOW_INCIDENT_AUTHORIZATION_REVIEW','identity');
  if(s.httpStatus===429)
    return incident('SHADOW_INCIDENT_RATE_LIMIT_MANUAL_REVIEW','rate-limit');
  if(s.httpStatus>=500)
    return incident('SHADOW_INCIDENT_PROVIDER_FAILURE_UNKNOWN','provider');
  if(s.httpStatus!==200)
    return incident('SHADOW_INCIDENT_OTHER_STATUS_UNRESOLVED','provider');
  if(s.contentType!=='application/json'||s.bodyBytes===0)
    return incident('SHADOW_INCIDENT_UNTRUSTED_200_PAYLOAD','provenance');

  // HTTP 200 with internally consistent mock metadata still carries
  // no trusted proof of source, invoice completeness, charge or key scope.
  return incident('SHADOW_INCIDENT_200_UNVERIFIED_NOT_SETTLED','provenance');
}
