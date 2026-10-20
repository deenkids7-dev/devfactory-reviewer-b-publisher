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
