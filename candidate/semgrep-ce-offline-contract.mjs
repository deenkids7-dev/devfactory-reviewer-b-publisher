import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { canonicalJson } from '../src/canonical.mjs';
import { validateReviewerFindings } from '../src/findings-contract.mjs';
import { deriveAddedLinesFromDiff } from './diff-added-lines.mjs';

// Pure, fee-free Semgrep CE JSON validator; NO subprocess, network, review
// publication, trust-root onboarding, model invocation or approval authority.
const HASH=/^[0-9a-f]{64}$/, RUN=/^[A-Za-z0-9_:-]{8,180}$/;
const RULE=/^devfactory\.[a-z][a-z0-9-]{3,80}$/;
const LEVELS=Object.freeze({
 ERROR:'high',WARNING:'medium',INFO:'informational',
 CRITICAL:'critical',HIGH:'high',MEDIUM:'medium',LOW:'low'
});
const digest=v=>createHash('sha256').update(v).digest('hex');
function deny(code){throw Error(code);}

/**
 * Validate local Semgrep CE results against exact, previously authenticated
 * GitHub diff anchors. This function does NOT prove the scanner executed,
 * the rules bundle was used, or the worker was operated independently.
 * Worker must authenticate both separately. No cloud rules or credentials.
 */
export function validateOfflineSemgrepCEFindings({
 rawJson,runId,trustedDiffBytes,expectedDiffSha256,
 trustedChangedPaths,rulePackSha256,scanExitCode=0
}={}){
 if(typeof rawJson!=='string'||Buffer.byteLength(rawJson,'utf8')>256*1024||
    !RUN.test(runId)||!Buffer.isBuffer(trustedDiffBytes)||
    !HASH.test(expectedDiffSha256)||digest(trustedDiffBytes)!==expectedDiffSha256||
    !HASH.test(rulePackSha256)||scanExitCode!==0)
   deny('SEMGREP_CE_INPUT_UNVERIFIED');
 const anchors=deriveAddedLinesFromDiff({diffBytes:trustedDiffBytes});
 if(!Array.isArray(trustedChangedPaths)||!trustedChangedPaths.length||
    JSON.stringify(Object.keys(anchors))!==JSON.stringify(trustedChangedPaths))
   deny('SEMGREP_CE_DIFF_SCOPE_UNVERIFIED');
 let parsed;
 try{parsed=JSON.parse(rawJson);}catch{deny('SEMGREP_CE_JSON_INVALID');}
 if(!parsed||typeof parsed!=='object'||Array.isArray(parsed)||
    !Array.isArray(parsed.results)||parsed.results.length>100||
    !Array.isArray(parsed.errors)||parsed.errors.length>0||
    typeof parsed.version!=='string'||
    !/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(parsed.version))
   deny('SEMGREP_CE_SCAN_UNVERIFIED');
 const findings=[],seen=new Set();let preexisting=0;
 for(const hit of parsed.results){
   if(!hit||typeof hit!=='object'||Array.isArray(hit)||
      typeof hit.check_id!=='string'||!RULE.test(hit.check_id)||
      typeof hit.path!=='string'||!Object.hasOwn(anchors,hit.path)||
      !Number.isSafeInteger(hit.start?.line)||hit.start.line<1||
      !Number.isSafeInteger(hit.end?.line)||hit.end.line<hit.start.line||
      hit.end.line-hit.start.line>2000||
      !hit.extra||!Object.hasOwn(LEVELS,hit.extra.severity)||
      hit.extra.is_ignored===true)
      deny('SEMGREP_CE_FINDING_UNTRUSTED');
   const selectedLine=anchors[hit.path].find(n=>
     n>=hit.start.line&&n<=hit.end.line);
   if(selectedLine===undefined){preexisting++;continue;}
   const identity=hit.check_id+'\0'+hit.path+'\0'+selectedLine;
   // Semgrep can emit multiple matches of the SAME rule at one added line.
   // Preserve the single blocking finding rather than treating duplicates
   // as scanner corruption. Different rules/lines remain distinct.
   if(seen.has(identity))continue;
   seen.add(identity);
   findings.push({
     fingerprint:digest('devfactory.semgrep-ce.v1\0'+rulePackSha256+'\0'+identity),
     severity:LEVELS[hit.extra.severity],path:hit.path,line:selectedLine,
     message:'Local Semgrep CE rule '+hit.check_id+' matched newly added source code',
     evidence:'Offline rule '+hit.check_id+' at added line '+selectedLine+'; inspection required'
   });
   if(findings.length>50)deny('SEMGREP_CE_TOO_MANY_FINDINGS');
 }
 const privateBytes=Buffer.from(canonicalJson({
    schema:'devfactory.reviewer-b.findings.v1',run_id:runId,
    summary:findings.length?
      'Offline Semgrep CE found risky added patterns; this is not independent semantic review.':
      'No new local rule matches; independent semantic review is still required.',
    findings
 }));
 const validated=validateReviewerFindings({
   reportBytes:privateBytes,changedPaths:trustedChangedPaths
 });
 const safe={
   provisionalState:validated.provisionalState,
   blockingFindings:validated.blockingFindingCount,
   ruleFindings:findings.length,
   excludedPreexistingCount:preexisting,
   semgrepExecutedByThisModule:false,
   independentReviewVerified:false,
   approvalAuthorized:false,publishEvent:null
 };
 Object.defineProperties(safe,{
   privateCanonicalReportBytes:{enumerable:false,configurable:false,
     get:()=>Buffer.from(privateBytes)},
   toJSON:{enumerable:false,configurable:false,
     value:()=>({...Object.fromEntries(Object.entries(safe)),
       privateCanonicalReportBytes:'[REDACTED_PRIVATE_SEMGREP_REPORT]'})},
   [inspect.custom]:{enumerable:false,configurable:false,
     value:()=> '[OfflineSemgrepCE: PRIVATE REPORT REDACTED; NOT AUTHORIZED]'}
 });
 return Object.freeze(safe);
}
