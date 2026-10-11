import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { canonicalJson } from '../src/canonical.mjs';
import { validateReviewerFindings } from '../src/findings-contract.mjs';
import {deriveAddedLinesFromDiff,isAddedLine} from './diff-added-lines.mjs';

const RUN=/^[A-Za-z0-9_:-]{8,180}$/;
const PATH=/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*$/;
const RULES=Object.freeze([
  Object.freeze({id:'unsafe-pr-target-workflow',severity:'high',
    pathOnly:/^\.github\/workflows\/.*\.ya?ml$/,
    pattern:/\bpull_request_target\b/,
    message:'Untrusted pull_request_target workflow trigger newly introduced'}),
  Object.freeze({id:'workflow-write-all',severity:'high',
    pathOnly:/^\.github\/workflows\/.*\.ya?ml$/,
    pattern:/^\s*permissions\s*:\s*(?:(["'])write-all\1|write-all)\s*(?:#.*)?$/,
    message:'Broad write-all workflow permissions newly introduced'}),
  Object.freeze({id:'workflow-untrusted-shell',severity:'high',
    pathOnly:/^\.github\/workflows\/.*\.ya?ml$/,
    pattern:/(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh|dash|ksh|ash)\b/,
    message:'Remote downloaded shell code execution newly introduced'}),
  Object.freeze({id:'workflow-token-write-scope',severity:'high',
    pathOnly:/^\.github\/workflows\/.*\.ya?ml$/,
    // Conservative trigger. A write scope can occur at job-level, where it
    // overrides a safe root permissions block. False positives remain FAIL,
    // never a silent PASS; independent review decides final authorization.
    // Recognize block YAML and inline flow mappings such as
    // permissions: { contents: write, actions: 'write' }.
    // Conservative matches remain FAIL, never permission to publish.
    pattern:/\b(?:actions|attestations|checks|contents|deployments|discussions|id-token|issues|models|packages|pages|pull-requests|repository-projects|security-events|statuses)\s*:\s*(?:(["'])write\1|write)(?=\s*[,}#]|\s*$)/,
    message:'Workflow newly requests a GitHub token write permission'})
]);
function deny(code){throw Error(code);}
function hash(v){return createHash('sha256').update(v).digest('hex');}
function newLineFromHunk(text){
  const m=text.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
  return m?Number(m[1]):null;
}
/**
 * Executes a narrow, deterministic, fail-only security audit of a unified
 * Git diff. It does not review semantics, authorize release or replace the
 * independent model reviewer. No network, source logging or provider spend.
 */
export function runFailOnlyStaticDiffAudit({diffBytes,runId}={}){
  if(!Buffer.isBuffer(diffBytes)||diffBytes.length<16||
     diffBytes.length>128*1024||!RUN.test(runId))
    deny('STATIC_AUDIT_INPUT_INVALID');
  const rawText=diffBytes.toString('utf8');
  if(!Buffer.from(rawText,'utf8').equals(diffBytes)||
     /\x00/.test(rawText))deny('STATIC_AUDIT_ENCODING_UNSUPPORTED');
  // Compare against the original bytes elsewhere; this is parser-only text.
  const text=rawText.replace(/\r\n/g,'\n');
  if(text.includes('\r'))deny('STATIC_AUDIT_ENCODING_UNSUPPORTED');
  let currentPath=null,newLine=null;const paths=[],findings=[];
  for(const line of text.split('\n')){
    if(line.startsWith('diff --git ')){
      const m=line.match(/^diff --git a\/(\S+) b\/(\S+)$/);
      if(!m||m[1]!==m[2]||!PATH.test(m[1]))
        deny('STATIC_AUDIT_PATH_UNSUPPORTED');
      currentPath=m[1];newLine=null;paths.push(currentPath);
      continue;
    }
    if(line.startsWith('@@ ')){
      newLine=newLineFromHunk(line);
      if(newLine===null||newLine<1)deny('STATIC_AUDIT_HUNK_INVALID');
      continue;
    }
    if(!currentPath||newLine===null)continue;
    if(line.startsWith('+++ ')||line.startsWith('--- ')||
       line.startsWith('\\ No newline'))continue;
    if(line.startsWith('+')){
      const added=line.slice(1);
      for(const rule of RULES){
        if(rule.pathOnly.test(currentPath)&&rule.pattern.test(added)){
          findings.push({
            fingerprint:hash(`${rule.id}| ${currentPath}:${newLine}|${added}`),
            severity:rule.severity,path:currentPath,line:newLine,
            message:rule.message,
            // Never echo private source text into findings, logs or public artifacts.
            evidence:`Static rule ${rule.id} matched newly added line ${newLine}`
          });
        }
      }
      newLine++;
    }else if(line.startsWith(' ')){newLine++;}
    else if(line.startsWith('-')){/* original-side line only */}
  }
  if(paths.length<1||paths.length>100||
     new Set(paths).size!==paths.length||
     findings.length>50)deny('STATIC_AUDIT_SCOPE_UNVERIFIED');
  // A regex-only scanner used to accept malformed/incomplete hunks, so an
  // adversarial patch could make the reported line numbers misleading.
  // Require a fully counted, ordered unified diff before using any finding.
  let trustedAnchors;
  try {
    trustedAnchors=deriveAddedLinesFromDiff({diffBytes});
  } catch {
    deny('STATIC_AUDIT_DIFF_STRUCTURE_INVALID');
  }
  if(JSON.stringify(Object.keys(trustedAnchors))!==JSON.stringify(paths)||
    findings.some(f=>!isAddedLine({
      anchors:trustedAnchors,path:f.path,line:f.line
    }))) deny('STATIC_AUDIT_LINE_COVERAGE_UNVERIFIED');
  const reportBytes=Buffer.from(canonicalJson({
    schema:'devfactory.reviewer-b.findings.v1',
    run_id:runId,
    summary:findings.length?
      'Deterministic static rules detected newly introduced risky patterns. This is not an independent semantic review.':
      'No matches for a narrow set of static security rules; independent semantic review remains required.',
    findings
  }));
  const checked=validateReviewerFindings({reportBytes,changedPaths:paths});
  // Private file paths may appear in findings; hide bytes from generic logs.
  const privateReport=Buffer.from(reportBytes);
  const safe={
    provisionalState:checked.provisionalState,
    blockingFindings:checked.blockingFindingCount,
    approvalAuthorized:false,independenceVerified:false
  };
  Object.defineProperties(safe,{
    reportBytes:{enumerable:false,configurable:false,
      get:()=>Buffer.from(privateReport)},
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(safe)),
        reportBytes:'[REDACTED_PRIVATE_REPORT]'})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[StaticDiffAudit: PRIVATE REPORT REDACTED]'
    }
  });
  return Object.freeze(safe);
}
