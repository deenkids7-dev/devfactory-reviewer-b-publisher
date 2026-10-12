/**
 * R73: bounded, nonauthoritative cross-shard declaration hints.
 * Source: ONLY the full GitHub-authenticated immutable PRIVATE diff.
 * No repository-wide claim, external reads, cloud calls, report PASS, or
 * untrusted caller-provided prompt text. No right to approve/merge.
 */
import {inspect} from 'node:util';
import {createHash} from 'node:crypto';
import {deriveAddedLinesFromDiff} from './diff-added-lines.mjs';
import {prepareBoundedSemanticReview} from './semantic-review-request.mjs';

const REPO='deenkids7-dev/deenkids';
const JS=/\.(?:mjs|cjs|js|jsx|ts|tsx)$/i;
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const IDENT=/^[A-Za-z_$][\w$]{0,79}$/;
const trusted=new WeakSet();
function deny(){throw Error('DIFF_DECLARATIONS_UNTRUSTED');}
const digest=v=>createHash('sha256').update(v).digest('hex');

/**
 * Build only lexical names of declarations, never expressions or source
 * values. Accept introduced (+) and retained context (space) diff lines:
 * both are part of the HEAD version, unlike removed (-) lines. Omitted
 * names and code outside diff hunks remain UNKNOWN, never proof of absence.
 */
export function makeBoundedDiffDeclarationIndex({plan}={}){
 const scope=plan?.exactScope,source=plan?.privateDiffText;
 if(!scope||scope.repository!==REPO||
    !Number.isSafeInteger(scope.prNumber)||scope.prNumber<1||
    typeof scope.headSha!=='string'||!SHA.test(scope.headSha)||
    typeof scope.baseSha!=='string'||!SHA.test(scope.baseSha)||
    typeof scope.diffSha256!=='string'||!HASH.test(scope.diffSha256)||
    typeof source!=='string'||source.length<16||
    !Array.isArray(plan.changedPaths)||!plan.changedPaths.length)
    deny();
 const bytes=Buffer.from(source,'utf8');
 if(bytes.length>128*1024||digest(bytes)!==scope.diffSha256)deny();
 let rebuilt;
 try{
  rebuilt=prepareBoundedSemanticReview({snapshot:{
   repository:REPO,repository_id:1282086207,pr_number:scope.prNumber,
   head_sha:scope.headSha,base_sha:scope.baseSha,
   diff_sha256:scope.diffSha256
  },rawDiffBytes:bytes});
  deriveAddedLinesFromDiff({diffBytes:bytes});
 }catch{deny();}
 if(JSON.stringify(rebuilt.changedPaths)!==JSON.stringify(plan.changedPaths)||
    rebuilt.systemInstructions!==plan.systemInstructions)deny();
 const selected=[],seen=new Set();
 let path='',inHunk=false,count=0;
 function add(name,kind){
  if(!IDENT.test(name))return;
  const key=path+'|'+kind+'|'+name;
  if(seen.has(key))return;
  seen.add(key);count++;
  const line=path+':'+kind+' '+name;
  if(selected.join('\n').length+line.length+1<=1400&&selected.length<90)
   selected.push(line);
 }
 for(const line of source.replace(/\r\n/g,'\n').split('\n')){
  if(line.startsWith('diff --git ')){
   const m=line.match(/^diff --git a\/(\S+) b\/(\S+)$/);
   if(!m||m[1]!==m[2])deny();
   path=m[1];inHunk=false;continue;
  }
  if(line.startsWith('@@ ')){inHunk=true;continue;}
  if(!inHunk||!JS.test(path)||!['+',' '].includes(line[0])||
     line.startsWith('+++ '))continue;
  // Context lines are on BOTH sides; deleted (-) declarations no longer
  // exist on HEAD and must NEVER be passed as currently present.
  const added=line.slice(1).trim();
  const decl=added.match(/^(?:export\s+)?(?:default\s+)?(?:async\s+)?(function|class|const|let|var)\s+([A-Za-z_$][\w$]*)\b/);
  if(decl)add(decl[2],decl[1]);
  const imp=added.match(/^import\s+(?:type\s+)?\{([^}]+)\}/);
  if(imp){
   for(const item of imp[1].split(',')){
    const names=item.trim().replace(/^type\s+/,'').split(/\s+as\s+/);
    const local=names.at(-1)?.trim();
    if(local)add(local,'import');
   }
  }
  const def=added.match(/^import\s+([A-Za-z_$][\w$]*)\s+from\b/);
  if(def)add(def[1],'import');
 }
 const summary=selected.length?[
  'AUTHENTICATED HEAD-SIDE DIFF DECLARATIONS (added/context lines only, no complete file):',
  ...selected,
  count>selected.length?'TRUNCATED: some declarations omitted; absence never proves undefined.':'',
  'Names here may be in other shards; removed declarations are excluded. Check lexical scope and imports before claiming undefined.',
 ].filter(Boolean).join('\n'):'';
 const safe={repository:REPO,prNumber:scope.prNumber,
  headSha:scope.headSha,baseSha:scope.baseSha,
  originalDiffSha256:scope.diffSha256,entryCount:selected.length,
  truncated:count>selected.length,modelContextCompletenessVerified:false,
  independentReviewVerified:false,approvalAuthorized:false};
 Object.defineProperties(safe,{
  privateSummary:{enumerable:false,configurable:false,get:()=>summary},
  toJSON:{enumerable:false,configurable:false,value:()=>({
   entryCount:selected.length,truncated:count>selected.length,
   privateSummary:'[REDACTED]',approvalAuthorized:false})},
  [inspect.custom]:{enumerable:false,configurable:false,
   value:()=> '[AuthenticatedDiffDeclarationIndex: PRIVATE REDACTED]'}
 });
 Object.freeze(safe);trusted.add(safe);
 return safe;
}
/**
 * Cross-shard context is optional but cannot be forged by a PR, model,
 * synthetic JSON or a caller-supplied source summary.
 */
export function verifiedDiffDeclarationSummary({index,plan}={}){
 if(index===undefined||index===null)return '';
 if(!trusted.has(index)||!plan||!plan.exactScope||
   index.repository!==plan.exactScope.repository||
   index.prNumber!==plan.exactScope.prNumber||
   index.headSha!==plan.exactScope.headSha||
   index.baseSha!==plan.exactScope.baseSha||
   // The original immutable diff identity must be exact, not inferred only
   // from HEAD/BASE. A synthetic or stale cross-shard index can never add
   // declarations from a different authenticated diff.
   index.originalDiffSha256!==plan.exactScope.diffSha256||
   !Array.isArray(plan.changedPaths)||
   plan.changedPaths.some(path=>typeof path!=='string'))
   deny();
 return index.privateSummary;
}
