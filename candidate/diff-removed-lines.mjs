/**
 * R75: OLD-side removed-line coordinates from the SAME authenticated unified
 * diff as the existing NEW-side anchored reviewer contract.
 * The strict added-line parser proves Git hunk lengths/paths BEFORE deriving
 * OLD anchors. No free-text model paths, guessed line numbers or network.
 */
import {deriveAddedLinesFromDiff} from './diff-added-lines.mjs';
function deny(){throw Error('DIFF_OLD_ANCHOR_INVALID');}
export function deriveRemovedLinesFromDiff({diffBytes}={}){
 const verified=deriveAddedLinesFromDiff({diffBytes});
 const result=Object.create(null);
 for(const path of Object.keys(verified))result[path]=[];
 let file=null,inHunk=false,oldLine=0;
 const source=diffBytes.toString('utf8').replace(/\r\n/g,'\n');
 for(const line of source.split('\n')){
  if(line.startsWith('diff --git ')){
   const m=line.match(/^diff --git a\/(\S+) b\/(\S+)$/);
   if(!m||m[1]!==m[2]||!Object.hasOwn(result,m[1]))deny();
   file=m[1];inHunk=false;continue;
  }
  if(line.startsWith('@@ ')){
   const m=line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
   if(!file||!m)deny();
   oldLine=Number(m[1]);inHunk=true;continue;
  }
  if(!inHunk)continue;
  if(line.startsWith('\\ No newline at end of file'))continue;
  if(line.startsWith('-')){
   if(oldLine<1||oldLine>1_000_000)deny();
   result[file].push(oldLine++);
  }else if(line.startsWith(' ')){
   oldLine++;
  }
  // Added lines do not advance OLD-side coordinates.
 }
 for(const path of Object.keys(result))Object.freeze(result[path]);
 return Object.freeze(result);
}
export function isRemovedLine({anchors,path,line}={}){
 return !!(anchors&&Object.hasOwn(anchors,path)&&
   Number.isSafeInteger(line)&&anchors[path].includes(line));
}
