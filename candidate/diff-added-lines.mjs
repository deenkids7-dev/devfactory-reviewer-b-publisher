// Pure, bounded source-line anchoring for authenticated unified Git diffs.
// No network, model, secrets, GitHub write or approval authority.
const PATH=/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;
function deny(code){throw Error(code);}
export function deriveAddedLinesFromDiff({diffBytes}={}){
  if(!Buffer.isBuffer(diffBytes)||diffBytes.length<16||
    diffBytes.length>128*1024)deny('DIFF_ANCHOR_INPUT_UNTRUSTED');
  const rawSource=diffBytes.toString('utf8');
  if(!Buffer.from(rawSource,'utf8').equals(diffBytes)||/\x00/.test(rawSource))
    deny('DIFF_ANCHOR_ENCODING_INVALID');
  // Parse CRLF safely without modifying the authenticated source bytes.
  const source=rawSource.replace(/\r\n/g,'\n');
  if(source.includes('\r'))deny('DIFF_ANCHOR_ENCODING_INVALID');
  const entries=Object.create(null);
  let file=null,oldLeft=0,newLeft=0,newLine=0,inHunk=false;
  let oldHeader=false,newHeader=false,hasHunk=false;
  let previousOldEnd=-1,previousNewEnd=-1,previousHunk=false;
  function finishHunk(){
    if(inHunk&&(oldLeft!==0||newLeft!==0))deny('DIFF_ANCHOR_HUNK_MISMATCH');
    inHunk=false;
  }
  function finishFile(){
    finishHunk();
    if(file&&(!oldHeader||!newHeader||!hasHunk))
      deny('DIFF_ANCHOR_FILE_INCOMPLETE');
  }
  for(const line of source.split('\n')){
    if(line.startsWith('diff --git ')){
      finishFile();
      const m=line.match(/^diff --git a\/(\S+) b\/(\S+)$/);
      if(!m||m[1]!==m[2]||!PATH.test(m[1])||
        Object.hasOwn(entries,m[1]))deny('DIFF_ANCHOR_PATH_INVALID');
      file=m[1];entries[file]=[];
      oldLeft=0;newLeft=0;newLine=0;
      inHunk=false;oldHeader=false;newHeader=false;hasHunk=false;
      previousOldEnd=-1;previousNewEnd=-1;previousHunk=false;
      continue;
    }
    if(!file){if(line==='')continue;deny('DIFF_ANCHOR_FILE_INCOMPLETE');}
    if(line.startsWith('@@ ')){
      finishHunk();
      if(!oldHeader||!newHeader)deny('DIFF_ANCHOR_FILE_INCOMPLETE');
      const m=line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$/);
      if(!m)deny('DIFF_ANCHOR_HUNK_MISMATCH');
      oldLeft=m[2]===undefined?1:Number(m[2]);
      newLeft=m[4]===undefined?1:Number(m[4]);
      newLine=Number(m[3]);
      if(![oldLeft,newLeft,newLine].every(Number.isSafeInteger)||
        oldLeft<0||newLeft<0||newLine<0||oldLeft>100000||newLeft>100000||
        oldLeft+newLeft===0)deny('DIFF_ANCHOR_HUNK_MISMATCH');
      const oldStart=Number(m[1]);
      if(!Number.isSafeInteger(oldStart)||
         (oldLeft>0&&oldStart===0)||
         (newLeft>0&&newLine===0)||
         (previousHunk&&(oldStart<previousOldEnd||
           newLine<previousNewEnd)))
        deny('DIFF_ANCHOR_HUNK_ORDER_INVALID');
      previousOldEnd=oldStart+oldLeft;
      previousNewEnd=newLine+newLeft;
      if(!Number.isSafeInteger(previousOldEnd)||
         !Number.isSafeInteger(previousNewEnd))
        deny('DIFF_ANCHOR_HUNK_ORDER_INVALID');
      previousHunk=true;
      inHunk=true;hasHunk=true;
      continue;
    }
    if(inHunk&&line.startsWith('\\ No newline at end of file'))continue;
    if(inHunk&&(oldLeft>0||newLeft>0)){
      if(line[0]==='+'){
        if(!newLeft||newLine<1)deny('DIFF_ANCHOR_HUNK_MISMATCH');
        entries[file].push(newLine++);
        newLeft--;
      }else if(line[0]==='-'){
        if(!oldLeft)deny('DIFF_ANCHOR_HUNK_MISMATCH');
        oldLeft--;
      }else if(line[0]===' '){
        if(!oldLeft||!newLeft)deny('DIFF_ANCHOR_HUNK_MISMATCH');
        oldLeft--;newLeft--;newLine++;
      }else deny('DIFF_ANCHOR_HUNK_MISMATCH');
      continue;
    }
    if(inHunk)finishHunk();
    if(line.startsWith('--- ')){
      if(oldHeader||newHeader||hasHunk||
        !['--- a/'+file,'--- /dev/null'].includes(line))
        deny('DIFF_ANCHOR_FILE_INCOMPLETE');
      oldHeader=true;
    }else if(line.startsWith('+++ ')){
      if(!oldHeader||newHeader||hasHunk||
        !['+++ b/'+file,'+++ /dev/null'].includes(line))
        deny('DIFF_ANCHOR_FILE_INCOMPLETE');
      newHeader=true;
    }else if(line===''){
      // Only whitespace separator after complete source hunk or metadata.
    }else if(!oldHeader&&
      /^(?:index |new file mode |deleted file mode |old mode |new mode )/.test(line)){
      // Supported pre-hunk Git metadata.
    }else deny('DIFF_ANCHOR_FILE_INCOMPLETE');
  }
  finishFile();
  if(!Object.keys(entries).length||Object.keys(entries).length>100)
    deny('DIFF_ANCHOR_FILE_INCOMPLETE');
  for(const p of Object.keys(entries))entries[p]=Object.freeze(entries[p]);
  return Object.freeze(entries);
}
export function isAddedLine({anchors,path,line}={}){
  return !!(anchors&&Object.hasOwn(anchors,path)&&
    Number.isSafeInteger(line)&&anchors[path].includes(line));
}

/**
 * Reject a bounded diff hunk that deletes source but has no new-side added
 * line where reviewer findings v1 could be anchored. This DOES NOT classify
 * the deletion as unsafe: it proves only that the current reviewer cannot
 * safely assert complete semantic coverage of this fragment.
 *
 * Call on each individual inference shard (and again on model completion).
 * Do not borrow a line number from a different hunk or model shard.
 */
export function assertReviewableDeletionCoverage({diffBytes}={}){
  deriveAddedLinesFromDiff({diffBytes});
  const source=diffBytes.toString('utf8').replace(/\r\n/g,'\n');
  let inHunk=false,deleted=false,added=false;
  function finish(){
    if(inHunk&&deleted&&!added)deny('DIFF_DELETION_ONLY_UNANCHORED');
  }
  for(const line of source.split('\n')){
    if(line.startsWith('diff --git ')||line.startsWith('@@ ')){
      finish();
      inHunk=line.startsWith('@@ ');
      deleted=false;added=false;
    }else if(inHunk){
      if(line.startsWith('-'))deleted=true;
      else if(line.startsWith('+'))added=true;
    }
  }
  finish();
  return true;
}
