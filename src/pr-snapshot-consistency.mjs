import { createHash } from 'node:crypto';

const REPO = 'deenkids7-dev/deenkids';
const REPO_ID = 1282086207;
const SHA40 = /^[0-9a-f]{40}$/;
const MAX_DIFF_BYTES = 2 * 1024 * 1024;
const MAX_CHANGED_FILES = 100;

function deny(code) { throw new Error(code); }
function isObject(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }

const SAFE_PATH=/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;

/**
 * GitHub text diff must have one complete and parseable header and at least
 * one hunk for EACH changed file. Unrecognized rename, binary, whitespace-
 * quoted paths or hunkless files are deliberately BLOCKED, not accepted.
 */
function checkDiffCoverage(text, expectedCount) {
  let file=null, count=0;
  const seen=new Set();
  function finish() {
    if(!file) return;
    if(!file.oldHeader || !file.newHeader || !file.hunkSeen)
      deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
  }
  for(const line of text.split('\n')) {
    if(line.startsWith('diff --git ')) {
      finish();
      const m=line.match(/^diff --git a\/(\S+) b\/(\S+)$/);
      if(!m || m[1]!==m[2] || !SAFE_PATH.test(m[1]) || seen.has(m[1]))
        deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
      seen.add(m[1]); count++;
      file={path:m[1],oldHeader:false,newHeader:false,hunkSeen:false};
      continue;
    }
    if(!file) {
      if(line.trim()!=='') deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
      continue;
    }
    if(!file.hunkSeen && line.startsWith('--- ')) {
      if(file.oldHeader || (line!=='--- a/'+file.path && line!=='--- /dev/null'))
        deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
      file.oldHeader=true;
      continue;
    }
    if(!file.hunkSeen && line.startsWith('+++ ')) {
      if(!file.oldHeader || file.newHeader ||
         (line!=='+++ b/'+file.path && line!=='+++ /dev/null'))
        deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
      file.newHeader=true;
      continue;
    }
    if(line.startsWith('@@ ')) {
      if(!file.oldHeader || !file.newHeader ||
         !/^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@/.test(line))
        deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
      file.hunkSeen=true;
      continue;
    }
  }
  finish();
  if(count!==expectedCount) deny('GITHUB_DIFF_COVERAGE_UNVERIFIED');
}

function extractMetadata(document, requestedPr) {
  if (!isObject(document) || !isObject(document.head) ||
      !isObject(document.base) || !isObject(document.base.repo)) {
    deny('INVALID_GITHUB_PR_METADATA');
  }
  if (!Number.isSafeInteger(requestedPr) || requestedPr < 1 ||
      document.number !== requestedPr || document.state !== 'open' ||
      document.merged_at !== null || document.draft !== false ||
      document.base.ref !== 'master' ||
      document.base.repo.full_name !== REPO ||
      document.base.repo.id !== REPO_ID ||
      !SHA40.test(document.head.sha) || !SHA40.test(document.base.sha) ||
      !Number.isSafeInteger(document.changed_files) ||
      document.changed_files < 1 || document.changed_files > MAX_CHANGED_FILES) {
    deny('GITHUB_PR_NOT_ELIGIBLE');
  }
  return {
    repository: REPO, repository_id: REPO_ID, pr_number: requestedPr,
    head_sha: document.head.sha, base_sha: document.base.sha,
    changed_files: document.changed_files
  };
}

/**
 * ONLY verifies the internal consistency of input bytes and JSON metadata.
 * The caller MUST obtain all three inputs from the authenticated GitHub API
 * over an independently trusted transport. DO NOT accept PR-author-provided
 * JSON/diff or self-declared status as an authoritative snapshot.
 *
 * No network requests, credentials, permissions, GitHub writes, or approvals.
 * Small text-only PRs by design: unsupported cases are BLOCKED, never PASS.
 */
export function deriveConsistentPrSnapshot({
  requestedPr, metadataBefore, metadataAfter, rawDiff
}) {
  const before = extractMetadata(metadataBefore, requestedPr);
  const after = extractMetadata(metadataAfter, requestedPr);
  for (const key of ['repository','repository_id','pr_number',
    'head_sha','base_sha','changed_files']) {
    if (before[key] !== after[key]) deny('GITHUB_PR_CHANGED_DURING_READ');
  }
  if (!Buffer.isBuffer(rawDiff) ||
      rawDiff.length < 16 || rawDiff.length > MAX_DIFF_BYTES) {
    deny('GITHUB_DIFF_BYTES_UNSUPPORTED');
  }
  const text = rawDiff.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(rawDiff) ||
      /^(?:GIT binary patch|Binary files )/m.test(text)) {
    deny('GITHUB_DIFF_ENCODING_OR_BINARY_UNSUPPORTED');
  }
  checkDiffCoverage(text, before.changed_files);
  return Object.freeze({
    repository:before.repository, repository_id:before.repository_id,
    pr_number:before.pr_number, head_sha:before.head_sha,
    base_sha:before.base_sha,
    diff_sha256:createHash('sha256').update(rawDiff).digest('hex')
  });
}
