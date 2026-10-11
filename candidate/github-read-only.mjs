import { observePrSnapshot } from '../src/github-pr-observer.mjs';

// Read-only adapter. Intentionally not wired to CI or any production workflow.
// The caller must supply an independent GitHub App INSTALLATION token from a
// separately reviewed, secret-bearing trusted job. NEVER log token or response.
// The GitHub API is the only network destination; no redirects are followed.
const OWNER = 'deenkids7-dev';
const REPO = 'deenkids';
const PATH_PREFIX = `https://api.github.com/repos/${OWNER}/${REPO}/pulls/`;
const COMPARE_PREFIX = `https://api.github.com/repos/${OWNER}/${REPO}/compare/`;
const API = 'https://api.github.com';
const COMPARE_PATH=/^[a-f0-9]{40}\.\.\.[a-f0-9]{40}$/;
const ACCEPT = new Set(['application/vnd.github+json', 'application/vnd.github.diff']);
const JSON_CONTENT = /^application\/(?:vnd\.github\+)?json(?:\s*;|$)/i;
const DIFF_CONTENT = /^(?:text\/plain|application\/vnd\.github(?:\.v3)?\.diff)(?:\s*;|$)/i;

function deny(code) { throw new Error(code); }
function validPr(value) {
  return Number.isSafeInteger(value) && value > 0 && value <= 2147483647;
}
function assertFixedTarget(url,accept) {
  if(typeof url!=='string')deny('GITHUB_ENDPOINT_DENIED');
  if(accept==='application/vnd.github+json' &&
     url.startsWith(PATH_PREFIX) &&
     /^\d+$/.test(url.slice(PATH_PREFIX.length)) &&
     validPr(Number(url.slice(PATH_PREFIX.length))))return;
  if(accept==='application/vnd.github.diff' &&
     url.startsWith(COMPARE_PREFIX) &&
     COMPARE_PATH.test(url.slice(COMPARE_PREFIX.length)))return;
  deny('GITHUB_ENDPOINT_DENIED');
}
function cleanToken(value) {
  // Do not expose the token in error messages, logs or returned values.
  if (typeof value !== 'string' || value.length < 15 || value.length > 2000 ||
      /[^A-Za-z0-9_\-.]/.test(value)) deny('INVALID_INSTALLATION_TOKEN');
}
async function consumeBounded(response, maxBytes) {
  if (!response?.body?.getReader) deny('GITHUB_BODY_NOT_STREAM');
  const chunks=[];
  let total=0;
  const reader=response.body.getReader();
  let completed=false;
  try {
    for (;;) {
      const {done,value}=await reader.read();
      if (done) { completed=true; break; }
      if (!(value instanceof Uint8Array)) deny('GITHUB_RESPONSE_CHUNK_INVALID');
      total+=value.length;
      if (total>maxBytes) deny('GITHUB_RESPONSE_OVERSIZED');
      chunks.push(Buffer.from(value));
    }
  } finally {
    // Aborted reads must not leave an HTTP stream consuming resources.
    if(!completed){try{await reader.cancel();}catch{/* Keep original denial. */}}
    reader.releaseLock();
  }
  return Buffer.concat(chunks,total);
}

/**
 * A concrete API reader, NOT independent-review provenance or authorization.
 *
 * Only GET /pulls/:pr metadata and immutable /compare/:base...:head DIFF are permitted. The token
 * must belong to a separate trusted GitHub App installation. Calls requiring
 * payment, PR writes, arbitrary URLs or reading other repos are impossible.
 * An injected fetchImpl is for TESTS ONLY. Production MUST use global fetch.
 */
export function createReadOnlyGitHubTransport({
  installationToken, fetchImpl=fetch
}={}) {
  cleanToken(installationToken);
  if (typeof fetchImpl !== 'function') deny('GITHUB_TRANSPORT_MISSING');
  return async function request({url,method,accept,maxBytes}) {
    assertFixedTarget(url,accept);
    if (method !== 'GET' || !ACCEPT.has(accept) ||
        !Number.isSafeInteger(maxBytes) || maxBytes < 1 ||
        maxBytes > 2*1024*1024) deny('GITHUB_READ_CONTRACT_VIOLATION');
    let response;
    try {
      response=await fetchImpl(url,{
        method:'GET', redirect:'error', cache:'no-store',
        headers:{
          Authorization:`Bearer ${installationToken}`,
          Accept:accept,
          'X-GitHub-Api-Version':'2022-11-28',
          'User-Agent':'devfactory-independent-reviewer-b-readonly'
        },
        signal:AbortSignal.timeout(15000)
      });
    } catch { deny('GITHUB_READ_FAILED'); }
    if (response?.status !== 200 || response?.redirected ||
        response?.url !== url || new URL(response.url).origin !== API) {
      deny('GITHUB_NONCANONICAL_RESPONSE');
    }
    const contentType=response.headers?.get('content-type')||'';
    if (!(accept === 'application/vnd.github+json' ?
          JSON_CONTENT.test(contentType) : DIFF_CONTENT.test(contentType))) {
      deny('GITHUB_UNEXPECTED_MEDIA_TYPE');
    }
    const length=response.headers?.get('content-length');
    if (length !== null && length !== undefined && length !== '' &&
        (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
      deny('GITHUB_RESPONSE_OVERSIZED');
    }
    let body;
    try { body=await consumeBounded(response,maxBytes); }
    catch { deny('GITHUB_RESPONSE_OVERSIZED_OR_INTERRUPTED'); }
    return Object.freeze({
      url, expectedUrl:url, status:200, redirected:false,
      accept, contentType, body
    });
  };
}

export async function readCurrentGitHubPrSnapshot({
  prNumber, installationToken, fetchImpl=fetch
}={}) {
  if (!validPr(prNumber)) deny('INVALID_PR_SELECTOR');
  const request=createReadOnlyGitHubTransport({installationToken,fetchImpl});
  return observePrSnapshot({prNumber,request});
}
