import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const y=()=>readFileSync(new URL('../.github/workflows/reviewer-b-codeql-audit.yml',import.meta.url),'utf8');
test('GitHub CodeQL static scan is pinned, read-only, public-only and fail-closed',()=>{
 const c=y();
 assert.match(c,/permissions:\s*\n\s*contents:\s*read/);
 assert.doesNotMatch(c,/security-events:\s*write|secrets\./);
 assert.doesNotMatch(c,/(?:pull_request_target|workflow_run|workflow_call)\s*:/);
 assert.match(c,/upload: never/);
 assert.match(c,/upload-database: 'false'/);
 assert.match(c,/actions\/checkout@[a-f0-9]{40}/);
 assert.match(c,/github\/codeql-action\/init@[a-f0-9]{40}/);
 assert.match(c,/github\/codeql-action\/analyze@[a-f0-9]{40}/);
 assert.match(c,/persist-credentials: false/);
 assert.match(c,/github\.event\.pull_request\.head\.sha/);
 assert.match(c,/CODEQL_SARIF_ABSENT/);
 assert.match(c,/CODEQL_SECURITY_FINDINGS_REMAIN/);
});
test('CodeQL scan cannot claim an independent GitHub review or PR approval',()=>{
 const c=y();
 assert.match(c,/approvalAuthorized:false,publishEvent:null/);
 assert.doesNotMatch(c,/APPROVED|REQUEST_CHANGES|POST\s+\/reviews/);
 assert.doesNotMatch(c,/deenkids7-dev\/deenkids/);
});
