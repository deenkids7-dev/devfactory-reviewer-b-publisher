import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const workflows = [
  '.github/workflows/reviewer-b-smoke-test.yml',
  '.github/workflows/reviewer-b-attestation-tests.yml'
];
const oldName = 'devfactory-reviewer-service/devfactory-reviewer-b-publisher';
const canonicalName = 'devfactory-reviewer-trust/devfactory-reviewer-b-publisher';

test('both CI workflows enforce the exact transferred organization repository', () => {
  for (const relativePath of workflows) {
    const content = readFileSync(path.join(root, relativePath), 'utf8');
    assert.ok(content.includes(canonicalName),
      relativePath + ': canonical repository identity missing');
    assert.ok(!content.includes(oldName),
      relativePath + ': obsolete repository owner detected');
  }
});

test('smoke workflow checks live runner repository identity', () => {
  const content = readFileSync(path.join(root, workflows[0]), 'utf8');
  assert.match(content, /\$GITHUB_REPOSITORY/);
  assert.match(content, /github-hosted/);
});

test('attestation CI checks exact PR HEAD and refuses foreign-fork branch', () => {
  const content = readFileSync(path.join(root, workflows[1]), 'utf8');
  assert.match(content, /GH_HEAD_REPO/);
  assert.match(content, /GH_SHA/);
  assert.match(content, /test "\$GH_HEAD_REPO" = "\$GH_REPO"/);
});
