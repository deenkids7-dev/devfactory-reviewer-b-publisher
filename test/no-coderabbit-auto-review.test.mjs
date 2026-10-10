import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('Publisher repo never requests automatic or draft CodeRabbit reviews',()=>{
  const source=readFileSync(new URL('../.coderabbit.yaml',import.meta.url),'utf8');
  assert.match(source,/^\s*auto_review:\s*\n\s*enabled:\s*false\s*$/m);
  assert.match(source,/^\s*drafts:\s*false\s*$/m);
  assert.match(source,/^\s*auto_incremental_review:\s*false\s*$/m);
  assert.doesNotMatch(source,/^\s*enabled:\s*true\s*$/m);
});
test('free synthetic benchmark never includes a CodeRabbit hosted review job',()=>{
  const path=new URL('../.github/workflows/reviewer-b-ollama-synthetic-canary.yml',import.meta.url);
  const workflow=readFileSync(path,'utf8');
  assert.match(workflow,/127\.0\.0\.1:11434/);
  assert.doesNotMatch(workflow,/coderabbit\.ai|coderabbit review|DEEPSEEK_API_KEY|OPENAI_API_KEY/);
  assert.match(workflow,/^\s*permissions:\s*\n\s*contents:\s*read\s*$/m);
});
