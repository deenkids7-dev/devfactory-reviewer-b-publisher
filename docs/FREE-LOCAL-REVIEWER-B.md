# Free Reviewer B — local open-source model path

Status: CANDIDATE ONLY. No actual independent review or external witness yet.

## Upstream inspiration
The-PR-Agent/pr-agent (MIT): https://github.com/The-PR-Agent/pr-agent
Its diff-scoped AI review and structured findings design inform this adapter.
No PR-Agent source code has been copied. Qodo's hosted subscription is NOT
the free PR-Agent codebase.

## Free inference option
Use Ollama with a local Qwen 2.5 Coder 7B/14B model in a future independently
controlled trust domain. This avoids paid model API calls and CodeRabbit quota.
Compute, downloads, electricity and operating costs can still apply.
Public GitHub Actions standard runner minutes are free, but public CI must
NEVER load the private DevFactory diff, keys, reports, or privileged credentials.

## Reuse, do not duplicate
- Existing authenticated immutable GitHub diff reader and fail-only audit.
- Existing bounded semantic plan and canonical findings normalizer.
- New pure Ollama adapter: candidate/ollama-offline-contract.mjs.
- Existing Ed25519 attestation, RSA marker, native review readback and canonical
  HUMAN_GO; no new scheduler, router, approval authority or Publisher service.
- Tests use ONLY synthetic data. No network invocation and no secrets.

## Critical unfinished gates
1. Review exact Publisher PR HEAD independently and approve any trust changes.
2. Use a separate trusted analyzer (running a model on the main DevFactory MSI
   is NOT sufficient independence).
3. Independently authorize any processing of PRIVATE source on that worker.
4. Verify protected environment hold/release, GitHub App Contents:Read and
   Issues:Read, minimal installation tokens and independent provenance.
5. Benchmark genuine model quality on synthetic known-bug PRs.
6. Only AFTER audited keys, real witness, nonce/idempotence and HUMAN_GO,
   allow the Publisher to post one authentic native GitHub review.

This code cannot grant PASS, APPROVED, HUMAN_GO, publish, spend, or merge.

## Manual, zero-secret synthetic benchmark

On an isolated testing computer where Ollama is already installed, first
run `ollama pull qwen2.5-coder:7b`; then run `npm run benchmark:local-synthetic`
from this repository. This invokes ONLY two hardcoded synthetic diffs over
`http://127.0.0.1:11434/api/chat`. No private GitHub code, token, file,
secret or network model provider is loaded. The sample must NOT be used to
claim independent review or model quality certification. Verify the Ollama
server is bound to loopback, not a public interface.

The candidate now requests a fixed `num_ctx: 8192` and a restrictive JSON
schema, but **tokenization and absence of input truncation are not yet
independently proved**. Never interpret a zero-findings response as PASS.

## No-secret GitHub-hosted public canary

A dedicated experimental workflow on PR #2 can run the SMALL 1.5B model in
a free standard public GitHub-hosted Ubuntu runner. It uses the same benchmark
code on SYNTHETIC source only. This is NOT a security approval, is NOT connected
to the private DevFactory repository, does not post PR reviews, and must never
receive any credential or private PR diff. Ollama binary is pinned to an
upstream GitHub release artifact SHA-256. A 1.5B model is NOT a suitable basis
for automatic security approvals. GH-hosted runner resource availability,
model registry uptime and execution success still need live verification.

## Quality benchmark upgrade

The first real 1.5B hosted run produced a false alarm on the normal workflow.
The expanded benchmark now includes a seeded missing-authorization bug and
a safe null-check change. The public GitHub Actions canary tests 7B and
reports detection plus false-alarm counts, while explicitly keeping
modelQualityCertified=false. A complete, valid summary is mandatory for CI;
no empty/silent process can make this job PASS. No private source is used.

## Model finding schema improvement

The first Qwen 7B smoke run rejected invalid model-produced findings, as
required by fail-closed policy. The next adapter revision binds Ollama's
structured-output schema to the *exact changed paths* and requests specific
added-line evidence. Invalid responses remain BLOCKED; outputs are not silently
filtered or promoted into authorization.

## Fail-closed model diagnostics

Model output defects are classified without showing findings or source in
public Actions logs: changed-path mismatch, non-positive line, unsupported
severity, malformed/multiline evidence or duplicate finding. Such errors
remain blocked, never silently fixed or converted to a model PASS.

## Safe findings normalization

A genuine Qwen 7B run exposed multiline/formatting in model findings. The
adapter now deterministically flattens CR/LF/tab/space runs in summary,
message and evidence before computing canonical hashes, but does NOT discard
findings or silently alter file paths or line numbers. Control characters
(other than permitted whitespace), empty or oversized fields and duplicate
findings still fail closed. Model quality is NOT certified by this fix.

## Explain synthetic false alerts without exposing private source

The benchmark may print a short, bounded explanation for model findings on
the FOUR HARDCODED synthetic public-safe examples only. This output must not
be reused for private diff reviews or in a privileged workflow. Metrics now
show whether all seeded semantic bugs were detected and no clean fixtures
were flagged; even if this small synthetic target becomes true, it does NOT
establish production review quality, provenance, HUMAN_GO or approval.
