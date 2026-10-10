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
