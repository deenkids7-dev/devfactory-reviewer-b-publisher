# Reviewer B R62 — Adaptive QUICK / DEEP (owner-approved)

## Goal

Reduce elapsed review time on small, lower-risk **private functional PRs** without dropping semantic coverage, adding a remote inference provider, or creating another mandatory reviewer/merge gate. Runs remain a single protected, approved GitHub-hosted ephemeral Qwen 2.5 Coder 7B job using an authenticated immutable PRIVATE diff, in parallel with the private repo CI workflow.

## Routing (verified in protected local process, not PR text)

**QUICK** is eligible only when the authenticated diff is at most 12 KiB, contains at most 4 changed files, and none of the changed paths is in protected runtime, CI, auth, security, payment, migration, release, infrastructure or other sensitive families. The adapter attempts 3,072-byte bounded shards, then 2,304-byte shards. It chooses QUICK **only if** a candidate reduces actual shard count relative to DEEP *and* every fully built Ollama request is proven to fit the existing strict token/context budget before the first model call. It also proves complete byte/line coverage. The same 7B model, response schema, line-enum checking, finite per-shard deadline and immutable exact SHA provenance remain.

**DEEP** preserves the existing 1,536-byte chunks for sensitive PRs, large changes, incompatible context, or any case not proven to benefit. The entire PRIVATE diff is always analyzed, with no skippable fragments or silent partial verdict.

**Gemini supplemental advisory** is marked `SUGGESTED_NON_BLOCKING` on DEEP classified sensitive changes. This is only a recommendation for a supplemental review; it does **not** invoke Google, imply Gemini reviewed the PRIVATE repository, become an approval, impose a timeout, delay Qwen, or alter the branch's required CI. A future actual Gemini private-repo review would require authorized provider access and explicit security review. It is not a mandatory dependency.

## Non-negotiable restrictions

- Source stays private, no cloud model fallback, no paid Gemini/OpenAI API, no new GitHub account/runner/controller/merge service or second orchestrator.
- Protected `reviewer-b-publish` environment approval and service-owned issue #21 exact-HEAD request remain mandatory for PRIVILEGED inference.
- Native GitHub output is **COMMENTED only**, never APPROVED, independent signer PASS, HUMAN_GO or MERGE_GO.
- Exact source HEAD/BASE, changed paths, full bytes, GitHub App actor and exact CI remain independently verified before release by canonical DevFactory policy.
- No alteration to actual GitHub branch protections or bypass of Canonical ClaimBinding and risk gates.
- Parallel CI/Qwen reduce wall-clock time, but Gemini's optional audit may be pursued without blocking the release decision.

## Validation and measurement

Synthetic tests compare QUICK and DEEP shard counts with the same authenticated input, reconstruct all added lines, reject path drift, enforce context budget and prove sensitive paths stay DEEP. Protected publish tests require truthful mode labels and forbid a QUICK route with mandatory Gemini. GitHub CI must be green before protected merge. Re-measure real Qwen duration by job timestamps after qualifying benign PRs: **a reduction is expected, not yet empirically proven**.

This plan does not authorize an unsafe runtime restart or amend exceptional historical #895/#898 bootstrap requirements.