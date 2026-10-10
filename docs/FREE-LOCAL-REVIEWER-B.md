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

## Caller-supplied plan hardening

The local adapter rebuilds the semantic plan from the bound SHA-256 diff bytes
and refuses any caller-supplied system instruction changes or changed-path
lists that differ from the canonical parser. This closes a self-declared
prompt/scope spoofing path. It does not by itself authenticate GitHub API
origin or make the review independent: those remain separate trust gates.

## Quality calibration after first 7B review

The real synthetic Qwen 7B test found the seeded auth bypass, but falsely
claimed that an isolated read-only permission YAML hunk was malformed and
that defensive optional chaining weakened an admin-role comparison. The
read-only example is now a more realistic *write-to-read permission reduction*;
model instructions emphasize partial-diff limitations, reproducible paths and
actual guard semantics. Do not treat this small benchmark as a release gate.

## Shared public-runner 7B versus 14B quality comparison

The same public, no-secret GitHub Actions workflow now runs a bounded
matrix of Qwen 2.5 Coder 7B and 14B (four fixed synthetic examples each),
not a second production reviewer, scheduler or service. Each branch validates
its actual model ID, number of fixtures, and absence of publishing authority.
This measures only provisional error rates and never claims independent
reviewer provenance or production safety. A 14B model may exceed runner
resources or free execution limits; such an outcome is a failed experiment,
not permission to fall back silently or weaken controls.

## Exact diff-line evidence and efficient manual canary gate

Model findings are now rejected if their reported path and new-side line
number do not identify an actual added line in the separately trusted unified
diff. The validator also requires the exact SHA-256 diff digest and rejects
missing/mismatched source bytes, duplicate paths, malformed hunks and fake
source locations. This is evidence-location integrity, not an independent
semantic judgment or HUMAN_GO.

The free model benchmark is now deliberately opt-in with the
`reviewer-b-benchmark` PR label. This prevents every small hardening commit
from repeatedly downloading large models; an authorized repository writer
may label PR #2 when another synthetic quality run is needed. The job uses no
secrets or private source. Existing in-flight workflow runs are unaffected.

## Expanded quality dataset (ten synthetic scenarios)

The free benchmark now contains two deterministic high-risk workflow cases,
four deliberately introduced semantic defects (authorization bypass, removed
HTML escaping, weakened amount validation, inverted session-token rejection),
and four supposedly safe hardening cases (read-only permission reduction,
null-safe guard, nonnegative clamp, immutable configuration). Only FIXED,
synthetic text is sent to Ollama.

Semantic recall is counted conservatively only when the model's message or
evidence includes an oracle term associated with the seeded defect. The
benchmark separately records any false alert and *blocking* false alerts.
This dataset is still too small and synthetic to certify a production reviewer.
The default remains fail-closed and no-model-PASS.

## Directional oracle quality correction

Merely mentioning a relevant word (such as "amount" or "token") no longer
counts as having correctly identified a seeded bug. Synthetic evaluation now
requires a directional explanation: always-true authorization bypass, XSS from
removed escaping, negative amounts newly accepted, or valid-session tokens
rejected / invalid tokens accepted. The model's report remains untrusted data,
and this still is only a small heuristic benchmark, NOT independent model
quality certification. This corrects overly generous historical 7B recall
figures without rewriting or erasing past logs.

## Verified Qwen 7B vs 14B ten-case synthetic comparison (2026-10-10)

GitHub Actions reference: https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/actions/runs/38060206403

| Real public synthetic model result | Qwen 7B | Qwen 14B |
|---|---:|---:|
| Model completions generated | 10/10 | 10/10 |
| Seeded semantic bug cases with an alert | 4/4 | 4/4 |
| Safe cases with a false alert | 4/4 | 3/4 |
| Safe cases with HIGH/CRITICAL false alert | 3/4 | 0/4 |
| Approved for independent publishing | NO | NO |

These historic figures show finding presence, NOT four independently verified
correct diagnoses. The old permissive keyword oracle incorrectly credited
directionally wrong/inconclusive explanations on negative-amount validation.
The later stricter directional oracle corrects this in new runs, not old logs.

The historical Actions run concluded FAILURE due to a stale final assertion
expecting a four-case array despite producing a ten-case report. The assertion
was corrected at 1bd35d3bdf990164f1b25e5f50f030022e0da294. Do not
reinterpret the historical failure as a model inference failure, or the
produced model output as a production review PASS.

Qwen 14B is the better synthetic advisory candidate on severity, but it still
raises speculative concerns and cannot authorize merges or certify independent
analysis. Actual private PR review needs independently security-reviewed
protected execution, minimally scoped App permissions, trustworthy independent
provenance, replay protection, and canonical HUMAN_GO. See PREKEY-READINESS.md.
No private source, protected keys, paid API, production native review or
privileged merge was used during these synthetic experiments.

## Zero-CodeRabbit auto-review policy

The Publisher's existing `.coderabbit.yaml` previously had
`reviews.auto_review.enabled: true` and `drafts: true`, even though the
project has now switched to a free local Ollama review experiment. They have
been explicitly changed to `false`, and a test enforces those settings.
This is a repository policy to avoid requesting further external/possibly
billable automated reviews. It does NOT cancel a third-party CodeRabbit
subscription, change the service-side GitHub installation, or retroactively
erase old comments. Do not invoke CodeRabbit manually, on its CLI or via
`@coderabbitai` without a separately verified cost-free entitlement and
operator consent. Model-only advisory signals remain INCONCLUSIVE, not PASS.

## Fail-closed inference-context size cap

The generic diff plan can represent up to 128 KiB, but the local Ollama
candidate is configured with `num_ctx=8192`. Accepting such a large plan
would risk model-side silent truncation. The adapter now rejects a request if
the **entire serialized request**, measured conservatively in UTF-8 bytes,
plus the full requested generation limit and a 512-token framing reserve
exceeds 8,192. This is intentionally stricter than usual BPE tokenization.
No silent truncation, fallback, chunking or PASS is permitted.

This conservative admission check is not proof of actual model context
provenance; `modelContextCompletenessVerified` remains `false` until an
independently instrumented runner can verify the supplied input was used
intact. Large PRs will require an independently reviewed deterministic
chunking and coverage protocol before any production review.

## Free-model quality gate before production (2026-10-10)

Previous model benchmark jobs only checked that ten model responses existed,
NOT that they correctly described every seeded bug with zero safe-case alerts.
The opt-in synthetic CI now marks its model job FAIL if *any* of four seeded
semantic defects lack a directionally correct finding or *any* of four safe
changes elicits an alert. It also rejects invalid metric counts. This is
intentionally stringent: a red benchmark is better than declaring an unsafe
model ready. Even a fully green synthetic benchmark would not prove real-world
model accuracy, independently authenticated execution, or authorized review.
No private source enters this free CI; run only by explicit benchmark label.

## Token-count runtime bound

The post-inference response parser now defaults to the actual 8,192-token
configured context (not a permissive 200,000-token caller default) and a
2,048-token generation cap. It refuses completions for which
`prompt_eval_count + eval_count + 512 > 8192`, or either declared limit is
exceeded. This does not prove the underlying tokenizer saw every input
token; independent context-completeness provenance remains unverified.

## Updated independent free-model evidence — real ten-case run, 2026-10-10

[Public GitHub Actions run 38065898352](https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/actions/runs/38065898352)
executed 7B and 14B over ten fixed synthetic examples each. Both inference
jobs completed and their historical workflows reported SUCCESS **because that
commit checked execution integrity, not model quality**. The later strict
quality gate was introduced afterward; it was not part of that run.

| Synthetic benchmark metric | Qwen 7B | Qwen 14B |
|---|---:|---:|
| Real model completions | 10 | 10 |
| Four semantic defects recognized by contemporaneous strict oracle | 2 | 1 |
| Safe examples triggering any model concern (of four) | 4 | 2 |
| Safe examples triggering blocking model concerns (of four) | 3 | 0 |
| Approved for production security reviews | NO | NO |

The strict auth oracle undercounted a concrete 14B phrase,
"Authorization check bypassed"; a subsequent grammar-only correction adds
that accurate wording. Do not retroactively change this run's recorded metric
or claim more bug recall than what its log actually scored. By manual reading,
14B correctly identified at least the XSS removal and the auth bypass, but
still misread negative-amount direction, raised speculative safe-case concerns,
and did not provide the required session-token consequence. The next
synthetic quality gate requires **all four** seeded semantics and **zero**
safe alerts, and can legitimately FAIL. It never supplies independent
execution provenance or permission to post GitHub reviews.

Verdict: neither 7B nor 14B is production-ready as an independent automatic
Reviewer B. Both remain research/advisory candidates, without model API fees
and without exposure to PRIVATE DevFactory source.

## Third free model candidate: Qwen3 8B (evaluation only)

Added an opt-in **synthetic-only** `qwen3:8b` Ollama canary. Ollama's
`think:false` keeps the constrained JSON response format within the strict
8,192-token context, and the fixed ten-case quality gate rejects false alerts
and missed semantic bugs. This is **not** a claim that Qwen3 is more accurate
than Qwen 2.5 Coder or that it will pass. No private data, cloud model, paid
API, signing credentials or privileged publication are used. Qwen3 Coder 30B
quantized is about 19 GB and does not fit the standard 16-GB test runner; it
is not activated by this change.
