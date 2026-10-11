# Reviewer B permanent zero-subscription track (2026-10-10)

**Status: PREPARED, NOT DEPLOYED. This is NOT an APPROVED review.**

## Verified physical limit

The actual DevFactory MSI was inspected using read-only Desktop Commander
hardware queries: Intel Core Ultra 7 155H, **15.7 GiB RAM installed**,
**~2.6 GiB RAM free** at inspection; Ollama and Semgrep commands were not
found in the Windows PowerShell PATH. Do **not** install or run a 30B model
on this live MSI. Do **not** restart Supervisor, WSL or Runner to fit it.

The free local Ollama model **qwen3-coder:30b** is ~19GB model weights
(Q4_K_M), excluding OS, context/KV cache and other applications.
The permanent reviewer needs **another Linux host** with **32GB RAM at
minimum** and preferably 64GB, >=40GB free storage, and adequate cooling.
At 32GB the context budget and CPU throughput must be measured; running
without a capable GPU can be very slow. This is NOT a monthly subscription
but hardware, electricity and maintenance can cost money.

Official model: https://ollama.com/library/qwen3-coder/tags

## Existing software reused; no second platform

- Immutable GitHub diff/HEAD binding: existing Reviewer B readers.
- Deterministic fail-only rules: candidate/fail-only-static-audit.mjs.
- Local Semgrep CE scan rules: rules/reviewer-b-semgrep-ce.yml.
- Bound, zero-network Semgrep JSON checker:
  candidate/semgrep-ce-offline-contract.mjs.
- Pure local Ollama request/response contract:
  candidate/ollama-offline-contract.mjs.
- Existing canonical finding aggregation, review signing and publication
  prototype. Draft private DevFactory PR #900 includes a pure external
  Ed25519 witness verifier; it is NOT a live, independent approval.
- Existing HUMAN_GO and DevFactory merge executor remain the sole
  operator/merge authorities. No new scheduler, retry manager, State
  Ledger, auditing authority or model router.

## The new Semgrep CE stage

Semgrep Community Edition is open-source and allows a local-only scan
with no login and no paid Semgrep Cloud service.

On a separately authorized, secured Linux review worker, install a
stable, audited Semgrep CE binary into a dedicated Python virtualenv.
Record/pin the exact package version and hash before processing private
code. Store the local ruleset from the reviewed exact code SHA, and
verify its sha256 separately.

Run an **example** scan with environment/network off for telemetry:

    SEMGREP_SEND_METRICS=off semgrep scan --json --metrics=off \
      --disable-version-check \
      --config rules/reviewer-b-semgrep-ce.yml \
      --output /restricted/reviewer-b/semgrep-private.json \
      src/

The real target list MUST come from the independently authenticated
changed paths, not from an arbitrary PR comment or shell-interpolated
user data. Local Semgrep CE JSON may include private source snippets,
therefore keep it under protected storage; no public Actions logs,
artifacts, issue comments, or stdout report dumps. Use no cloud rules
registry and no semgrep login.

Next, a trusted worker, using the authenticated exact BASE/HEAD diff,
must call validateOfflineSemgrepCEFindings() with the full local
scanner JSON bytes, exact rules SHA, process exit code and diff SHA.
It rejects parser errors, foreign files, invalid rules, incorrect
new-line scopes, ignored findings, duplicate findings and bad exit codes.
Old-line matches are counted separately and do not justify approving
or blocking a newly added line. An empty static report remains
INCONCLUSIVE. The validator alone CANNOT prove scan execution or
independence.

The initial local rule pack covers direct eval() and new Function()
calls in JS/TypeScript. It is *deliberately narrow* to limit false
positives, not a comprehensive security certification. The existing
static workflow and other rules are unchanged.

Semgrep CE documentation:
https://semgrep.dev/products/community-edition/
https://github.com/semgrep/semgrep

## The model stage: 30B free, manual-only until proven

Install Ollama locally on the **separate** Linux reviewer and record a
verified upstream binary/model digest. Bind it to loopback only. Explicit
local-only examples (the actual protected worker needs separate
operational hardening):

    export OLLAMA_HOST=127.0.0.1:11434
    export OLLAMA_NO_CLOUD=1
    ollama pull qwen3-coder:30b
    ollama serve

In a separate shell on that host, from the vetted Publisher repository:

    node bench/ollama-synthetic-benchmark.mjs --coder-30b-synthetic

This uses the EXISTING ten synthetic/public examples, with the same
strict oracle: 4/4 known semantic bugs correctly described, 0/4 clean
false warnings and 0/4 clean blocking false warnings. Neither
benchmark passes nor any individual model output is a native GitHub
APPROVED review. Qwen3-Coder 30B has NOT been benchmarked live here,
since MSI has only 16GB and public GitHub Actions standard runners do
not have the necessary memory. Never add 30B to the public matrix.

The previously measured Qwen3 8B counterfactual-prompt run reached
4/4 bug recall but also warned on all four safe examples, so it
FAILS the strict gate. Do not relax thresholds or suppress true
findings to obtain green CI.

## Independence and exact necessary operator steps

1. Obtain the **second host** and configure an isolated dedicated
   Linux reviewer account; the primary DevFactory MSI must NOT have
   access to its signing keys. Physical host separation alone is
   insufficient: a separately accountable security operator must
   attest ownership and controls.
2. Authorize an external security audit of PUBLIC Publisher draft PR #2
   on its **final exact head**. Fix any open findings and repeat checks.
   Only an authentically separate reviewer may issue actual APPROVED.
3. Run the full Semgrep CE + 30B synthetic quality trials on that
   second host. Do not allow private DevFactory diffs until quality
   gate, security audit and canonical HUMAN_GO authorize disclosure.
4. Independently pin external reviewer Ed25519 public SPKI and native
   RSA public SPKI under reviewed protected trust configuration.
   DO NOT paste GitHub App keys/PATs/PEMs into chat, public PRs,
   logs or the MSI. A signature alone never proves independent work.
5. Independently approve only the minimum required GitHub App
   repo-scoped permission changes and test protected environment
   hold/release **without secrets first**. No untrusted workflow
   gets the private diff or GitHub write token.
6. Prove an authentic full PR review on an exact HEAD, signed
   independent provenance, authoritative native GitHub identity,
   persistent nonce/replay protection and canonical HUMAN_GO before
   enabling any automated merge. Keep Publisher PR #2, DevFactory
   #898/#899/#900 and other drafts unmerged pending these gates.

The software has no API-token charges or monthly licensing costs.
A hosted GitHub offering may change its terms: the trusted local
inference/review process must not depend on recurring hosted minutes.

## Honest release gate

READY FOR SYNTHETIC OFFLINE TESTS: yes (unit/CI tests must pass).
LIVE INDEPENDENT REVIEW: NO.
PRODUCTION APP KEY / PRIVATE INFERENCE: NOT AUTHORIZED.
NATIVE APPROVED AND AUTOMATIC MERGES: NO.
