# REAL free-model quality-gate outcome — 2026-10-10

Run: https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/actions/runs/38066397657

Both Ollama models ran on GitHub-hosted PUBLIC synthetic-only runners; neither
had access to DevFactory private source, API credentials, signing keys, or
native GitHub review permissions. Each model emitted all ten responses.
The updated CI correctly rejected both as **NOT PRODUCTION READY**.

| Strict public ten-case benchmark | Qwen 2.5 Coder 7B | Qwen 2.5 Coder 14B |
|---|---:|---:|
| Completed local inference responses | 10 | 10 |
| Known semantic defects correctly described / 4 | 2 | 2 |
| Clean changes with any false alert / 4 | 4 | 2 |
| Clean changes with blocking false alerts / 4 | 2 | 0 |
| Strict quality gate | FAIL | FAIL |
| Independent reviewer provenance | NOT PROVEN | NOT PROVEN |
| Production review or approval authorized | NO | NO |

These scores are based on the benchmark's deliberately narrow directional
oracle; they do not certify detection performance on real code. The 14B had
fewer safe-case false alerts in this run but still failed the hard gate.
Do not disable or relax the gate just to get a green CI. A green unit-test
suite only validates protocol handling, not model quality.

A separate opt-in Qwen3 8B synthetic candidate may run afterward, but is
not qualified without equally strict observed results. A true Reviewer B
deployment still requires independent security review, protected GitHub App
credentials with minimum authorized scopes, separately trusted provenance,
canonical HUMAN_GO, replay control and live PR HEAD checks. Never treat
this benchmark, signatures or test mocks as external independent approval.
