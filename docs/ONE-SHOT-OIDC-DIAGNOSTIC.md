# Protected PUBLIC OIDC permission diagnostic

This test strictly checks whether GitHub can START a job requesting
`id-token: write` and `attestations: write` under the existing
`reviewer-b-publish` environment. It is a one-time, marker-filtered,
protected-main, service-actor push workflow with NO third-party action,
NO checkout, NO network request, NO GitHub App key and NO private source.

If the job enters WAITING, the GitHub scheduler accepted the permission
scopes; release from the existing `deenkids7-dev` environment approver
and check job result. If this succeeds, the prior keyless synthetic
`startup_failure` is specific to a different workflow element such as
the pinned external action or the workflow's contract, not a general
OIDC scope restriction. Investigate action allowlist next.

If it fails with zero jobs and `startup_failure`, investigate
repository/organization Actions token permission policy and account
feature eligibility. Do not falsely record a signed attestation.
If it starts but fails a step, investigate the missing OIDC variables
and GitHub-hosted runner permissions.

Do not put private code, secrets, source excerpts, or actual tokens in
logs. This test never requests a GitHub OIDC token, never generates
or verifies attestation, and never grants Reviewer B PASS/HUMAN_GO.
It must not be re-triggered by editing the marker.
