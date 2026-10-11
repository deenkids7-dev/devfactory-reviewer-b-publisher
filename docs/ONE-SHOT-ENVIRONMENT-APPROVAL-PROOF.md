# One-time protected environment approval proof (NO SECRETS)

**Scope:** prove GitHub's existing two-account operational hold/release gate
on PUBLIC Publisher protected `main`, without asking the workflow's actor
to authenticate a second time for `workflow_dispatch`.

This narrowly scoped `push` job runs only after the source branch PR is
reviewed and normally merged by `devfactory-reviewer-service` into
protected `main`, and only when the exact frozen marker file changes.
It cannot run in feature PRs or from other repos/accounts. It has root
`permissions: {}`, no secrets, no checkout, no network, no API writes,
no model/provider call and no private source processing.

**Expected:** GitHub run enters `waiting` with pending deployment for
`reviewer-b-publish`. A separately authenticated existing environment
reviewer `deenkids7-dev` approves the specific run after checking its
run ID, actor, source SHA, job identity and branch. The run then completes,
prints only `NO_SECRETS_APPROVAL_GATE_RELEASED` and reports SUCCESS.
Evidence must include the actual approval actor and run ID. Reject
self-approval, bypass or unheld execution. If the run does not enter WAITING
then STOP and inspect environment policy before any production secret.

**This is a technical two-account operational gate, NOT human reviewer
independence**: both GitHub accounts are controlled by one operator.
No security review PASS, native Reviewer B, HUMAN_GO or privileged
publisher can be inferred from this no-secret proof. Do not silently
enlarge the approved actor set, workflow permissions or trigger path.

Once completed, leave the one-shot marker unchanged so later pushes do not
replay the proof. Existing `workflow_dispatch` probe stays available for
manual revalidation. App permission/secret provisioning remains
separate and requires the reviewed privileged workflow.
