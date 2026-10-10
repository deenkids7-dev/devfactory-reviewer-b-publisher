# Independent Reviewer B — exact HEAD external account check

The proof of independence must be **real** and externally authenticated.
Source: candidate/independent-review-candidates.mjs is a pure, nonprivileged
candidate filter for GitHub review objects. It cannot authenticate them and
can NEVER set securityReviewVerified, actualHumanIndependenceVerified or
approvalAuthorized to true. Co-owned accounts deenkids7-dev and
devfactory-reviewer-service, GitHub bots, stale commits and comments are
not acceptable reviewers. Any external account must be explicitly verified
by the actual project security owner, with a review on CURRENT HEAD.

The public repository currently has no qualified independent reviewer
APPROVED review of PR #2 at its live commit. The existing CodeRabbit and
self-authored comments do not satisfy this gate. Do not merge or generate
privileged keys on their basis.

GitHub CodeQL is free for public repositories, but the attempted no-write
first-party CodeQL Action hit a GitHub startup_failure before creating a job
(run 38063996156). No scan or findings were produced. Activate CodeQL
DEFAULT SETUP in Repository Settings > Advanced Security and verify its
actual scan separately. Do not call the attempted run a PASS. The
experimental workflow is removed rather than weakening PR CI permissions.
