# CodeQL external static scan — blocked pending repository default setup

The public CodeQL scan is eligible for free GitHub-hosted code scanning, but
the attempted PR-level CodeQL workflow on commit
58d2bed6df531e9583b3c7a50a93c3988a7e27d4 produced
Actions run 38063996156 = **startup_failure**, zero jobs and zero SARIF.
This is NOT a completed scan or a security PASS.

The experimental workflow and its test were removed to restore green PR
checks without granting the public PR extra permissions. The next step,
requiring an administrator of the PUBLIC Publisher repository, is:

1. GitHub > repository Settings > Advanced Security.
2. Code Security > CodeQL analysis > Set up > Default.
3. Choose JavaScript/TypeScript and the security-extended query suite if
   available; enable scanning, and verify a CodeQL analysis on the exact
   current public Publisher PR HEAD.
4. Record the actual run result and address all high-priority alerts.

No scan on the PRIVATE DevFactory repo is authorized by this document.
CodeQL is a separate static security tool, not a qualified human auditor,
independent model provenance witness or GH REVIEW APPROVED.
Until a scan really runs, the CodeQL evidence state is BLOCKED.
