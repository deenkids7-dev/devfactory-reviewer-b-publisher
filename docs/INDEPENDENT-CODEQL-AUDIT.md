# Supplemental independent public CodeQL security scan

Workflow: .github/workflows/reviewer-b-codeql-audit.yml. Runs GitHub's own CodeQL
security-extended JavaScript engine on the PUBLIC Publisher HEAD only. It
rejects forks, checks exact source SHA, uses pinned first-party actions and
Contents:Read only, with no secrets or SARIF upload. Missing, invalid or
nonempty security findings cause FAIL. Only PUBLIC rule/file/line indicators
are emitted. The engine provides independent STATIC SECURITY ANALYSIS, not an
independent human/semantic Reviewer B, not an authenticated reviewer
execution witness, and never a native GitHub APPROVED review or HUMAN_GO.
A passing CodeQL job is supplemental evidence only; the PR still needs an
external current-HEAD security review before authorized deployment.
