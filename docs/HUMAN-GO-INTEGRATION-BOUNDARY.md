# Canonical HUMAN_GO integration boundary (DESIGN ONLY)

The Publisher MUST NOT invent a parallel authorization ledger, issue marker,
approval command, or HUMAN_GO decision. The source of truth remains GitHub
Issues in private `deenkids7-dev/deenkids` and the DevFactory canonical
authority implemented by `devfactory/lib/human-go-batch*.mjs`.

The current GitHub App `DevFactory Reviewer B` is installed on ONLY the
private `deenkids7-dev/deenkids` repository, historically with Metadata Read
and Pull requests Read/Write. **Contents: Read is additionally required for
the immutable compare endpoint**; do not assume this permission is granted.
Its App ID is 5253138 (from owner UI) and its historical
installation ID is 169674558 (reverify). The Publisher cannot presently
assume independent access to Issue metadata and contracts.

GitHub REST `GET /repos/{owner}/{repo}/issues` requires Issues:read.
Some issue-comment GET endpoints document alternative Issues:read or Pull
requests:read permissions, but reading comments alone cannot establish a
complete authoritative Issue/LOT contract, its current eligibility, latest
labels, or a nonstale batch approval fingerprint. **Do not treat comment
visibility as HUMAN_GO proof.**

## Design choices

1. PREFERRED, pending independent security review: extend the EXISTING
   Reviewer B GitHub App installation to **Issues: Read-only**, never Issues
   Write. Keep installation scoped to the sole private `deenkids` repo.
   GitHub installation permission changes require explicit operator action.
2. Use separate short-lived downscoped installation tokens for each
   privilege purpose: immutable private PR diff (`Contents:read` +
   `Pull requests:read`); Issue/LOT metadata (`Issues:read` with only
   the minimum accompanying access); native review publication
   (`Pull requests:write`, WITHOUT Contents access). NEVER reuse a
   publication token as the analysis token. Enforce exact repository ID
   1282086207 and zero cross-repository access.
3. Fetch current Issues, labels, LOT text, canonical approval markers and
   exact GitHub actor with GitHub API—not via source text supplied by a PR.
4. Reuse canonical parsing, contract hashing and issue-lifecycle checks from
   the current DevFactory code at the exact reviewed `master` version.
   No local alternative HUMAN_GO format or additional audit State Ledger.
5. Check that a legitimate HUMAN_GO covers the **specific protected action**
   (external review publication) on a named PR/HEAD. Ordinary general
   conversation authorizations and successful CI are NOT substitutes.
6. Re-fetch the canonical authority and current HEAD immediately before
   any privileged publication. Any missing permission, invalid source, stale
   fingerprint, changed Issue contract, unapproved scope, absent witness
   or ambiguous actor => BLOCKED.
7. All changes need independent code security review; the Publisher's
   separate account is an operator boundary, not a certified independent
   semantic reviewer.

## Constraints

- Do NOT grant Issues:write or Contents:write to the Reviewer B App.
- Do NOT read private Issues through the MSI's existing OAuth credentials
  as a shortcut.
- Do NOT mint a new independent gate, controller, scheduler, model router
  or approval authority in this Publisher.
- Do NOT request the private GitHub App key until the protected workflow and
  zero-secret environment hold/release have been independently validated.
- Any private Issue contents, reports and diffs must remain outside PUBLIC
  Actions output and repository artifacts.

## Current state

**BLOCKED BY DESIGN**: No Issues-reading integration, live HUMAN_GO
verification, provider selection or privileged Publisher is operational.
All candidate checks are synthetic and fail closed. No paid provider,
new GitHub App permissions, secrets or merges have been activated.

Official GitHub permissions reference:
https://docs.github.com/en/rest/issues/issues
https://docs.github.com/en/rest/issues/comments
