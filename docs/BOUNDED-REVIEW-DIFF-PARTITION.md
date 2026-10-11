# Bounded diff partitioner — preparation only

Source: \`candidate/review-diff-partition.mjs\`.

A real security review MUST cover all changed files on the same immutable
GitHub \`base_sha...head_sha\` comparison. The whole diff SHA-256 is a trust
input from that authenticated source, never an untrusted PR author field.

This pure, network-free candidate divides a text Git diff into complete
file-boundary chunks of at most 3,072 UTF-8 bytes by default. It enforces
SHA-256 identity, exact changed-path order, strict hunk parsing, whole-byte
reconstruction, per-chunk digests, duplicate exclusion, and redacted
serialization. Every file must fit in a single chunk; unsupported large
files, renames, binary diffs, malformed hunks and partial coverage BLOCK.
No silent truncation, skip, opportunistic filename selection or PASS is
permitted.

This is not a semantic reviewer, inference scheduler, provenance witness,
merge gate or a second authority. No local model is called. \`coverageComplete\`
means only that the original supplied bytes were reconstructed from shards,
**not** that the GitHub source was authenticated, all shards were independently
reviewed, the model interpreted the full context, or the release is safe.
A future protected pipeline must independently attest the full parent
HEAD/BASE, each part's digest, the content coverage and the ultimate report
before any signed result can be treated as genuine. Oversized single files
will require an audited hunk-level protocol rather than a silent fallback.

## Experimental line-level lossless slicing

The same module also provides partitionLosslessDiffLines for files that do
not fit into a single 3,072-byte model request. It segments only at complete
UTF-8 lines, tracks original file identities, byte offsets, line offsets
and SHA-256 fingerprints, validates the entire original diff structure, and
reconstructs every original byte exactly. An oversized single line remains
BLOCKED, never silently truncated.

**CRITICAL:** these are contiguous TEXT SPANS, not valid standalone Git diffs.
They may begin in the middle of a Git hunk and lack full code context.
byteCoverageComplete does NOT mean semanticReviewCoverageVerified.
No existing model inference, normalizer, signed reviewer attestation or
Publisher is allowed to treat them as reviewed. A separate audited context
and line mapping, complete signed coverage contract, and independent witness
are mandatory future work before any actual multi-span semantic review.
