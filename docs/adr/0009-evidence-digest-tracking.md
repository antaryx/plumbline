# ADR-0009 — Facts carry the digest of every file they were parsed from

**Status:** accepted · **Date:** 2026-08-18

## Context

WP-09 gives findings content-addressed evidence: the raw source lives in the
bundle at `evidence/<sha256>.blob`, and `finding.Evidence.SHA256` points at it,
so an auditor disputing an excerpt can re-read the bytes the verdict was
actually derived from.

The store worked; the last link did not. A check is a pure function from facts
to findings — it never touches the OS — so the only digest a check can cite is
one a fact already carries. `fact.SSHDConfig` recorded `Files []string`: which
files were read, but not what was in them. SSHD-0002 could therefore say
"/etc/ssh/sshd_config line 3" and could not say which bytes that was.

Leaving `SHA256` empty was the honest short-term answer, and it makes the
evidence store decorative: blobs are written that nothing references.

Options considered:

- **Digest map on the fact** — `Digests map[string]string`, path to sha256
- **Restructure `Files` into `[]struct{Path, SHA256 string}`** — tidier, but a
  breaking change to a field every SSHD check and fixture already reads, for no
  gain in expressiveness
- **Have the check ask the evidence store** — impossible without giving checks
  a handle on collection state, which is the split ADR-0001 exists to protect
- **Recompute the digest at render time** — requires re-reading the host, which
  is exactly what a bundle exists to avoid, and would silently produce a
  different answer if the file changed after the scan

## Decision

**Add `Digests map[string]string` to `fact.SSHDConfig`**, keyed by the same
absolute path that appears in `Files` and in every `Directive.File`, valued
with the sha256 the seam already computed in `system.ReadResult`.

`FactVersion` is **not** bumped. Per DATA-MODEL.md §2.2 this is an optional
field: no check is required to consider it, and a check reading a bundle
written before this change sees an absent map and emits evidence without a
digest — which is exactly what it did yesterday, and which the findings schema
already permits (`sha256` is optional there). Bumping would force
`UNKNOWN(fact_version_mismatch)` on every historical bundle to signal a change
that cannot make a verdict wrong.

The pattern generalises: any fact parsed from files carries the digests of
those files. It is not sshd-specific, and later collectors should copy it
rather than inventing a second convention.

## Consequences

- Findings cite evidence that can be verified against the bundle, which is the
  difference between an audit and a screenshot
- The fact is slightly larger — one map entry per file read, tens of bytes
- Facts now record something no check is required to read. That is deliberate,
  but it means "is this field used?" is no longer a question the compiler can
  answer for facts
- A digest for a file that was read but produced no directives is still
  recorded. That is correct: the auditor's question is "what did you read",
  not "what did you find useful"
- `docs/DATA-MODEL.md` §2.3 is updated in the same change. A fact shape the
  normative document does not describe is a fact shape nobody can review
