# ADR-0007 — The JSON schema is the public API

**Status:** accepted · **Date:** 2026-08-18

## Context

The predecessor design exposed `pkg/argus` as a public Go library API at
v1.0.0, alongside JSON output whose shape was never specified.

Both halves are wrong. Committing to a Go API at 1.0 means committing to a
shape you have not yet discovered, and it binds you to it under SemVer for the
life of the major version. Meanwhile the thing users *actually* integrate
against — the JSON that feeds their CI, dashboards and scripts — had no
contract at all, so it would drift release to release and break consumers
silently.

## Decision

**The JSON output is the public API.** Published as
`schema/findings-v1.schema.json`, validated in CI against every rendered
document, versioned as a major-only integer (`findings/v1`), with
additive-only changes within a major and a one-major deprecation window on
transition.

Everything in Go stays `internal/` for v1 and v2. A public `pkg/plumbline`
appears in v3, *after* three majors of learning what the shape should be.

The schema encodes the finding invariants structurally — UNKNOWN requires a
reason, FAIL requires remediation and evidence, non-FAIL must not carry
remediation — so a violation fails the build rather than reaching a user.

Fingerprint derivation is part of the contract: changing it silently
invalidates every user's suppression baseline and every SARIF result in
GitHub's security tab.

## Consequences

- Go consumers must shell out and parse JSON until v3, which is friction
- Schema changes need real thought, which is the intended effect
- The compatibility burden lands on a format designed for it rather than on Go
  types that will be refactored
- Freedom to restructure internals arbitrarily without breaking anyone
