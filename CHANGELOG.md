# Changelog

All notable changes are recorded here. Format follows [Keep a Changelog];
versioning follows `docs/VERSIONING.md`, which governs four separate version
numbers (tool, catalog, schema, vulnerability data).

Every release that alters a check's verdict logic MUST carry a
`### Check corrections` section naming the check, the old behaviour, the new
behaviour, and who is affected. A user's posture score changing without an
explanation in this file is a defect.

## [Unreleased]

## [0.1.0] — 2026-08-18

**Pre-release. No stability guarantees.** The walking skeleton: one collector,
one check, and every architectural claim under test. Flag names, exit codes and
the findings schema are contracts from this point on; everything in Go stays
`internal/` and may change without notice (ADR-0007).

Catalog version 1 · schema `findings/v1` · bundle `bundle/v1`

### Added
- `System` interface with `live` (scan-root aware) and `fake` (fixture-backed)
  implementations — the single OS seam
- `fact` package: typed facts, `FactSet`, typed fact errors, generic `Get`
- `finding` package: five result states, severity weights, evidence,
  remediation, stable fingerprints
- `catalog` package: check registry, evaluation runner with required-fact
  gating and panic isolation
- sshd collector with `Include` resolution, `Match` scope tracking and
  first-value-wins precedence
- SSHD-0002 (root login over SSH disabled) — reference check, 9 fixtures
- `schema/findings-v1.schema.json` and `schema/bundle-v1.schema.json`
- `make verify`: formatting, vet, tests, and architectural invariant gates
- `tools/fixturegate`: mechanises the rule that every check carries PASS and
  FAIL fixtures, parsing check IDs and test tables with `go/ast` rather than
  regular expressions
- `bundle` package: zstd-compressed `.plb` archives per `DATA-MODEL.md` §6,
  with per-member sha256 verified before anything is parsed. An unregistered
  fact ID — or a known ID at an unknown `fact_version` — is preserved as opaque
  bytes, so an old binary opens a newer bundle instead of failing
- `collect` registry and runner: dependency DAG with cycles rejected at init,
  independent branches concurrent, `Expensive` collectors serialised to one at
  a time, per-collector budgets, and panic isolation. A collector that hangs,
  panics or lacks a privilege it declared produces a recorded fact error rather
  than a hung or silently incomplete scan
- `sanitize` package: C0, C1, DEL and invalid-UTF-8 bytes are made visible
  rather than deleted, and length caps are spent on output so a hostile 10 MB
  source costs no more than a benign one (`THREAT-MODEL.md` T-03)
- Content-addressed evidence: raw sources stored at `evidence/<sha256>.blob`,
  deduplicated by construction, cited by digest from `finding.Evidence.SHA256`
- `score` package: posture and coverage, read through accessors that cannot be
  used without acknowledging that either may be *undefined*
- `render/json`: `findings/v1`, deterministic and schema-validated in CI
- `cmd/plumbline`: `collect`, `eval`, `scan`, `version`, `--redact`, and the
  exit-code ladder as a single tested function
- Offline proof: a full scan in a network namespace with no interfaces
- Hostile-input corpus: FIFO, 40-deep symlink chain, symlink to `/etc/shadow`,
  100 MB file, ANSI filenames, cyclic include, directory-as-file, zero-byte
  config, CRLF
- CI: build for amd64 and arm64, `make verify`, race, schema validation,
  offline, hostile corpus, and a scan on ubuntu:24.04, debian:13,
  fedora:latest and alpine:3.20

### Changed
- `fact.SSHDConfig` carries `Digests`, mapping each file read to its sha256, so
  a finding can cite evidence an auditor can verify. `FactVersion` deliberately
  **not** bumped: the field is optional and no check is required to consider it
  (ADR-0009, `DATA-MODEL.md` §2.2)
- `summary.posture` and `summary.coverage` in `findings-v1` accept `null`.
  `null` means undefined, which is **not** zero: a consumer that coerces it
  reports a host in perfect failure when nobody looked at it (ADR-0010)
- `go.mod` requires Go 1.23

### Security
- Bundles and reports are written `0600`, with the mode applied after opening
  so that overwriting a world-readable file does not inherit its permissions
- `--redact` removes the hostname at collection time, so the identity is never
  written to disk
- Working-directory configuration is ignored when euid is 0 unless passed with
  `--config` (`THREAT-MODEL.md` T-07)
- Bundle reads are capped, integrity-checked before parsing, and never
  extracted to disk (`THREAT-MODEL.md` T-09)

### Dependencies
- `github.com/klauspost/compress` (zstd; pure Go, no cgo — ADR-0008)
- `github.com/spf13/cobra` (command surface)
- `github.com/santhosh-tekuri/jsonschema/v5` (tests only; never linked into the
  binary)

### Check corrections
None. SSHD-0002 is new in this release.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
