# ADR-0008 — zstd for bundle compression

**Status:** accepted · **Date:** 2026-08-18

## Context

WP-07 makes the bundle real: a portable, archival artifact holding every fact
a scan collected, plus the evidence it was derived from. It has to be
compressed. Facts are JSON — highly repetitive keys, paths and directive names
— and evidence blobs are configuration text, which is the best case for any
dictionary coder. An uncompressed bundle of a real host is large enough that
people would stop keeping them, and a bundle nobody keeps defeats the point of
having one.

This is the project's **first external dependency**. Everything to date is
standard library, and that is not an accident: this binary runs as root, so
every import is supply-chain surface (CLAUDE.md rule 7). The bar for adding one
is therefore "the standard library cannot do this and the cost of doing it
ourselves is worse than the cost of the dependency".

The standard library offers `compress/gzip` and `compress/flate`. Neither is
close to zstd on either ratio or speed for this shape of data, and writing a
zstd implementation is not a reasonable use of this project's time.

Candidates considered:

- `github.com/klauspost/compress/zstd` — pure Go, no cgo, widely deployed,
  actively maintained, permissive licence
- `github.com/valyala/gozstd` and other cgo bindings to libzstd — faster, but
  cgo means a C toolchain in the build, dynamic linking against a system
  library, and losing `CGO_ENABLED=0` static binaries
- `compress/gzip` — no new dependency, materially worse ratio

## Decision

**Use `github.com/klauspost/compress` for zstd, and add nothing else.**

Pure Go is the deciding property, not the compression ratio. `CGO_ENABLED=0`
is what makes the release a single static binary that runs on any Linux
userland, which is what an auditing tool has to be: an operator drops it onto a
host they do not control and runs it. A cgo dependency would trade that for
speed nobody asked for.

The dependency is pinned to the newest release compatible with the `go`
directive in `go.mod`, not to `latest`. A compression library is not a reason
to move the whole project's minimum Go version, and the CI matrix pins a Go
version deliberately.

Read and write both go through `internal/bundle`. No other package imports
zstd, so replacing it later touches one file.

## Consequences

- The supply-chain surface is no longer zero, and `docs/SUPPLY-CHAIN.md` now
  has something real to say. Dependency review is part of release from here on
- Bundles are not readable with `tar -x` alone; `plumbline` or `zstd -d` is
  required. Acceptable: the bundle already needs a reader for integrity
  verification, and a bundle whose members are trivially editable is worse
- Upgrading the dependency is now a decision with a blast radius, because a
  decoder bug is reachable from `plumbline eval <bundle-from-anywhere>`
  (THREAT-MODEL.md T-09). Decompression is capped and integrity-checked for
  exactly this reason
- If zstd ever becomes unmaintained, the escape is one package and a format
  version, not a rewrite
