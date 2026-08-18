# ADR-0002 — Go's `plugin` package is never used

**Status:** accepted · **Date:** 2026-08-18

## Context

The predecessor design listed "stable plugin ABI" as a v1.0.0 milestone, built
on Go's `plugin` package, with a hosted signed plugin registry.

Go's `plugin` requires the host and plugin to be built with the **identical Go
toolchain version and identical versions of every shared dependency**. It does
not work on Windows, is fragile on macOS, and forces dynamic linking — which
breaks `CGO_ENABLED=0` static binaries, the primary stated differentiator
against shell-based tools.

A "stable ABI" on this foundation is not achievable. Every Go patch release
breaks every plugin.

## Decision

Go's `plugin` package is never used. Extensibility arrives in v3 as, in order
of preference:

1. **Declarative check packs** — YAML over the existing fact model. Covers the
   majority of real checks with no third-party code execution.
2. **Subprocess protocol** — any executable, JSON over stdio, dropped
   privileges, no network, timeout and memory caps. No ABI, any language.
3. **WASM** (`wazero`, no CGO) if genuine sandboxing becomes necessary.

No hosted registry. A signed index file on GitHub Releases costs nothing to run
and has no uptime obligation.

## Consequences

- Extension authors cannot use Go types directly; they work against a
  documented data contract, which is the right boundary anyway
- Subprocess overhead per extension call — irrelevant at this scale
- The trust model must be stated plainly: an extension is code you chose to
  run. A signature identifies the publisher, not the behaviour. Signing is not
  sandboxing, and `PACK-AUTHORING.md` will say so in those words.
