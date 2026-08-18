# ADR-0001 — Split collection from evaluation

**Status:** accepted · **Date:** 2026-08-18

## Context

The design this project replaces ran checks directly against the live machine:
`Run(ctx) ([]Finding, error)`, with modules executing in parallel goroutines.
Two consequences, both fatal at scale:

1. **Duplicated collection.** Twelve of the proposed checks required a full
   filesystem traversal. Run in parallel, that is twelve concurrent `find /`
   equivalents competing for one disk. On a server with a large `/var` it does
   not finish, and parallelism makes it worse because the work is IO-bound.
2. **Untestable checks.** Testing "does this check flag `arcfour` in `Ciphers`"
   required a machine configured that way. With ~110 checks and four outcomes
   each, that is hundreds of system states. Nobody builds them, so checks ship
   unverified — and an unverified security check reports confident wrong
   answers with no external symptom.

## Decision

Collection and evaluation are separate phases with a serialisable artifact
between them.

**Collectors** touch the OS and produce typed **facts**. **Checks** are pure
functions from facts to findings: no IO, no clock, no network, enforced by the
type signature and by `make check-check-purity`.

## Consequences

**Good:**
- One filesystem walk, shared by every consumer via interest predicates
- Checks are unit-testable against fixture trees; the corpus is cheap to grow
- Bundles are portable: collect on a locked-down host, evaluate anywhere
- Old bundles can be re-evaluated against a newer catalog, offline
- Two bundles diff, which makes "what changed since March" a real feature
- Fixtures and golden bundles are the same artifact as production output

**Costs:**
- Facts must be designed before checks, and a missing field means a collector
  change rather than a one-line check edit
- Memory holds the full fact set during evaluation
- Fact versioning is now a compatibility surface of its own
- A check cannot ask an ad-hoc question about the system; if it is not in the
  bundle it does not exist

The last cost is the one that will bite, and it is accepted deliberately: it is
the same constraint that makes everything else possible.
