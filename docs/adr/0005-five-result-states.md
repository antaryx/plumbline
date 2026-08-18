# ADR-0005 — Five result states, with UNKNOWN first-class

**Status:** accepted · **Date:** 2026-08-18

## Context

The predecessor design had four result states: PASS, FAIL, N/A, SKIP. There was
nowhere to put "I could not determine this."

So when a check hits a permission error, an unparseable file, a truncated read,
or a config whose value might live in an include that failed to resolve, the
likely implementations either crash the scan or return PASS. Returning PASS is
the worst outcome available: it tells an operator their system is fine when it
may not be, and unlike a crash there is no symptom that would prompt anyone to
look again.

The scoring formula compounded it — `Passed / All` counts SKIP as failure, so an
unprivileged run scored ~40 and punished the user for not being root.

## Decision

Five states: `PASS`, `FAIL`, `NOT_APPLICABLE`, `SKIPPED`, `UNKNOWN`.

`UNKNOWN` carries a machine-readable reason (`insufficient_privileges`,
`unparseable_source`, `source_truncated`, `fact_version_mismatch`,
`ambiguous_system_state`, `internal_error`, `fact_not_collected`).

Scoring: only `PASS` and `FAIL` score. `NOT_APPLICABLE` leaves the population
entirely. `SKIPPED` and `UNKNOWN` leave the denominator and reduce **coverage**,
which is displayed beside every posture score and may never be omitted by a
renderer.

Fact errors propagate to `UNKNOWN` automatically via the runner's required-fact
gate. Panics become `UNKNOWN(internal_error)`. A check never has to remember to
handle a missing fact, because it never sees one.

The set is **closed** in schema v1: a sixth state is a breaking change.

## Consequences

- Reports are noisier; unprivileged runs surface many UNKNOWNs
- Check authors must think about ignorance explicitly, which is more work and
  is exactly the work that matters
- Two numbers to explain instead of one — posture and coverage
- An unprivileged run reports `posture 82 (coverage 44%)`, which is true, rather
  than `40`, which is not
- False PASS becomes structurally difficult rather than merely discouraged
