# ADR-0010 — Posture and coverage are nullable in the schema

**Status:** accepted · **Date:** 2026-08-18

## Context

WP-10 established that posture has an undefined state. It is undefined when
nothing was evaluated — an all-`SKIPPED` or all-`UNKNOWN` run — and also when
everything evaluated carries no weight, which an `INFO`-only run does. In Go
this is expressed by `Score.Posture()` returning `(float64, bool)`, so a caller
cannot read the number without acknowledging whether there is one.

`findings-v1.schema.json` could not express it. `summary.posture` was
`{"type": "number", "minimum": 0, "maximum": 100}` and appeared in `required`,
so the only document a renderer could legally emit for an unexamined host was
`"posture": 0`.

That is the audited scoring bug arriving through the back door. "Nobody looked"
and "everything failed" are different statements about a machine, and `0` says
the second. A CI gate reading that field would fail a build over a host it was
never allowed to examine, and an operator reading it would conclude their
machine is in perfect failure. The Go type would be careful and the wire format
would throw the care away, which is worse than not having it: the schema is the
public API (ADR-0007), so the wire format is what consumers actually see.

Options considered:

- **`["number", "null"]`** — the state is representable; consumers must handle
  null, which is the point
- **Omit `posture` when undefined** — the key's absence would mean undefined,
  but `additionalProperties` and `required` interplay makes "absent" easy to
  read as "the producer is old" rather than "the value does not exist"
- **A sentinel such as `-1`** — every consumer that forgets the sentinel gets a
  number outside the documented range and no error
- **A separate `posture_defined` boolean** — two fields that can disagree, and
  a consumer reading only the first still gets `0`

## Decision

**`summary.posture` becomes `["number", "null"]`.** `null` means undefined and
is documented in the schema itself as *not* zero, with the failure mode spelled
out for consumers who would otherwise coerce it.

**`summary.coverage` becomes `["number", "null"]` for the same reason.** This
was raised as a separate question and then answered by the corpus: the
`sshd-absent` fixture — a host with no sshd, whose only finding is
`NOT_APPLICABLE` — has no applicable checks, so its coverage is 0/0. It is a
shipped fixture, not a hypothetical, and WP-11 requires every fixture to render
to a valid document.

The alternative was for the renderer to refuse to emit a document at all in
that state. That was implemented first and rejected on the evidence: a scan of
a host that legitimately has nothing to check is a successful scan, and
producing no output for it would be a worse lie than producing a wrong number.
`0%` of an empty set is a division by zero, not a zero, so the only honest
answer the format can carry is `null`.

This is an additive change within `findings/v1`: a document that was valid
before is still valid, and only documents that could not previously be written
at all become expressible. It is not a major-version transition.

## Consequences

- Consumers must handle `null`. That is the intended cost: a consumer that
  cannot tell "unexamined" from "failed" was already wrong, it just could not
  find out
- `--threshold N` (CLI-SPEC.md) has to decide what an undefined posture does.
  It cannot be "below the threshold" and it cannot be "above" it; the run did
  not produce a posture, and the exit code has to say so
- Renderers must not coerce. The JSON renderer emits `null`; the terminal and
  SARIF renderers will each need the same care, and the rule is a rendering
  invariant like "never show posture without coverage"
- Both figures are now nullable, so a renderer must handle two independent
  undefined states. They are not independent in practice — an undefined
  coverage implies an undefined posture, because a host with no applicable
  checks has nothing to evaluate — and the renderer asserts that rather than
  assuming it
