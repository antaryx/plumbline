# ADR-0018 — SARIF mapping

**Status:** accepted
**Date:** 2026-08-20
**Supersedes:** nothing. **Superseded by:** nothing.
**Related:** ADR-0007 (findings/v1 is the API), `docs/VERSIONING.md` §4.4,
`docs/CLI-SPEC.md` §Output.

## Context

`--format sarif` emits SARIF 2.1.0 so that GitHub Advanced Security, and
anything else that ingests SARIF, can consume a Plumbline scan.

SARIF is a *findings interchange* format built for static analysis of source
code. Plumbline audits a running host. The two models disagree in three places,
and each disagreement has a wrong answer that is easy to reach:

1. **SARIF has no "I could not tell".** Its levels are `error`, `warning`,
   `note` and `none`. Plumbline's `UNKNOWN` — the state this whole project
   exists to keep honest — has nowhere obvious to go.
2. **SARIF results are things to act on.** A run carrying 74 passing checks is
   noise, and noise in a security tab trains people to close the tab.
3. **SARIF locations are file regions.** Many Plumbline findings are about a
   sysctl, an account or the host as a whole, and have no file to point at.

A mapping that resolves these badly does not merely look wrong; it reports a
different host than the one that was scanned.

## Decision

### Result levels

| Plumbline | SARIF | Why |
|---|---|---|
| `FAIL`, severity `CRITICAL` or `HIGH` | `error` | Acted on today |
| `FAIL`, severity `MEDIUM`, `LOW`, `INFO` | `warning` | Real, not urgent |
| `UNKNOWN` | `warning` | See below |
| `SKIPPED` **with** a suppression | emitted, with a `suppressions` array | See below |
| `SKIPPED` **without** one | omitted from `results` | Nothing was examined |
| `PASS` | omitted from `results` | See below |
| `NOT_APPLICABLE` | omitted from `results` | The subject is not here |

### `UNKNOWN` maps to `warning`, not to `none`

This is the load-bearing decision of the whole mapping.

`none` files an `UNKNOWN` as informational, and `error` claims a failure that
was never observed. The first is the failure mode this project refuses
everywhere else — it makes a host look cleaner than the scan found it — and the
second invents a verdict.

`warning` is chosen because **the consequence of an `UNKNOWN` is the same as
the consequence of a finding: somebody has to look.** It is not a claim that
the check failed, and the result carries what it needs to say so:

- `message.text` opens with `Could not determine:` and names the reason code.
- `properties["plumbline/result"]` is the literal string `UNKNOWN`.
- `properties["plumbline/unknown_reason"]` is the reason code.

A consumer that models Plumbline can branch on the properties bag. One that
does not still sees something it must handle, which is the correct default.

### Suppressed findings use SARIF's `suppressions`, not a level

SARIF models suppression as a first-class concept: a result carries a
`suppressions` array, each entry with a `kind` and a `justification`. This is
the one place the two models line up exactly, and using it means an accepted
risk appears in GitHub as *dismissed with a reason* rather than as absent.

- `kind` is `"external"` — the decision lives in a file outside the tool.
- `justification` is the operator's text, verbatim.
- The result keeps the `level` its **original** verdict would have had, because
  a suppressed finding is still a finding; only its standing has changed.
- `properties["plumbline/original_result"]` records that verdict.

Mapping a suppression to a level instead would throw away the one part of the
suppression design that SARIF already understands.

### `PASS` and `NOT_APPLICABLE` are not results

They are tallied in `runs[].invocations[0].properties`:

```json
"properties": {
  "plumbline/counts": {"pass": 74, "fail": 3, "unknown": 0,
                       "not_applicable": 0, "skipped": 2, "total": 79},
  "plumbline/posture": 96.6,
  "plumbline/coverage": 97.5,
  "plumbline/catalog_version": 13
}
```

**Coverage is emitted wherever posture is**, which is the same invariant the
other two renderers enforce: a posture with no scale beside it flatters an
unexamined host.

A reader who wants the passing checks reads the counts; a reader who wants
findings reads `results`. Emitting 74 passing checks as `level: "none"` results
would bury three real ones and is the reason security tabs get ignored.

### Locations

Every result carries exactly one location.

- When `subject` looks like an absolute path, `artifactLocation.uri` is that
  path with a `file://` scheme, and `region` is omitted — Plumbline knows the
  file, not the line, and a fabricated `"startLine": 1` is a claim about
  evidence that does not exist.
- Otherwise — a sysctl key, an account, the host as a whole — the location is
  the scan root (`/` for a live host), and the subject is carried in
  `properties["plumbline/subject"]`.

SARIF requires *a* location for a result to be actionable in most consumers;
inventing a plausible-looking one is worse than pointing at the host.

### `partialFingerprints`

```json
"partialFingerprints": {"plumblineFingerprint/v1": "<finding.Fingerprint>"}
```

The key is versioned so that a future change of derivation can be introduced
alongside the old one rather than silently redefining it.

**This raises the stakes on fingerprint stability, and the raise is the point
of writing it down.** `docs/VERSIONING.md` §4.4 already makes the derivation a
schema-level guarantee. Before SARIF, breaking it cost users a rewritten
suppression file — annoying, visible, recoverable in an afternoon. After SARIF
it *also* costs them their GitHub security-tab history: every alert re-appears
as new, every dismissal is lost, and every "fixed" transition is fabricated on
a day nothing about the host changed.

There is no migration for this. GitHub deduplicates on the fingerprint we give
it, and it has no way to learn that two fingerprints mean one finding.
Therefore:

- Changing `finding.Fingerprint`'s derivation is a **findings/v2** change and a
  major tool release, never a patch.
- If it ever changes, the new key is `plumblineFingerprint/v2` and **both are
  emitted** for at least one full major, so consumers can bridge.
- `Fingerprint` deliberately excludes result, severity and detail. A finding
  that flips `FAIL` → `PASS` → `FAIL` is one finding with one history. That
  property is now load-bearing in two systems rather than one.

### Rules

One `reportingDescriptor` per check that produced at least one emitted result,
in `tool.driver.rules`, referenced by `ruleIndex`. Each carries:

- `id` — the check ID. Permanent, and the same string a suppression file uses.
- `shortDescription` — the check title.
- `fullDescription` and `help` — the detail and remediation summary.
- `defaultConfiguration.level` — from the check's base severity.
- `properties["security-severity"]` — a numeric string, because **this is what
  GitHub ranks by**; without it every alert is "medium" in the UI.
- `properties["tags"]` — `["security", "plumbline", "<module>"]`.

## Consequences

- A SARIF consumer sees failures and unknowns, never passes. That is a smaller
  document than the findings one, and deliberately so.
- An accepted risk round-trips as a dismissal rather than as silence.
- `finding.Fingerprint` is now load-bearing for an external system's history.
  It was already frozen; it is now expensive to unfreeze, and this ADR is the
  record of why.
- SARIF is **not** validated against a vendored copy of its schema in CI. The
  schema is a 500 KB external document that would have to be kept in sync by
  hand, and a stale copy is a gate that passes for the wrong reason. The
  exporter is tested structurally against the mappings above instead, which is
  what this ADR actually specifies. Validating against the upstream schema is a
  reasonable addition the day CI is allowed a network call for it.

## Alternatives considered

**`UNKNOWN` → `none`.** Rejected: it is exactly "report a cleaner host than you
saw", which rule 3 of `CONTRIBUTING.md` exists to prevent.

**`UNKNOWN` → `error`.** Rejected: it claims a verdict the scan did not reach,
and it would make an unprivileged scan look catastrophic rather than partial.

**Emit `PASS` as `level: "none"`.** Rejected: 74 informational results per host
per run, burying the three that matter.

**Use a SARIF library.** Rejected under rule 7 of `CONTRIBUTING.md` — this binary runs
as root and every import is supply-chain surface. The subset of SARIF needed
here is about 120 lines of structs.
