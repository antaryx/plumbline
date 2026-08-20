# CLI SPEC — Plumbline

**Status:** normative for v1.x. Flag names and exit codes are a contract
(`VERSIONING.md` §5); do not add, rename or repurpose without a decision.
**Implements:** WP-12.

---

## 1. Command tree (v1.0)

```
plumbline
├── scan        collect + evaluate + render, in one pass
├── collect     collect facts into a bundle and stop        (privileged step)
├── eval        evaluate a bundle into findings             (unprivileged, offline)
├── diff        compare two bundles or two findings documents
├── report      re-render an existing findings document
├── check       catalog introspection: list, show, explain
├── doctor      self-diagnostic and capability report
├── version     tool, catalog and schema versions
└── completion  bash | zsh | fish | powershell
```

`scan` is `collect | eval` fused. That the two are genuinely separable is the
architecture, not a convenience: the privileged step and the analysis step are
different trust domains.

---

## 2. `plumbline scan`

```
plumbline scan [flags]
```

### Target

| Flag | Default | Meaning |
|---|---|---|
| `--root PATH` | `/` | Scan root. Use for mounted images and for host scanning from a container. All paths are interpreted beneath it. |
| `--profile NAME` | `default` | Built-in: `default`, `server`, `workstation`, `minimal` |

### Selection

| Flag | Meaning |
|---|---|
| `--module LIST` | Comma-separated module IDs to include |
| `--skip-module LIST` | Module IDs to exclude |
| `--check LIST` | Specific check IDs to run |
| `--tag LIST` | Only checks carrying any of these tags |

Resolution order: start from the profile's module set → apply `--module` as an
intersection → apply `--skip-module` as a subtraction → apply `--check` as an
override that replaces everything. Anything excluded is reported `SKIPPED`, not
silently omitted: a check that vanished and a check that passed must never look
the same.

### Output

| Flag | Default | Meaning | Implemented |
|---|---|---|---|
| `--format NAME` | `terminal` | `terminal`, `json`, `sarif` | **yes** |
| `--json` | false | Shorthand for `--format json` | **yes** (v0.3) |
| `--output PATH` | — | Output file; only valid with a single format | **yes** |
| `--no-color` | false | Also honours `NO_COLOR` and non-TTY stdout | **yes** (v0.3) |
| `--output-dir DIR` | — | Directory; required when multiple formats | no |
| `--quiet` | false | Findings only, no progress | no |
| `--verbose` | false | Per-check execution detail | no |
| `--debug` | false | Engine internals to stderr | no |

`--format` takes a single name today, not a comma-separated list. Multiple
formats in one run need `--output-dir`, and neither exists yet; the flag is
specified as `LIST` for the release that adds them, and until then a second
format is a second invocation.

**`--json` is shorthand over the default, not an override.** `--json` alone
selects JSON. `--format json --json` is accepted, because it is not a
contradiction. `--format terminal --json` is a **usage error**: the operator
stated a format explicitly, and silently discarding it would be the same class
of defect as silently accepting a misspelled `--fail-on` level.

#### Colour

Three rules, in order of how explicit they are. The first that applies wins.

1. `--no-color` — never colour.
2. `NO_COLOR` present in the environment, **at any value including `0`** — never
   colour. The [no-color.org](https://no-color.org) convention is that the
   variable existing at all is the request.
3. Otherwise, colour only when the destination is a character device.

Writing to `--output` is never coloured, whatever the rules above say. An
escape sequence in a file the operator asked to keep is not a rendering choice;
it is corruption of an artefact they will read later in something that is not a
terminal.

#### Terminal layout

The terminal report is in two phases.

The **scan phase** is one line per check, grouped under a `[+] MODULE` heading:
the check's title on the left, and a bracketed verdict flush against the right
edge of a fixed 78-column grid.

| Result | Token | Colour |
|---|---|---|
| `PASS` | `[ OK ]` | green |
| `FAIL` | `[ WARNING ]` | red |
| `UNKNOWN` | `[ UNKNOWN ]` | yellow |
| `NOT_APPLICABLE` | `[ SKIPPED ]` | dim |
| `SKIPPED` | `[ DISABLED ]` | dim |

`NOT_APPLICABLE` and `SKIPPED` do not share a token. The first means the
subject is not on this host; the second means it may well be and the check was
deliberately not run. Collapsing them would report a declined check where in
truth there was nothing to check.

The scan phase carries **no** detail, evidence or remediation. All of it is in
the **suggestion phase** at the bottom, under `[=] Warnings and suggestions`,
where each finding gets a starred headline carrying its check ID and labelled
value lines beneath. `FAIL` and `UNKNOWN` appear there under separate headings
and at equal weight — moving the detail to the bottom is a change of layout and
must never become a change of emphasis.

**The grid is 78 columns and does not follow the terminal.** A report has to be
byte-identical across two runs of an unchanged host, or a scheduled scan
produces a diff every night and people stop reading it. Only check titles are
ever truncated to fit; a check ID, a path or an evidence excerpt is a value an
operator copies, and one silently shortened to make a column line up is worse
than a ragged column.

#### `--format sarif`

SARIF 2.1.0, for GitHub Advanced Security and anything else that ingests it.
The mapping is specified in `docs/adr/0018-sarif-mapping.md`; the parts an
operator needs to know:

| Plumbline | SARIF |
|---|---|
| `FAIL`, `CRITICAL`/`HIGH` | result, `level: error` |
| `FAIL`, `MEDIUM`/`LOW`/`INFO` | result, `level: warning` |
| `UNKNOWN` | result, `level: warning`, message opens `Could not determine (reason):` |
| `SKIPPED` **with** a suppression | result with a `suppressions` array, `kind: external` |
| `SKIPPED` without one | not a result |
| `PASS`, `NOT_APPLICABLE` | not results; counted in `invocations[0].properties` |

**`UNKNOWN` is a `warning`, never `none`.** `none` files it as informational,
which reports a cleaner host than the scan found. The consequence of an
`UNKNOWN` is a finding's consequence — somebody has to look — and
`properties["plumbline/result"]` carries the literal state for a consumer that
models it.

**SARIF is a lossy projection and is not the API.** It carries what a consumer
acts on; `findings/v1` carries everything observed. A pipeline that needs the
passing checks reads `--json`.

`partialFingerprints["plumblineFingerprint/v1"]` is `finding.Fingerprint` — the
same string a suppression file matches on, so GitHub's dismissals and the
suppression baseline stay aligned.

#### What may be parsed

**`--format json` is the API. `--format terminal` is not.** The terminal
report's layout may change in a patch release and nothing may depend on it;
`findings/v1` is versioned, schema-validated in CI, and changes only under the
rules in `VERSIONING.md`. A pipeline that greps the terminal report is a
pipeline that will break, and it will break silently.

### Suppressions

| Flag | Default | Meaning |
|---|---|---|
| `--suppress PATH` | — | Apply accepted-risk suppressions from a `suppressions/v1` file |

A team that has reviewed a finding and accepted it must be able to say so, or
the second scan reports the same thing as the first and people stop reading it.
**A suppression never removes a finding.** It changes the result to `SKIPPED`
and attaches the justification, and the report gives accepted risks their own
`[=] Accepted risks` section stating what each one would otherwise have said.

The path is an **operator-named path**, like `--output` and the bundle. `--root`
is never prefixed onto it (ADR-0011): `--root /mnt/image --suppress
./accepted.json` reads the operator's file from the working directory, not from
inside the filesystem under audit.

#### File format

```json
{
  "schema": "suppressions/v1",
  "suppressions": [
    {
      "fingerprint": "f18675a62f48a1e849159a7516d827a2",
      "justification": "Deploy account owns cron by design; reviewed by platform-sec, SEC-4471.",
      "expires_at": "2027-01-31T00:00:00Z",
      "check_id": "CRON-0001",
      "subject": "/etc/crontab"
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `schema` | yes | Must be `suppressions/v1` |
| `fingerprint` | yes | 32 lowercase hex characters, copied from a findings document |
| `justification` | yes | Why the risk was accepted. **May not be blank.** |
| `expires_at` | no | RFC 3339. The rule stops applying at this instant |
| `check_id`, `subject` | no | Advisory labels, so a human can read the file |

Five rules govern the format, and each one exists because the obvious
implementation gets it wrong.

1. **A blank justification is a parse error, not a warning.** An unaccountable
   suppression is a hidden finding with extra steps, and a format that tolerates
   a blank reason becomes the format everyone uses. A warning on stderr in CI is
   a warning nobody reads.
2. **Unknown fields are a parse error.** `"justifcation"` silently parsing as an
   absent justification is precisely the failure this feature must not have.
3. **`check_id` and `subject` are verified, never trusted.** If present, they
   must fingerprint to the value recorded beside them. A label that can drift
   from what it describes is worse than no label.
4. **A `PASS` is never suppressed**, and a rule matching one is reported as
   unmatched — which is how an operator learns the acceptance is no longer
   needed.
5. **Expiry is measured against the scan's start time, not the wall clock.**
   The same bundle, catalog and suppression file give the same findings today
   and in three years, which is what makes a bundle evidence rather than a
   snapshot of an opinion.

Rules that did not fire are reported on **stderr**, never in the findings
document — a lapsed or stale rule is a fact about the operator's file, not about
the host:

```
plumbline: suppression 00112233… expired 2026-06-30T00:00:00Z; the finding is reported
plumbline: suppression 44556677… matched no failing finding; it may already be fixed, or the subject may have changed
```

A `--suppress` file that is missing, unreadable or invalid is a **hard error**
(exit 20, `ExitInternal`). Continuing without it would print a report full of
findings the operator had already accepted, which reads exactly like the
suppressions having applied and nothing having been accepted.

#### Effect on scoring

An accepted risk is `SKIPPED`, which means it **leaves the posture denominator
entirely** — a team is not scored down for having reviewed something — and
**reduces coverage**, because a suppressed check genuinely did not produce a
verdict about the host. That is the existing documented meaning of `SKIPPED`
(`ARCHITECTURE.md` §5) and suppression does not special-case it.

### Filtering

| Flag | Default | Meaning |
|---|---|---|
| `--severity LEVEL` | `info` | Show findings at or above this level |
| `--only-failures` | false | Display `FAIL` only. Does not affect scoring or exit codes. |
| `--suppressions PATH` | — | Suppression file; suppressed findings become `SKIPPED(suppressed)` and are listed in the summary |

Filtering is a **display** concern. It never changes posture, coverage or the
exit code. A pipeline that greps its way to a green build is a pipeline that
has stopped working.

### Gating

| Flag | Default | Meaning |
|---|---|---|
| `--fail-on LEVEL` | `none` | Exit 2 if any `FAIL` at or above this level |
| `--threshold N` | — | Exit 3 if posture < N |
| `--min-coverage N` | — | Exit 4 if coverage < N |
| `--strict-privileges` | false | Exit 10 if the profile needs privileges we lack |

`--min-coverage` is the one people omit and then regret: without it, a scan
that could read nothing exits 0 and the pipeline is green while auditing
nothing.

### Collection

| Flag | Default | Meaning |
|---|---|---|
| `--redact` | false | Remove hostname and non-loopback addresses at collection time. **Not an anonymiser** — see below |
| `--save-bundle PATH` | — | Keep the bundle `scan` produced |
| `--timeout DURATION` | `30m` | Whole-scan budget |
| `--concurrency N` | auto | Cap on concurrent collectors |

### What `--redact` does and does not cover

`--redact` removes the hostname and non-loopback addresses. It does **not**
anonymise the bundle.

A bundle always contains the host's account list, because every USERS finding
names the account it is about and a report that will not say which account is
not actionable. Account names also feed the finding fingerprint, so changing
them would invalidate every suppression an operator has written.

A bundle never contains password hashes, whether or not `--redact` is passed.
The contents of `/etc/shadow`, `/etc/gshadow` and `/etc/security/opasswd` are
read, classified and discarded; only the properties a check judges — empty,
locked, which crypt scheme — reach the bundle. This is not configurable.

Treat a bundle as sensitive in all cases. It is written `0600`, and `--redact`
makes it less identifying, not safe to publish. See
`docs/adr/0015-account-data-in-bundles.md`.

### Misc

| Flag | Meaning |
|---|---|
| `--config PATH` | Explicit config file |
| `--explain-exit-codes` | Print the exit-code table (`--json` for machine form) and exit 0 |

---

## 3. `collect` and `eval`

```
plumbline collect [--root PATH] -o BUNDLE [--redact] [--profile NAME] [--timeout D]
plumbline eval BUNDLE [--format ...] [--suppressions PATH] [--fail-on ...] [--threshold N]
```

`collect` accepts no filtering flags beyond `--profile`. Collection is cheap
relative to its value, and a bundle collected with checks in mind is a bundle
that cannot answer tomorrow's question. Collect broadly, evaluate narrowly.

`eval` accepts no `--root`: the bundle already holds everything. It must work
with no network and no privileges, and CI asserts both.

---

## 4. `diff`

```
plumbline diff OLD NEW [--suppress FILE] [--no-color] [-o PATH]
```

Compares two **bundles** and reports only what moved.

Both arguments are evidence bundles (`plumbline scan --save-bundle host.plb`
or `plumbline collect -o host.plb`), **not** findings documents. A findings
document written with `--json` holds verdicts that have already been drawn; a
bundle holds the facts they were drawn from, which is what lets `diff` judge
both sides with one catalog. Handing a findings document to `eval` or `diff` is
rejected by content — the file's first bytes, never its extension — with an
error naming what it is and how to produce the right file. Unchanged findings are
never printed: a diff that lists everything is a report.

**Both sides are re-evaluated with today's catalog.** A bundle stores facts, not
verdicts, so `diff` runs the current catalog over each one. A check whose logic
was corrected between the two collections therefore cannot appear as the host
having changed, because the same code judged both. This is also why there is no
`--allow-catalog-drift` flag and no cross-catalog annotation: there is no drift
to allow. (An earlier draft of this spec described such a flag, and described
diffing two rendered findings documents. Both were dropped for this reason —
comparing two documents means comparing verdicts from two possibly-different
catalogs, which is precisely the confusion re-evaluation removes.)

Findings are matched by **fingerprint**, which is stable across verdict changes
by design. A suppressed finding is compared by `suppression.original_result` —
the verdict the check actually reached — so accepting a risk diffs as an
acceptance rather than as a fix.

### Categories

Reported in this order, most urgent first, each rendered separately and never
merged:

| Category | Meaning | Colour |
|---|---|---|
| `NEW FAILURE` | Was not failing, now `FAIL` or `UNKNOWN` | red |
| `REGRESSED` | Was an accepted risk; the rule expired or was removed | yellow |
| `VERDICT CHANGED` | Failing before and now, but `FAIL` ↔ `UNKNOWN` | dim |
| `NEWLY SUPPRESSED` | Was failing; an operator has since accepted it | cyan |
| `RESOLVED` | Was failing; now `PASS`, `NOT_APPLICABLE`, or gone | green |

`VERDICT CHANGED` is not a transition anybody asks for, and it exists because
without it the report contradicts itself: `UNKNOWN` leaves the posture
denominator and `FAIL` does not, so a check sliding between them moves the score
with no change listed to explain it. It is also the transition that matters most
on its own terms — the tool has stopped being able to tell.

Each change is shown with **both ends** of its transition
(`[ PASS → FAIL ]`, `[ SUPPRESSED → FAIL ]`, `[ ABSENT → FAIL ]`), because
"resolved" alone does not distinguish a check that started passing from one
whose subject stopped existing.

### Joining the two sets

A fingerprint is `hash(check_id, subject)`, and several checks in the catalog
set a subject only when they have something to point at — `SSHD-0003` reports
subject `""` when it passes and `"PasswordAuthentication"` when it fails. The
same check on the same host therefore fingerprints differently either side of a
verdict change.

`diff` joins by fingerprint first, then makes a second pass over what is left:
when a check has **exactly one** unmatched finding on each side, the two are
paired. That is precisely the host-wide case above. A check reporting several
subjects at once is never paired this way, because guessing which path became
which would invent a transition that did not happen.

### Suppressions

`--suppress` applies to both sides, with expiry measured against **each
bundle's own scan time**. One file, two moments, two answers — which is what
makes `REGRESSED` observable: a rule that lapsed between the two collections
suppresses the older side and not the newer one.

### Output

Terminal only. `--json` is a **usage error**: rendering a comparison as a
document would be a second public API and `findings/v1` does not describe one.
Emitting an unagreed shape that a pipeline would then depend on is worse than
refusing.

`diff` exits `0` whatever it finds, and `70` if a bundle is missing or corrupt.
It carries no gate flags — the gates live on `scan` and `eval`, which is where
a verdict about a host belongs.

---

## 5. Flag precedence

Highest wins:

1. Explicit command-line flags
2. `--profile`
3. Config file (`--config` → `$PLUMBLINE_CONFIG` → `./plumbline.yaml`¹ → `~/.config/plumbline/config.yaml` → `/etc/plumbline/config.yaml`)
4. Built-in defaults

¹ **Ignored when euid is 0** unless passed explicitly with `--config`
(`THREAT-MODEL.md` T-07).

Mode flags are a single enum, not independent booleans; passing two is a usage
error, not a silent precedence surprise. Unknown config *keys* are a warning
(fleets run mixed versions); unknown *values* for known keys are an error,
because silently ignoring `fail_on: hgih` is how a gate stops gating.

---

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; all gates satisfied |
| 1 | Usage or configuration error — nothing was scanned |
| 2 | Completed; findings at or above `--fail-on` |
| 3 | Completed; posture below `--threshold` |
| 4 | Completed **degraded** — a collector failed, or coverage below `--min-coverage` |
| 10 | Insufficient privileges with `--strict-privileges` |
| 11 | Timeout exceeded |
| 70 | Internal error — panic escaped, bundle corrupt |
| 130 | Interrupted (SIGINT) |

**Precedence, evaluated top-down:**

```
130 > 70 > 11 > 1 > 10 > 4 > 2 > 3 > 0
```

Implemented as one function, tested per branch. The audited design had three
codes matching a single common outcome with no tiebreak, so CI behaviour
depended on implementation accident.

Code 4 is the one that matters most and the one the source design lacked
entirely: it distinguishes *"your host is misconfigured"* from *"the scanner
could not see your host"*. Codes 5–9, 12–19 and 71–79 are reserved for
expansion.

---

## 7. Output discipline

| Stream | Carries |
|---|---|
| stdout | The requested output, and nothing else. Machine-consumable when `--format json`. |
| stderr | Progress, warnings, deprecations, debug |

Progress is suppressed automatically when stdout is not a TTY. `--format json`
never writes a byte of anything else to stdout — a JSON document with a
progress spinner in it is not a JSON document.

---

## 8. Environment variables

| Variable | Effect |
|---|---|
| `PLUMBLINE_CONFIG` | Config path (below `--config`) |
| `NO_COLOR` | Any value disables colour |
| `PLUMBLINE_NO_PROGRESS` | Disables progress output |

No environment variable may enable a behaviour that a flag cannot, and none may
weaken a security control. Configuration surface is attack surface.
