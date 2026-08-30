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
| `--verbose`, `-v` | false | Add the severity tally and the detailed report (§7) | **yes** |
| `--quiet`, `-q` | false | Stream nothing; print only the closing result block (§7) | **yes** |
| `--fix` | false | Print the shell that would repair the failing checks this build can fix. **Executes nothing.** `--format terminal` only | **yes** |
| `--pace D` | `100ms` | How long a streamed row waits before its verdict lands; `0` draws at full speed (§7) | **yes** |
| `--output-dir DIR` | — | Directory; required when multiple formats | no |
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

The scan phase carries **no** detail, evidence or remediation. What an operator
acts on is in the **suggestion phase** at the bottom, under
`[=] Warnings and suggestions`, and it is **two lines per finding**:

```
  Warnings (36)  ·  a check read the value and it does not meet the requirement

  - [HIGH]    PAM does not accept an empty password [AUTH-0004]
      Details: Remove nullok from every pam_unix.so auth rule, and check for
               accounts that were relying on it.
  - [HIGH]    IPv6 router advertisements are refused in the sys… [KERNEL-0026]
      Details: Write net.ipv6.conf.all.accept_ra = 0 and
               net.ipv6.conf.default.accept_ra = 0 to a file in /etc/sysctl.d/
               — but confirm this host does not use SLAAC first.

  Could not determine (27)  ·  these are not passes

  - [UNKNOWN] No setuid or setgid executable is writable by gr… [FILESYS-0001]
      Details: source truncated
```

| Line | Content |
|---|---|
| The tag | The severity, or `[UNKNOWN]` for a check that produced no verdict. One space follows it — the colour is what the eye runs down, so a padded column was doing the work twice. |
| The bullet | The check's title and its ID in brackets. The title is truncated to fit; the ID never is — it is what a suppression file matches on and what `plumbline explain` takes. |
| `Details:` | The remediation summary. Failing that the subject; failing that, for an `UNKNOWN`, why it could not be determined — spelled out (`source truncated`), not the machine token the JSON keeps. **Word-wrapped, never truncated**, with a hanging indent to the column the value starts in: this is the one sentence telling an operator what to type, and a version of this section that cut it at the grid was concise and useless. |

Tag colours, which are what the eye runs down:

| Tag | Colour |
|---|---|
| `[CRITICAL]`, `[HIGH]` | red |
| `[MEDIUM]` | yellow |
| `[LOW]` | blue |
| `[UNKNOWN]` | magenta |
| `[INFO]` | unpainted — colouring every row is the same as colouring none |

`[UNKNOWN]` is deliberately not a shade of warning. A check that could not be
evaluated is not a mild failure; it is the absence of a verdict, and it must not
sit in the same colour as one that was evaluated and failed.

**Nothing else is printed here**, and that is deliberate. The detail sentence,
the evidence array with its sources and line numbers, the remediation effort and
its caution are all produced and all retained — by `--format json`,
by `--format sarif`, and by `docs/checks/<ID>.md`, which carries the full
remediation including its steps and commands. On a real host the same section
was 1,333 lines before this and is 170 now. A document nobody reads is not a
safety feature however complete it is; the terminal is the one output where
being exhaustive costs the reader something.

`FAIL` and `UNKNOWN` appear under separate headings and at equal weight, in the
same two-line form — moving the detail out of the scan phase was a change of
layout and must never become a change of emphasis.

#### Two widths, and one measurement that chooses between them

**The report's furniture is 78 columns and does not follow the terminal**: the
section rules, the scan phase's status column, the dashboard boxes. A report has
to be byte-identical across two runs of an unchanged host, or a scheduled scan
produces a diff every night and people stop reading it.

**The warnings section does follow the terminal** — the entry headline and the
wrapped remediation under it. That is prose read once and never diffed, and
holding it to 78 columns in a 160-column window folds a sentence that had room
to finish.

What decides is `TIOCGWINSZ` **on the destination writer**, not a flag:

| Destination | Warnings section |
|---|---|
| A terminal | the window's width, clamped to [40, 120] |
| A pipe, a redirect, `--output FILE` | 78 |

The ioctl answers for a terminal and fails for a file, so `plumbline scan > report.txt`
produces the same bytes from any window it is run in, and no mode flag can be
set wrongly. The cap at 120 is a judgement: prose set to 200 columns is prose
the eye loses on the return sweep, and it is the same ceiling the live stream
uses in `streamMaxWidth`.

Only check titles are Only check titles are
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

## 3a. Profiles

```
plumbline scan --profile cis-l1
plumbline eval host.plb --profile ./company-baseline.json
plumbline profiles
```

A **profile** is a declared baseline: the checks that apply to this class of
host. A server, a workstation and a hardened container are not the same machine
and should not share a posture denominator.

`--profile` takes a built-in name or a path to a `profile/v1` file. It is the
same flag `scan` has always carried — it was recorded in the bundle manifest
and displayed in the header and did nothing else; it now scopes the evaluation,
and the manifest field it already wrote becomes the record of that scope.

### Built-ins

| ID | Selects |
|---|---|
| `default` | The whole catalog. In force when no `--profile` is given |
| `cis-l1` | A Level 1 server hardening baseline. **Not a CIS benchmark** — see below |

`plumbline profiles` lists them with the count each selects.

**`cis-l1` is not a compliance artefact.** No check in this catalog carries a
CIS control mapping — the catalog maps to NIST 800-53 r5 only — so the
selection is Plumbline's own reading of which of its checks address Level 1
themes, not a correspondence to numbered CIS recommendations. It omits controls
a real Level 1 benchmark requires and cannot yet be observed, and includes
checks no CIS recommendation asks for. Passing it is evidence of sensible
hardening; it is **not** evidence of compliance and will not satisfy an auditor
who asked for CIS. The profile says so in its own description.

### File format

```json
{
  "schema": "profile/v1",
  "id": "company-baseline",
  "title": "What our servers must meet",
  "description": "optional",
  "included_checks": ["SSHD-*", "USERS-0001"],
  "excluded_checks": ["SSHD-0009"],
  "severity_overrides": {"CRON-0005": "LOW"}
}
```

| Field | Required | Meaning |
|---|---|---|
| `schema` | yes | Must be `profile/v1` |
| `id` | yes | Recorded in every output as the active profile |
| `title` | yes | A baseline nobody can describe is one nobody should trust |
| `included_checks` | yes | Check-ID patterns. `*` matches any run; `["*"]` is the catalog |
| `excluded_checks` | no | Applied after includes, and **wins** |
| `severity_overrides` | no | Per-check effective severity. One check each, never a pattern |

Unknown keys, a bad pattern, an invalid severity, a pattern used as an override
key, an empty include list, or a missing title are all **parse errors**, and an
unknown profile name or unreadable file exits `1`. Falling back to the whole
catalog would score a host against a baseline nobody asked for, and the
operator would read the number as though their profile had applied.

### What a profile does to the report

- **An excluded check is `SKIPPED`, never omitted and never
  `NOT_APPLICABLE`.** Omitting it would make a narrow profile look like a clean
  host; `NOT_APPLICABLE` would claim the subject is absent when in fact the
  question was withdrawn. It carries `skipped_by` naming the profile, and its
  evidence and remediation are cleared — they describe a verdict never reached.
- **An excluded check leaves the posture denominator.** The profile declares
  what applies, so the applicable set *is* the profile. A thirty-check baseline
  reports coverage against thirty checks, not against the catalog.
- **A severity override moves the effective severity and never the base.** Both
  are reported, exactly as a context adjustment is.
- The active profile ID appears in the terminal header, in `scan.profile` in
  `findings/v1`, and in `plumbline/profile` in SARIF.

The profile is applied **after every check has reached its verdict and before
anything is scored** — the same seam suppression uses. No check can observe a
profile, so check purity is untouched: a profile is a statement about which
questions to count, not an input to answering one. It is applied *before*
suppression, because a check outside the baseline was never asked and there is
nothing there to accept.

---

## 4a. `explain`

```
plumbline explain CHECK-ID [--no-color] [-o PATH]
```

Prints one catalog entry in full: what the check tests, which facts it reads,
the remediation with **every step and command**, the control mappings and the
references.

**This is where the remediation procedure lives.** A scan report prints only a
remediation summary — a block running to forty lines per finding is one an
operator scrolls past — and the full procedure has to be reachable by ID.

It reads the catalog and nothing else: no host, no bundle, no privileges, no
network. A question about what a check asks is a question about the binary, and
answering it must not require pointing the tool at a machine.

The check ID is **case-insensitive** and surrounding space is trimmed, because
an ID pasted out of a report often brings some with it. An unknown ID exits `1`
and suggests the IDs in the same module — the mistake operators actually make
is remembering the module and not the number.

There is no `--format`. One rendering of a catalog entry exists and it is for a
person; a machine-readable catalog is its own work package with its own schema,
and inventing one here as a side effect would freeze a shape nobody designed.

Lines wrap to the same 78-column grid as every other report, with two
deliberate exceptions: **commands and URLs are never wrapped.** A command
broken across lines does something else when pasted, and a wrapped URL cannot
be clicked or copied. Both are values an operator takes out of the report, and
breaking them to keep a margin tidy trades the reader's task for the page's
appearance.

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
| 130 | Interrupted — `SIGINT` or `SIGTERM` (§6.1) |

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

### 6.1 Interruption

`SIGINT` and `SIGTERM` cancel the collection and exit 130. The handler is
installed once, at the process entry point, and cancels the context every
command already derives its `--timeout` from; the collector runner selects on
that context at every point it could block, so the cancellation reaches the
bottom of the pipeline through the mechanism that was already there.

**An interrupted run produces no artifact.**

| Command | On interrupt |
|---|---|
| `scan` | No findings document on stdout, and `--save-bundle` writes nothing |
| `collect` | No bundle; stderr names the file that was not written |

This is deliberately stricter than the `--timeout` path, which does keep what it
collected. A budget is a decision to accept whatever fits inside it. An
interrupt is a decision to stop, and a bundle assembled from half a collection
carries no mark saying so — the manifest lists the facts that made it and is
silent about the ones that did not, so months later it re-evaluates to a
posture score drawn from half a host.

Interruption outranks everything in the ladder above, including a `--timeout`
that expired in the same run: an operator who pressed Ctrl-C is told they
stopped it, not that a budget they never reached had expired. The cancellation
carries its reason with it, so the two cannot be confused by a caller that
checks in the wrong order.

**The second signal kills.** The handler is uninstalled the moment the first
one arrives, restoring the default disposition, so a second Ctrl-C terminates
the process immediately. That is the safety valve for the one case a handler
cannot cover: a collector wedged in a syscall that never returns.

---

## 7. Output discipline

| Stream | Carries |
|---|---|
| stdout | The requested output, and nothing else. Machine-consumable when `--format json`. |
| stderr | Progress, warnings, deprecations, debug |

`--format json` never writes a byte of anything else to stdout — a JSON
document with a progress spinner in it is not a JSON document. That holds by
construction rather than by care: the indicator's only writer is stderr, so no
format can put one on stdout.

### The scoring notice

`scan` writes a block to **stderr** before it collects anything, naming the
recent changes that moved posture scores:

```
──────────────────────────────────────────────────────────────────────────
plumbline: SCORING NOTICE — 4 recent changes moved posture scores

  catalog 33  Six KERNEL checks were re-rated so each parameter has one severity.
      ...

  Posture is severity-weighted, so these moved scores on hosts that did not
  change. Reports from before them are not directly comparable; `plumbline
  diff` refuses to compare across catalog versions for the same reason.
  Set PLUMBLINE_NO_NOTICES to silence this.
──────────────────────────────────────────────────────────────────────────
```

VERSIONING §2.4 requires it: a correction likely to change results on more than
roughly 10% of hosts "carries a `plumbline scan` startup warning for one minor
cycle". The problem is narrow. Posture is severity-weighted, so re-rating a
check moves the number on a host nobody touched, and an operator has two
explanations available — the host changed, or the tool did — with only one of
them worth an afternoon.

| Rule | Why |
|---|---|
| stderr only | stdout is the contract. The notice is written by one call taking one writer, and `scan` hands it stderr, so no `--format` can put a banner in a parsed document. |
| Before collection | A scoring change has to be stated before the score it moved is reported. It is also before the progress indicator claims the line. |
| Each entry expires on its own | Keyed to the tool version at which it stops being shown. A build with no release identity — `go run`, a test binary, `git describe` with no tags — shows every entry, because it has passed no expiry and a stale notice costs less than a missing one. |
| **Not** conditional on a terminal | The opposite of the progress indicator's policy, deliberately. That is an animation and useless in a log; this is one static block, and CI is where an unexplained posture movement trips a `--threshold` gate nobody can explain the next morning. |
| `PLUMBLINE_NO_NOTICES` silences it | Honoured on presence, not value (§8). |

`eval` does not write it. VERSIONING §2.4 names `scan`.

### The live scan stream

`scan --format terminal` narrates the scan on **stderr** as it happens: one row
per collector, then one per check, each with its verdict flush against the right
edge of the terminal.

```
[*] Collecting host evidence
  - Collecting users                                             [ DONE ]
  - Collecting fswalk (41s)                                      [ DONE ]

[*] Evaluating the catalog

[+] Module: AUTH
---------------------------------------------------
  - Checking A password quality module is enforced                 [ OK ]
  - Checking Password quality parameters require length…      [ WARNING ]

[+] Module: SSHD
---------------------------------------------------
  - Checking Root login is disabled over SSH                  [ WARNING ]

[*] Result  posture 88.3   coverage 100%
    82 passed, 11 failed, 0 unknown, 16 not applicable

    Run again with --verbose for detailed evidence and remediation.
```

**A streamed row is the verb, the title and the verdict.** No check ID, no
trailing ellipsis. An ID is for copying — into a suppression file, into
`plumbline explain` — and nothing can be copied out of a display that scrolls
past at a tenth of a second a row, while the report underneath carries the ID on
every entry and is still on screen when the scan ends. What the ID cost was the
title: it sat in the row's fixed tail, so on a narrow terminal the sentence was
squeezed to make room for an identifier nobody was reading.

**Three levels, and each marker means one thing.** `[*]` is a phase — the two
halves of a scan. `[+]` is a module heading, which is what `[+]` already means
in the report (`[+] SSHD  · 19 checks, 2 failing`). `  - ` is a row. Before the
grouping, `[+]` was a module in the report and a row in the stream, so an
operator who saw both in one session saw one marker for a family of checks and
for a single check.

Collector rows are indented on the same rule even though they open no module:
they sit under the `[*] Collecting host evidence` phase, and a second prefix in
the same column would be two vocabularies for one list.

| Rule | Detail |
|---|---|
| A heading per module | Taken from the check ID's prefix — `AUTH-0001` is `AUTH`. An ID with no hyphen has no module and opens no heading. |
| Written when the module changes | Not on a lookahead. The drawing goroutine compares the row in its hand against the module on screen, because it cannot see what is queued behind it and must not open a section a Ctrl-C is about to cancel. A catalog that stopped evaluating a module contiguously would therefore reopen its heading rather than file rows under one several screens above. |
| The rule is 51 columns, clamped | Narrower than the row, so it introduces the column of brackets instead of competing with it — and never wider than the terminal, because a rule that wraps is two rules. |
| The heading is not paced | The pace exists so a row can be read while it is on screen. A heading is not a result. |

**On a terminal, this is the whole of the output.** The detailed report — every
finding with its evidence, remediation and cautions — is withheld, because the
stream has just put the same checks on the same screen and following them with
several hundred lines of detail buries the thing the operator was watching. See
"What the terminal shows", below.

**It replaces the progress indicator; the two never both run.** They are the
same job — telling a person that something is happening — and they obey the same
four conditions (below). Where those conditions say nobody is watching, the
stream is not built and the indicator takes over, which is the behaviour that
was there before and is still right for a log.

| Property | Detail |
|---|---|
| stderr only | The report is the contract and this is a view of it being made. `plumbline scan --json > out.json` shows the scan happening and writes a clean document. |
| `--format terminal` only | Not a stdout concern — the stream never touches stdout — but an intent one. Somebody asking for machine-readable output is scripting, and narrating a hundred checks at them is noise on the stream they left open for errors. |
| Same four conditions as the indicator | `PLUMBLINE_NO_PROGRESS` unset, stderr a character device, `TERM` set and not `dumb`, no CI marker. One list, consulted twice. |
| Width follows the terminal | Unlike the report's fixed grid. See below. |
| Tokens are the report's | `[ OK ]`, `[ WARNING ]`, `[ UNKNOWN ]`, `[ SKIPPED ]`, produced by the same function the report uses. An operator who watches `WARNING` scroll past and then greps the report for it must find it. Colours match too, in every state but one: `SKIPPED` is cyan here and dim in the report, because a row carrying no verdict recedes correctly on a dense page and reads as a display failure in a scrolling list. |

#### `--fix`: the proposed remediation script

**It proposes and it runs nothing.** `--fix` appends a
`[=] Proposed remediation script` block after the report, whose first line is
"Nothing below has been run." What follows is a shell script an operator can
read, and paste, and run as root when they have decided to.

```
[=] Proposed remediation script
──────────────────────────────────────────────────────────────────────────────

  Nothing below has been run.
  2 checks covered by this script; review it, then run it as root.
  34 checks still failing with no automated fix; see the warnings above.

#!/bin/sh
...
# KERNEL-0004 — The kernel ring buffer is not readable by unprivileged users
sysctl -w kernel.dmesg_restrict=1
plumbline_sysctl_set kernel.dmesg_restrict 1 "$DROPIN"

sysctl --system
```

| Rule | Detail |
|---|---|
| Only a **failing, unsuppressed** check is fixed | An `UNKNOWN` established nothing about the host — writing configuration on the strength of it is acting on a guess, as root. `NOT_APPLICABLE` has nothing to fix. `SKIPPED` was deliberately not run. A **suppressed** finding is an operator saying what they want to happen, and is not even counted as unfixable. |
| What is *not* covered is said every time | A block listing four fixes and silent about the other thirty-two failures would read as the whole of what is wrong with the host. |
| Both halves of a sysctl, always | `sysctl -w` is undone by the next reboot; a line in a drop-in does nothing until something applies it. |
| One file, owned by plumbline | `/etc/sysctl.d/99-plumbline-hardening.conf`. `99-` sorts after every distribution and administrator file, so what plumbline sets is what the host boots with; the name says who wrote it. Editing `/etc/sysctl.conf` or a distribution's file would put the change where an upgrade will revert it. |
| **Safe to run twice** | The script replaces a key where it already stands, drops duplicates, and appends only a key that is absent. Running it a second time leaves the file byte-identical. |
| The script is printed unindented | Every other block in the report is laid out to be read; this one is laid out to be *taken*. Two leading spaces would survive the paste and have to be stripped by hand from a file about to be run as root. |
| `--format terminal` only | stdout is a document under `--json` and `--format sarif`, and appending shell to one produces something no parser accepts. The combination is a usage error rather than a silent redirect to stderr. |
| `scan` only | `eval` has no `--fix`: a bundle can be a month old and from another host, so proposing changes to *this* machine from it would be proposing them for the wrong one. |

Covered in this phase: `KERNEL-0004`, `KERNEL-0016`, `KERNEL-0026` (both `all`
and `default`, because neither alone is the effective setting), `KERNEL-0030`.

**Nothing applies a plan, and that is the line rather than a gap.**
`PROJECT-BRIEF.md` §1.3: generating a script is a review step; a tool that
rewrites configuration as root from a heuristic, on a machine the operator
cannot see, will eventually lock someone out of production.

#### The heartbeat

**Rows are written on completion, so the slowest collector is silent while it
runs.** On this host with a cold page cache that meant twenty-four seconds of a
motionless terminal while `fswalk` walked the filesystem — which reads as a
crash. While the display has nothing queued and a collector is still working, it
says so:

```
  - Collecting memory...                                                [ DONE ]
[~] Still working: fswalk (17s) /
```

| Rule | Detail |
|---|---|
| `[~]` is its own marker | `[*]` a phase, `[+]` a module, `  - ` a row — all three are permanent record. The heartbeat is overwritten and then erased, and nothing it says survives the scan. |
| It names the longest-running collector | That is the answer to the question a frozen screen raises. Others still going are counted (`and 2 more`), not listed: a line that named them all is the line that wraps. |
| It never ends a line | `\r`, erase, text, no newline — so it sits on the line the next row will be drawn on, and coming off is `\r` and an erase again. There is no cursor-up anywhere: stepping back over a newline breaks on a wrapped line, on the bottom row where the scroll region moves, and whenever anything else writes to stderr in between. |
| It never lands inside a row | The pause between a row's title and its verdict is the longest window with the cursor mid-line, and the display is inside that pause rather than at the top of its loop. A queued row also always beats a pending tick. |
| It is truncated to the terminal | A heartbeat that wrapped would be two screen lines and the erase reaches only one. |
| It refreshes every 125 ms | Fast enough to be visibly alive, slow enough that a stalled scan is not spending its time on escape sequences. |
| It stops when nothing is running | It is a statement about the host, not a decoration. |

Reported by `collect.Observer.CollectorStarted`, called when a collector begins
working — not when its goroutine is created. One queued behind a dependency or
behind the expensive slot is not on the host, and naming it would point at the
wrong collector. Every collector reports `CollectorDone`; only the ones that ran
report `CollectorStarted`.

#### The pace

**Each row is drawn in two halves with a deliberate pause between them**, and
that pause is the only thing in this tool that costs time without doing work,
so it is stated plainly rather than buried.

```
  - Checking Root login is disabled over SSH                             ← drawn
                                                             ...100 ms...  ← flushed, so it is on screen for this
  - Checking Root login is disabled over SSH                  [ WARNING ] ← then this
```

The catalog evaluates 109 checks in about 1.3 ms. Printed at that speed the
stream is not a stream: it is a wall of text already complete before the eye has
fixed on anything, which teaches an operator nothing the closing two lines would
not have told them faster. A row-by-row display is worth having only if a row
can be read while it is on screen.

| Rule | Detail |
|---|---|
| 100 ms a row | The third number this has had. 150 ms was the fastest cadence at which a column of brackets still reads as a sequence; 500 ms the slowest worth sitting through. Both were asking how long *one row* needs in a flat list of a hundred and twenty — where the pause is the only structure there is. Grouping supplies the structure instead, so the pace no longer has to, and a hundred and twenty-odd rows come in at about twelve seconds. |
| The title is flushed before the pause | A delay between two writes shows nothing unless the first has reached the screen. `os.Stderr` is an `*os.File` and needs no flush — one `write(2)` per `Write` — but the renderer probes its writer for `Flush() error` and calls it anyway, so the effect cannot be lost by wrapping stderr in a buffered writer for some unrelated reason. `Sync()` is deliberately not called: `*os.File` has it, it means *commit to storage*, and on a character device it returns `EINVAL`. |
| `--pace 0` removes it | For anybody who wants the answer rather than the show. `--pace 300ms` slows it. |
| Charged to the display, never to the engine | Every row is **queued**, not drawn, by whoever produced it: one goroutine owns the terminal and does the waiting. Evaluation still takes 1.3 ms, collectors keep reading the host instead of sitting in a sleep, and no duration the report prints is measuring the display. |
| Paid only where the rows are | A pipe, a redirect, a CI log, `--format json`, `PLUMBLINE_NO_PROGRESS` and `--quiet` all draw no rows, so none of them waits. `plumbline scan --quiet` and `plumbline scan \| cat` run at full speed. |
| Ctrl-C skips the display, not the answer | The first press abandons what is left of the queue within milliseconds, finishes the row it was drawing so no half-line is left on the terminal, and still prints the result block. A scan whose work is already done reports its result; only the narration is cut. |

#### What the terminal shows

**Three modes, and the standard one exists to leave the stream on the screen.**
Everything after the last streamed row competes with it for the last page of an
80×24 terminal, so standard mode allows itself four lines and a hint.

| | standard | `--verbose` | `--quiet` |
|---|---|---|---|
| Scoring notice | yes | yes | yes |
| Collection rows `[ DONE ]` | yes | yes | — |
| Evaluation rows `[ OK ]` / `[ WARNING ]` | yes | yes | — |
| `[*] Result` block — posture, coverage, counts | yes | yes | yes |
| Severity tally — the `! HIGH` list | — | yes | — |
| Detailed report — evidence, remediation, cautions | — | yes | — |
| Closing hint | `--verbose` | where the report went | — |
| Pays the `--pace` delay | yes | yes | — |

The **severity tally is one line per failing check** — eleven on a fixture,
forty on a real host — and it lands after the stream, so in standard mode it
would be the only thing left on screen when the scan ends. The `[*] Result`
block already says how many failed; *which* ones is a question `--verbose`
answers.

`--quiet` gets no hint: it is the mode that asked for less, and a line of advice
is what it asked to be rid of. It does not silence the scoring notice, which is
a correctness warning rather than progress chatter and has
`PLUMBLINE_NO_NOTICES` of its own. `--verbose` and `--quiet` contradict each
other and passing both is a usage error.

#### Where the detailed report goes

| Invocation | stdout |
|---|---|
| `plumbline scan` on a terminal | *nothing* |
| `plumbline scan --verbose` | the report, without its scan phase |
| `plumbline scan --quiet` | *nothing* |
| `plumbline scan > report.txt` | the whole report |
| `plumbline scan -o report.txt` | *nothing* (the file gets the whole report) |
| `plumbline scan --json` | the document |
| Piped, in CI, or `PLUMBLINE_NO_PROGRESS` | the whole report |

The report is withheld **only** when a live stream has already put the whole
scan on the same terminal and the operator did not ask for it — one condition,
four exceptions, all of them cases where nothing else has said anything.

Under `--verbose` on a terminal the report drops its own **scan phase**, the
grouped per-module listing, because the stream just drew the same hundred rows.
It keeps the header, the fact errors, the warnings and suggestions, and the
dashboard: a gauge and four module cards are not a repetition of a scrolling
list. Every non-terminal destination gets the scan phase as before.

This is the only place where stdout's content depends on what stdout is, and it
is a deliberate exception. Everything scripted keeps the document it always had:
a pipe, a redirect, `--output`, `--format json`, a CI run. What changes is the
one case where the tool was talking to a person who had just watched it work.

#### Why this one measures the terminal and the report does not

The report is an artifact somebody diffs, so its grid is fixed at 78 columns and
two runs of an unchanged host are byte-identical. The stream is gone as soon as
the terminal scrolls, is never redirected into a file anybody compares, and is
laid out against `TIOCGWINSZ` at the moment each row is written — so a window
resized mid-scan reflows from the next row on. Nothing already printed moves,
because nothing can move somebody's scrollback.

The terminal is measured **once per row**, and a module heading opened by that
row shares the measurement: a window dragged between a heading and its first row
cannot leave the two laid out against different widths, for the same reason the
two halves of one row cannot.

Each row is `  - ` + a fixed head + an elastic middle + a fixed tail, padded so
that head through token is exactly the terminal width. **Only the middle
gives.** A collector's elapsed time is in the tail and is never squeezed out —
`(41s)` is the answer to the question a person watching a long collector is
asking. A window too narrow for even one column of title produces a row exactly
one column over rather than a wrapped one. Widths are clamped to
[20, 120]: past 120, flush-right puts the verdict too far from the title for the
eye to associate them.

### The progress indicator

`scan` and `collect` draw a transient one-line indicator on **stderr** while
the collectors run, erased before anything else is written:

```
⠹ Collecting host evidence (12s)
```

Collection is the slow half of a scan, and it used to be the silent half — tens
of seconds of nothing on a real server, which looks exactly like a hang. The
elapsed time appears only after three seconds, because "0s" answers nothing
while "47s" distinguishes a large filesystem from a wedged one.

**Keyed off stderr, not stdout.** An earlier revision of this section said
stdout, which is the wrong descriptor for something stderr draws:
`plumbline scan > report.txt` leaves stderr on the terminal, and that is
precisely the run where an operator most wants to see that something is
happening. The file stays clean either way.

It is the fallback for the runs the live stream does not cover: `collect`,
which has no evaluation phase to narrate, and any `scan` asking for a format
other than `terminal`.

It is drawn only when all four of these hold, and the default is off:

| Condition | Why |
|---|---|
| stderr is a character device | A pipe, a file or a captured log cannot show an animation, only accumulate it. This is what keeps every CI harness clean, named or not. |
| `PLUMBLINE_NO_PROGRESS` is unset | The operator said no. §8 reserved the variable before there was anything to suppress. |
| `TERM` is set and is not `dumb` | A terminal that will not identify itself cannot be assumed to understand `CSI K`, and an indicator that can move the cursor but not erase itself is the one failure mode this must not have. |
| No CI marker in the environment | Several CI systems allocate a pty, which defeats the first condition while the output still goes to a log nobody is watching live. Presence of the variable is the signal, not its value. |

`NO_COLOR` is deliberately **not** consulted. That convention governs colour,
the indicator emits none, and widening somebody else's standard to also mean
"stop moving" is how a well-known variable stops meaning one predictable thing.

Interrupting a scan erases the indicator like any other ending: `SIGINT`
cancels the collection context, the collection phase returns, and the deferred
stop clears the line before the exit message is printed (§6.1).

---

## 8. Environment variables

| Variable | Effect |
|---|---|
| `PLUMBLINE_CONFIG` | Config path (below `--config`) |
| `NO_COLOR` | Any value disables colour |
| `PLUMBLINE_NO_PROGRESS` | Any value disables the progress indicator (§7) |
| `PLUMBLINE_NO_NOTICES` | Any value disables the scoring notice (§7) |

No environment variable may enable a behaviour that a flag cannot, and none may
weaken a security control. Configuration surface is attack surface.
