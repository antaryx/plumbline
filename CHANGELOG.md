# Changelog

All notable changes are recorded here. Format follows [Keep a Changelog];
versioning follows `docs/VERSIONING.md`, which governs four separate version
numbers (tool, catalog, schema, vulnerability data).

Every release that alters a check's verdict logic MUST carry a
`### Check corrections` section naming the check, the old behaviour, the new
behaviour, and who is affected. A user's posture score changing without an
explanation in this file is a defect.

## [Unreleased]

`v0.4.0` in progress. `docs/ROADMAP.md` carries the rest of the milestone:
suppressions first, then `diff`, then the catalog-legibility commands.

### Added
- **`plumbline diff OLD NEW` (WP-30).** Compares two bundles and reports only
  what moved, in five categories: `NEW FAILURE`, `REGRESSED`,
  `VERDICT CHANGED`, `NEWLY SUPPRESSED` and `RESOLVED`. Each change shows both
  ends of its transition, and the summary carries a posture delta beside a
  coverage delta.

  **Both sides are re-evaluated with today's catalog**, so a check whose logic
  was corrected between the two collections cannot appear as the host having
  changed. There is consequently no catalog-drift flag.

  A suppressed finding is compared by `suppression.original_result`, so
  accepting a risk diffs as an acceptance rather than as a fix — and a rule that
  lapsed between the two collections shows as `REGRESSED` rather than as
  somebody having broken something.

  `VERDICT CHANGED` (`FAIL` ↔ `UNKNOWN`) is not one of the four transitions the
  work package named. It is here because `UNKNOWN` leaves the posture
  denominator and `FAIL` does not, so without it a host could show a posture
  delta with no change listed to explain it.

  Terminal output only; `--json` is a usage error, because rendering a
  comparison as a document would be a second public API and `findings/v1` does
  not describe one.

- **Acknowledgeable suppressions (WP-29).** `--suppress PATH` applies a
  `suppressions/v1` file mapping a finding fingerprint to a justification and an
  optional expiry.

  **A suppression never removes a finding.** The result becomes `SKIPPED` and
  the finding carries a new `suppression` object recording the justification,
  the expiry, and `original_result` — what the check actually reached. Accepted
  risks get their own `[=] Accepted risks` section in the terminal report and a
  distinct `[ SUPPRESSED ]` status token, so "we accepted this" can never read
  as "we never looked".

  A blank justification, an unknown field, a duplicate fingerprint, or a
  `check_id`/`subject` label that fingerprints to something else are all **parse
  errors**, and a bad file is a hard error rather than a scan with nothing
  suppressed. Rules that lapsed or matched nothing are reported on stderr.

  Expiry is measured against the scan's start time rather than the wall clock,
  so re-evaluating an archived bundle gives the same answer forever.

  An accepted risk leaves the posture denominator (a team is not scored down for
  reviewing something) and reduces coverage, which is the existing meaning of
  `SKIPPED`.

### Schema
- **`findings-v1` gained an optional `suppression` object on a finding.**
  Additive within the schema major (`VERSIONING.md` §4.1); consumers written
  before it existed ignore it and correctly see a `SKIPPED` finding. The
  `result` enum is unchanged.
- The constraint "a result other than `FAIL` carries no remediation" now excepts
  suppressed findings, which keep the fix they would otherwise need so the
  acceptance stays reviewable. This relaxes a rule — no previously valid
  document becomes invalid.
- A new constraint enforces that `suppression` appears only on `SKIPPED`.

### Changed
- **The terminal report is laid out in the manner of `lynis` (WP-28).** A scan
  phase of one line per check under `[+] MODULE` headings, each carrying a
  bracketed verdict flush against a fixed 78-column grid — `[ OK ]`,
  `[ WARNING ]`, `[ UNKNOWN ]`, `[ SKIPPED ]`, `[ DISABLED ]` — and a
  `[=] Warnings and suggestions` phase at the bottom carrying every detail,
  evidence excerpt and remediation. The previous layout interleaved the two,
  which put forty lines of advice between two check results and destroyed the
  column of verdicts the layout exists to provide.

  `NOT_APPLICABLE` and `SKIPPED` render as different tokens rather than
  collapsing into one: the first means the subject is not on this host, the
  second that the check was deliberately not run.

  `UNKNOWN` keeps its own heading at equal weight in the suggestion phase. The
  detail moved; the emphasis did not.

  **This is a layout change to output that is explicitly not the API**
  (`docs/VERSIONING.md`, `CLI-SPEC.md` §Output). Anything parsing the terminal
  report was already unsupported and should ask for `--json`.

---

## [0.3.1] — 2026-08-20

**Verification harness repairs. No change to the tool.** Catalog version 13
unchanged, 79 checks unchanged, schema `findings-v1` unchanged, no check's
verdict logic touched. A scan of your host produces byte-identical output to
`v0.3.0`.

This release exists because `v0.3.0` shipped with a red pipeline, and a
security auditor whose own verification does not pass is not one you should
trust. Everything below was a defect in the test corpus or the CI harness. Two
of them had been failing on every CI run since the checks were written, and
passing on every developer machine — which is the interesting part.

### The fixture corpus did not survive a git checkout

Three FILESYS checks returned `PASS` on a fresh clone and `FAIL` in the
working tree that authored them. Git cannot store an empty directory and does
not store files nobody added, so `filesys-sticky/var/spool/upload`,
`filesys-system-dir/etc/cron.d` and `filesys-suid-writable/opt/vendor/helper`
did not exist in the tree CI checks out. Each check correctly found nothing
wrong with a subject that was not there. **The FAIL half of those fixtures
existed only on one machine**, so rule 5 was satisfied on paper and not in
fact.

`TestEveryFixtureSurvivesACheckout` now asserts that every path a
`fixture.json` names exists, that no fixture directory is empty, and that every
fixture file is tracked by git. It caught an untracked file of its own within
the hour.

To be explicit, because it was the first hypothesis and it was wrong: **git
stripping the SUID and SGID bits was not the cause.** Git records those
fixtures as `0644` and always has; the manifests declare the modes and the fake
seam applies them, so the checks never read the on-disk bits. No manifest
needed a mode override added, and none was.

### A fixture's verdict depended on who cloned the repository

`scan --root` reads through the live seam, so a fixture tree carries the
ownership of whoever checked it out — uid 1000 on a developer machine, 1001 on
a GitHub runner, 0 in a container. `cli-host/etc/passwd` contains `alice:1000`,
so on one of those three the owners resolved and FILESYS-0010 returned `PASS`.

On the other two the owner did not resolve, and the check declined to call it
stray without knowing the local files were the whole account database — it
returned `UNKNOWN(ambiguous_system_state)`, which is rule 3 working exactly as
intended. But an `UNKNOWN` is not an evaluated check, so coverage fell to 98.73
and the `--min-coverage 100` gate failed. **The bug moved coverage rather than
a verdict**, which is why it was invisible in a diff and green on the machine
that wrote it.

The check was right and is untouched. The fixture was wrong: a Debian 12 host
with no `/etc/nsswitch.conf` does not exist. With the file present the check
reaches a verdict under any ownership, and `docs/FIXTURES.md` §4.3 now states
the rule that live-seam fixtures have to follow.

### CI parsed a human report as JSON

Four workflow steps grep a `findings/v1` document out of `scan` and `eval`.
`v0.3.0` made the terminal report the default output and did not update them,
so they failed while reporting a degraded exit code — a symptom of the parse,
not of coverage. They pass `--json` now, and the distro step prints the summary
and every non-`PASS` finding when an assertion fails instead of exiting 1 with
no evidence.

### Verified
All twelve CI jobs pass on `main`: `verify`, `go test -race`, `golangci-lint`,
schema validation, the hostile-input corpus, the zero-network namespace scan,
both cross-compiles, and scans on `alpine:3.20`, `debian:13`, `fedora:latest`
and `ubuntu:24.04`. The suite was additionally run as uid 1001 over a
`git archive` of the release tree, which is what a runner actually receives.

### Check corrections
None. No check's verdict logic changed in this release, and the catalog version
is deliberately unchanged at 13 — a bump would falsely signal that scores are
no longer comparable with `v0.3.0`.

---

## [0.3.0] — 2026-08-20

**Engine maturation and resilience.** Catalog version 13, 79 checks across nine
modules, schema `findings-v1` unchanged.

Three things happened, and each closed a hole the previous milestone could not
have found.

**1 — The walker learned to aggregate, and FILESYS-0010 became possible.**
The shared walk recorded rows: the first N inodes matching a pure predicate.
That answers "show me the setuid binaries" and cannot answer "does every uid on
disk resolve to an account", because the join is against a fact that does not
exist when the predicate is registered and recording every owned inode to defer
the join would overflow the row cap on any host that has users. A `Tally` folds
instead of recording — one bucket per distinct key, an unbounded count inside
it, one exemplar path — so memory is bounded by distinct *owners* rather than
by inodes, and a tally covers a ten-million-inode filesystem in about 3 MB. The
join then happens in the check, where facts live. `users.nsswitch` was
collected alongside it, because "not in `/etc/passwd`" and "belongs to nobody"
are the same statement only when the local files are the whole account
database.

**2 — The default output became a report for a person.** `plumbline scan`
printed a `findings/v1` document, which is right for a pipeline and wrong for
whoever typed the command. `internal/render/text` is now the default: a header
with the scan's context, a per-module listing, a full block for every FAIL
**and every UNKNOWN**, and a summary that states the UNKNOWN count on its own
line instead of burying it. **This is a breaking change for anything piping the
output into a parser** — add `--json`. No new dependency: plain SGR escape
sequences and `text/tabwriter`.

**3 — The scanner stopped drawing verdicts from files it could not parse.**
Pointed at a host with four kilobytes of random bytes in every configuration
file, it used to return **22 PASS, 23 FAIL and zero fact errors**. No parser
panicked; every one of them silently produced an empty, confident fact, and an
empty configuration satisfies every negative assertion in the catalog. The same
host now produces five fact errors and no PASS or FAIL from any content-reading
module. Recorded in *Check corrections* below, because it moves posture scores
on damaged hosts.

### Milestone scope
`v0.3.0` was originally scoped as "feature complete for v1" with eighteen
items, and shipped four. **Feature freeze moves to v0.4.0**, which carries the
other fourteen — SARIF, `diff`, suppressions, `doctor`, the platform matrix and
the remaining collectors. The re-scoping is recorded in `docs/ROADMAP.md`
rather than applied quietly, because a milestone that redefines itself on the
way to being tagged is exactly the thing a reader cannot reconstruct from a
diff.

### Check corrections
- **Every check reading a configuration file now returns `UNKNOWN` where it
  previously reported a verdict drawn from a file it could not really parse.**
  A scan of a host with four kilobytes of random bytes in every config file
  used to produce 22 `PASS` and 23 `FAIL` findings and **zero fact errors**;
  it now produces five fact errors and no `PASS` or `FAIL` from any
  content-reading module. Affected: anyone whose posture score was computed
  over a host with a damaged `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `sshd_config`, `rsyslog.conf`, `nsswitch.conf`, a PAM stack, a firewall
  ruleset or a `sysctl.d` drop-in. Posture will move, and coverage will drop to
  reflect what was actually readable — which is the correct figure and was not
  being reported
- **Every SSHD check now returns `UNKNOWN` over a configuration `sshd -t`
  rejects**, including checks whose keyword the file appears to set. sshd
  refuses a config file as a unit rather than skipping the bad line, so on such
  a host the daemon runs whatever last parsed and the file on disk describes
  nothing. Previously these reported sshd's compiled-in defaults, which is
  correct for a valid file that omits a keyword and a confident wrong answer
  for a file that never loads
- **USERS-0006 no longer returns `PASS` over an `/etc/passwd` that is not an
  account database.** It read the (true) observation "this file contains no NIS
  import lines" off a file with no accounts in it at all. It now routes through
  the module's `unknownIfIncomplete` gate like every other check here
- **A required fact this build cannot decode is now `UNKNOWN(fact_version_mismatch)`
  rather than a verdict.** Re-evaluating a bundle written by a newer Plumbline
  reported `NOT_APPLICABLE: the SSH server is not configured on this host` —
  a statement about the host manufactured from a decode failure

### Added
- **`collect.NotText`, one gate on every collector's read path.** A NUL byte is
  *proof* a file is not the text configuration it was read as — every consumer
  of these files on Linux is C reading NUL-terminated strings, so the software
  that acts on the file stops at that byte or refuses it, and any reading of
  ours that continued past it would describe a configuration that is not in
  force. Applied in the `users`, `sshd`, `logging`, `network`, `auth` and
  `kernel` collectors. Invalid UTF-8 is deliberately **not** treated as
  malformation: a GECOS field carries a Latin-1 name on older hosts, and
  `sanitize` already handles those bytes correctly
- **`fact.SSHDConfig.SyntaxErrors`** — non-blank, non-comment lines that are not
  a keyword followed by an argument. `sshd_config(5)` defines no keyword taking
  zero arguments, so each is fatal to `sshd -t`. Unrecognised keywords are
  deliberately not recorded: the valid keyword set differs by OpenSSH release,
  and calling a newer option a syntax error would report a fault on a host that
  is merely more current than this build
- **`fact.Opaque`** — the marker for a fact that is present, preserved, and not
  interpretable by this build. An interface rather than a concrete type so that
  `internal/catalog` need not import `internal/bundle` to evaluate anything.
  `finding.ReasonFactVersion` was declared for this case and had never been
  produced by anything
- **Four `edge-*` fixtures** and module-wide tests over them. The tests are
  module-wide rather than per-check on purpose: the per-check version of these
  gates had already been forgotten three times — SSHD-0002 (the module's own
  reference implementation), SSHD-0007 and USERS-0006 all read their fact
  directly instead of through the shared funnel and so carried none of the
  shared gates
- **A human-readable terminal report, and it is now the default.** Running
  `plumbline scan` printed a `findings/v1` document, which is the right answer
  for a pipeline and the wrong one for the person who typed the command.
  `internal/render/text` renders a header with the scan's context, a
  per-module listing of every check, a full block for every FAIL and every
  UNKNOWN — detail, evidence, remediation summary and effort — and a summary
  table. `PASS` is green, `FAIL` red, `UNKNOWN` yellow, `NOT_APPLICABLE` and
  `SKIPPED` dim. No external dependency: plain SGR escape sequences and
  `text/tabwriter`
- **`--json`**, shorthand for `--format json`, on `scan` and `eval`. It is
  shorthand over the *default*, not an override — `--format terminal --json` is
  a usage error rather than a silent discard of what the operator typed
- **`--no-color`**, alongside `NO_COLOR` in the environment (honoured at any
  value, including `0`, per the no-color.org convention) and a non-terminal
  stdout. `--output` is never coloured whatever the rules say
- **Aggregating walker tallies** (`internal/collect/walker/tally.go`). The walk
  already answered "which inodes match this predicate" by recording rows. It
  now also answers "how are these inodes distributed across a keyspace" by
  folding: one bucket per distinct key, an unbounded count inside it, and one
  exemplar path. Memory is bounded by distinct keys rather than by inodes, so a
  tally can cover a ten-million-inode filesystem inside a budget a
  row-recording interest would exhaust in its first populated directory. New
  fact namespace `fs.tally.<name>` (`fact.FSTally`), new truncation reason
  `max_keys`, default keyspace cap 16,384
- **FILESYS-0010 — every uid and gid owning a file resolves to a local account
  or group.** MEDIUM. Files left behind by a deleted account are not untidiness:
  `useradd` allocates the lowest free uid, so the next account created inherits
  the number and everything the departed one owned, and nothing records that it
  happened
- **`users.nsswitch`** (`fact.NSSwitch`) — `/etc/nsswitch.conf`, parsed into
  which name services answer for which databases. Four USERS check specs
  already named this file as a known limitation; it is now collected

### Changed
- **`/etc/shadow` lines now require the nine fields `shadow(5)` defines.** The
  parser accepted any line with two, which let arbitrary text containing a
  single colon become an account with a password state — which is how four
  kilobytes of random bytes produced ten accounts and a `FAIL` reporting weak
  password hashes for people who do not exist
- Firewall ruleset files containing a NUL are recorded as `SourceError` rather
  than `SourcePresent`, so NETWORK-0001 no longer tells a host it has a
  firewall configured when nftables would refuse to load the file
- An unparseable rsyslog or journald drop-in is recorded as an unresolved
  include rather than skipped, so one bad drop-in degrades the checks that
  depend on it instead of reading as a file that configures nothing
- **`--format` now defaults to `terminal` rather than `json` on `scan` and
  `eval`.** This is the one change in this release that can break a caller:
  anything piping `plumbline scan` into a JSON parser must add `--json` or
  `--format json`. The exit codes, the schema and every flag that gates on
  findings are unchanged, and a test asserts the chosen format cannot move the
  exit code — rendering is display, gating is a verdict, and if the two could
  influence one another then `--json` would be a way to change what CI
  concluded about a host
- `--format` reports an unknown value by name and refuses `sarif` with a
  message that says it is coming rather than that it is a typo. The two are
  different problems for whoever is reading the error
- `internal/collect/collectors/users` reads a fourth file. `Produces()` gains
  `users.nsswitch`; a missing file is recorded as a *state* rather than as a
  fact error, because glibc falling back to a compiled-in default is a real
  observation about the host and simply not the same one as "configured to
  files"
- `walker.Walk` and the `fswalk` collector accept a walk justified by a tally
  alone. Previously a walk with no interests was a caller error
- `bundle.decoderFor` tests the `fs.tally.` prefix before `fs.`. The ordering is
  load bearing: `fs.tally.owner_uid` also carries the `fs.` prefix, and
  decoding it as an `FSMatches` would have *succeeded* — `encoding/json`
  ignores unrecognised fields — leaving an empty, complete-looking match set
  where a tally used to be, and FILESYS-0010 returning a confident PASS from a
  bundle that recorded a host full of unowned files. `TestRoundTripWalkerTallyFacts`
  pins it

### Security
- **The terminal renderer is where a hostile filename stops being a curiosity.**
  A path may contain arbitrary bytes including ESC, and this is the renderer
  that writes to an operator's session and that deliberately emits escape
  sequences of its own. Sanitisation already happens once, upstream, where
  untrusted text becomes part of a finding (T-03); `TestNoEscapeSequenceFromTheHostReachesTheTerminal`
  asserts the defence actually holds *through* this renderer rather than
  assuming it, and a second test asserts that with colour on, every ESC byte in
  the output is one the renderer wrote
- Reports written with `--output` are created owner-only, through the same path
  bundles are. A terminal report names paths, accounts and misconfigurations;
  it is the same reconnaissance material the JSON is

### Documentation
- `docs/DATA-MODEL.md` §3.1 documents what `parse` covers and, as importantly,
  the three things deliberately *not* treated as malformation. §3.2 documents
  `fact.Opaque` and the third state between present and missing
- `docs/FIXTURES.md` describes the `edge-*` corpus and what each fixture
  isolates
- **`docs/ROADMAP.md` rewritten against reality.** It still described the
  project as pre-v0.1 with everything ahead of it. v0.1.0 and v0.2.0 are now
  marked complete with what each actually shipped, the v1 module table carries
  a shipped-count column beside its target, and the 42-check gap between the
  78 that shipped and the ~120 planned is accounted for module by module rather
  than left to be rediscovered as a defect. v0.3.0 is scoped into engine
  maturation, UX and CLI polish, and edge-case resilience, in that order
- From this release, **every work package syncs `ROADMAP.md`, `CHANGELOG.md`
  and `DATA-MODEL.md` with what is actually in `main`.** A roadmap that
  disagrees with the code is worse than no roadmap, because people plan against
  it
- `docs/checks/FILESYS-0010.md`, and `docs/DATA-MODEL.md` §2.3 gains
  `fs.tally.<tally>` and `users.nsswitch`
- `docs/CLI-SPEC.md` §Output rewritten: which flags exist today and which are
  still specification, the three colour rules in precedence order, and an
  explicit statement that `--format json` is the API and the terminal report is
  not. `README.md` gains a usage section showing both
- **`docs/ROADMAP.md` v0.3 marks the terminal renderer done.** Per the rule
  adopted last release, the roadmap is synced in the same commit as the code

### Notes on what FILESYS-0010 will not do
- **It will not report a directory account as unowned.** "This uid is not in
  `/etc/passwd`" is a fact about a file; "this uid belongs to nobody" is a fact
  about the host, and the two coincide only when the local files are the whole
  account database. Where `nsswitch.conf` routes `passwd` or `group` anywhere
  else — including `systemd`, which is on the default line of every current
  systemd distribution — an unresolved identity yields
  `UNKNOWN(ambiguous_system_state)` naming the routing table, not a FAIL
- **The PASS branch never consults `nsswitch.conf`**, and that asymmetry is
  what keeps the check useful rather than permanently unknown. A name service
  can add identities that resolve; it cannot remove one `/etc/passwd` already
  resolves. So on a healthy directory-joined host every uid on disk still
  resolves locally and the check passes outright

---

## [0.2.0] — 2026-08-20

**The catalog milestone: 78 checks across nine modules**, every one with PASS
and FAIL fixtures enforced in CI, evaluated from a single filesystem traversal
and a bounded set of configuration reads. Catalog version 11.

| Module | Checks | | Module | Checks |
|---|---|---|---|---|
| SSHD | 19 | | AUTH | 6 |
| KERNEL | 16 | | CRON | 5 |
| USERS | 10 | | LOGGING | 5 |
| FILESYS | 9 | | SERVICES | 5 |
| | | | NETWORK | 3 |

### Security
- **Password hashes never enter a bundle.** Evidence recording is wired at the
  seam, so reading a file stored its bytes — which, applied to `/etc/shadow`,
  would have copied every password hash on the host into an artifact designed
  to be sent to auditors. `/etc/shadow`, `/etc/gshadow`,
  `/etc/security/opasswd` and `/etc/master.passwd` are now excluded from the
  evidence store, with no flag to re-enable them, and `users.shadow` records
  only whether a field is empty or locked and which crypt scheme it uses
  (ADR-0015)
- USERS-0009 (password maximum age) ships at **LOW** severity and names the
  framework conflict in its own finding. NIST SP 800-63B advises against forced
  rotation; CIS requires ≤365 days and the DISA STIGs require ≤60. Plumbline
  reports against the CIS threshold and states the disagreement rather than
  resolving it, so an organisation following NIST suppresses the check with a
  recorded reason instead of inheriting this project's opinion silently
- SSHD-0020 records the joint between two modules: with `UsePAM no`, sshd never
  runs the PAM account phase, so the password-aging policy USERS-0009 and
  USERS-0010 report is configured and not enforced for SSH logins
- `--redact` is documented precisely in `CLI-SPEC.md`: it removes the hostname,
  it does not anonymise account names, and it never was what kept hashes out of
  a bundle

### Check corrections
- **SSHD-0002 (root login) now reports a `Match` block that re-enables root
  login.** Previously a configuration with `PermitRootLogin no` globally and
  `PermitRootLogin yes` inside a `Match` block returned PASS, citing the
  Match-scoped directive as evidence but not acting on it. It now returns FAIL
  at MEDIUM — one class below the HIGH of a global misconfiguration, because the
  exposure is conditional rather than universal — and names the `Match` criteria
  in the detail.
  **Who is affected:** any host whose `sshd_config` re-enables root login inside
  a `Match` block. Those hosts move from PASS to FAIL and their posture score
  falls accordingly. The verdict was wrong before: the insecure state was
  reachable and the finding said otherwise.

### Added
- **FILESYS module (WP-24), 9 checks.** Catalog version 11. Six over the shared
  traversal — setuid or setgid executables writable by group or other
  (FILESYS-0001), the same outside the system binary directories (0002),
  world-writable files (0003), world-writable directories without the sticky
  bit (0004), world-writable system directories (0005), device nodes outside
  /dev (0006) — and three over the mount table: /tmp (0007), /dev/shm (0008)
  and /home (0009).
- **The shared filesystem walker is wired into the scan.** WP-15 built it and
  nothing consumed it; `internal/cli/catalog.go` now imports both the walker
  and the FILESYS interest registrations, so one traversal per scan actually
  happens. Five interests are registered: `suid`, `sgid`, `world_writable`,
  `world_writable_dir`, `device_outside_dev`.
- **The asymmetric truncation rule is enforced and tested first.** Every FILESYS
  check that concludes something from *not* finding a match returns
  `UNKNOWN(source_truncated)` when the walk hit a limit, and every check that
  reports something the walk *did* find returns FAIL whether or not the
  traversal finished. `filesys-truncated` is driven twice — once complete,
  where every check must PASS, and once with a four-inode budget, where every
  one must return UNKNOWN — because without the first half a check that
  returned UNKNOWN unconditionally would satisfy the second while being
  useless.
- **`fs.mounts` fact**, carrying each mount point's type, per-mount options,
  superblock options and a `Known` flag. It is derived from the mount table the
  walk **already reads** to apply its filesystem-type skip list rather than
  from a second read of /proc/self/mountinfo: two reads of one kernel table
  could disagree and the disagreement would be invisible. It is published
  unconditionally, including when no interest is registered and no traversal
  happens, because making it depend on an unrelated module's wiring would leave
  the mount checks UNKNOWN for a reason unconnected to the host.
- `parseMountInfoLine` now returns the per-mount and superblock option lists.
  The two are kept separate because mountinfo reports them separately and they
  are not the same thing — "is /tmp nosuid" is a question about the first, and
  answering from the second would be right often enough to look correct.
- **No FILESYS check carries an allowlist of blessed binaries**, per the
  runbook. Which setuid executables are legitimate differs per distribution and
  a hardcoded list silently excuses whatever an attacker names their implant
  after. What is asserted instead are properties no legitimate setuid binary
  has: being writable by a non-owner, and sitting outside the directories a
  package manager installs into.
- **SERVICES module (WP-21), 5 checks.** Catalog version 9. Cleartext-credential
  services not enabled (SERVICES-0001), network discovery and RPC portmapping
  (0002), exactly one time synchronisation daemon (0003), every enabled unit
  resolving to a unit file that exists (0004), and unit directories writable by
  root alone (0005).
- `services.units` fact. **systemd enablement is recovered from symlinks**:
  `systemctl enable` writes no database row and sets no flag inside the unit
  file, it creates a link in `<target>.wants/`, so reading those directories
  recovers exactly what `systemctl is-enabled` reports with no dbus and no
  privilege. Masking is tested before enablement because systemd does — a
  masked unit does not start even with a `.wants` symlink naming it.
- **`System.Readlink`**, which returns a symlink's target *as written* and
  resolves nothing (ADR-0017). A seam method returning a resolved absolute path
  would have dereferenced it against the real host rather than the scan root,
  silently, because a developer's machine has the file a fixture names.
  Resolution happens in the collector and goes back through `Stat`, so `--root`
  still governs it. `ErrNotSymlink` was added so `live` and `fake` agree about
  a path that is not a link.
- `symlinks` fixture-manifest key. Git stores symlinks natively, so unlike
  ADR-0013's inode overrides this is a containment rule rather than a
  capability gap: an *absolute* target committed as a real link resolves
  against the developer's root, and a fixture naming
  `/usr/lib/systemd/system/sshd.service` points at the real unit on every Linux
  workstation. Relative targets stay as real links and need no entry.
- **NETWORK module (WP-22), 3 checks.** Catalog version 10. A host firewall is
  configured (NETWORK-0001), its default inbound policy denies (0002), and
  exactly one configuration is in force (0003). The module is small on purpose:
  SSHD covers the exposed service and KERNEL covers the packet-handling
  parameters a firewall does not govern.
- `network.firewall` fact — **derived properties only, never ruleset contents**.
  A firewall configuration is a map of the network, and a bundle designed to
  travel would carry it wherever the bundle is filed. An empty configuration
  file is not a firewall: Debian's nftables package installs
  /etc/nftables.conf whether or not anybody wrote a rule in it, so statements
  are counted rather than the file's existence being trusted.
- **AUTH module (WP-23), 6 checks.** Catalog version 10. Password quality
  enforced (AUTH-0001), its parameters strict enough (0002), account lockout
  configured (0003), empty passwords refused (0004), strong password hashing
  (0005), and password history kept (0006).
- `auth.pam` fact — **the PAM stack as a graph, not a file**. Three include
  directives with different scopes build it: `@include` inlines a whole file,
  `<type> include` pulls in one management group, and confusing them either
  drops three quarters of a Debian host's rules or imports password rules into
  the auth stack. Both distribution layouts are always probed, so the layout is
  read from what is there rather than guessed. Control flow is deliberately
  **not** simulated: implementing the bracketed `[success=1 default=ignore]`
  jump semantics wrongly would produce confident verdicts about which module
  actually runs.
- Red Hat's `/etc/pam.d/system-auth` is a symlink on every stock install, which
  the seam's `O_NOFOLLOW` correctly refuses. The collector resolves the chain
  explicitly through `Readlink` — one observed hop at a time, bounded, each
  recorded — and cites the resolved file, because citing the link would send an
  operator to edit something authselect overwrites. Without this the module
  would report UNKNOWN across the entire Red Hat family.
- **LOGGING module (WP-20), 5 checks.** Catalog version 8. rsyslog log file
  permissions (LOGGING-0001), remote forwarding configured (0002), persistent
  journal storage (0003), journald-to-rsyslog forwarding (0004), and a reliable
  forwarding transport (0005).
- `logging.rsyslog` and `logging.journald` facts. **Both of rsyslog's
  configuration languages are parsed**: the sysklogd legacy format
  (`*.* @@host`), rsyslog's own `$Name value` directives, and RainerScript
  objects (`action(type="omfwd" ...)`), including statements that span several
  lines. All three appear in the same file on a stock Debian or RHEL host, and
  a parser reading only one would report a correctly-forwarding host as not
  forwarding. Which language a statement was written in is preserved into the
  fact, because a finding has to quote the operator's file back in the language
  it is actually written in.
- The journald fact records whether `/var/log/journal` exists. `Storage=auto`
  is the default and its effect is a property of the filesystem rather than of
  the configuration; without that one stat, "Storage is not configured" would
  be UNKNOWN on the majority of hosts.
- **journald precedence is last-wins**, the reverse of `sshd_config`: systemd
  drop-ins override the main file. `Journald.Overridden()` lets a finding cite
  the replaced occurrences so a reader who edited the main file can see why
  their value is not in force.
- `testdata/fixtures/cli-host` gains a compliant logging configuration. Unlike
  the CRON checks, these read file *contents* rather than ownership, so the
  baseline can exercise them rather than skipping the module.
- **CRON module (WP-19), 5 checks.** Catalog version 7. `/etc/crontab`
  ownership and write permissions (CRON-0001), the five drop-in directories
  (0002), access restricted by an allow list (0003), the access-control files'
  own permissions (0004), and schedule disclosure (0005).
- `cron.files` fact — file metadata only. **No crontab contents are collected.**
  Every check in the module asks who may *write* the schedule, not what it says,
  and a crontab's command lines carry script paths, hostnames and occasionally
  credentials passed as arguments. That is ADR-0015's reasoning applied before
  the mistake rather than after it.
- **ADR-0016** formalises `system.FileInfo`'s ownership fields as a verdict
  input. `UID` and `GID` have been in the seam since the initial slice, added
  for the walker; CRON is the first module whose PASS or FAIL rests on a uid
  comparison, and that promotion carries obligations. Chiefly: **uid 0 cannot
  double as "not recorded"** the way inode 0 does for `Dev`/`Ino`, because 0 is
  precisely the value an ownership check tests for and an unrecorded zero would
  read as "owned by root". Facts carrying ownership carry an explicit state
  beside it.
- `unstattable` fixture-manifest key, distinct from `unreadable`. A file at mode
  0640 is unreadable and perfectly stat-able; what defeats a stat is a parent
  directory refusing traversal. Without the distinction the CRON module's
  `UNKNOWN(insufficient_privileges)` branch had no way to be reached from a
  fixture.
- golangci-lint pinned to v1.64.8 in CI. The config is v1 format, so `latest`
  would silently move the linter to a major that cannot read it — which is how
  the G304 exclusion went missing once already.
- **SSHD module (WP-18), complete at 19 checks.** Catalog version 6.
  - Authentication: `PasswordAuthentication` (SSHD-0003), `PermitEmptyPasswords`
    (0004, the module's only CRITICAL), `MaxAuthTries` (0006), `IgnoreRhosts`
    (0013), `HostbasedAuthentication` (0014), `StrictModes` (0019), `UsePAM`
    (0020)
  - Forwarding and session environment: `X11Forwarding` (0005),
    `AllowTcpForwarding` (0008), `PermitUserEnvironment` (0015),
    `AllowAgentForwarding` (0018)
  - Session lifetime: `ClientAliveInterval` × `ClientAliveCountMax` (0007),
    `LoginGraceTime` (0016)
  - Logging and notice: `LogLevel` (0009), `Banner` (0017)
  - Cryptography: `Ciphers` (0010), `MACs` (0011), `KexAlgorithms` (0012)
- **`Match` blocks that loosen a secure global setting are reported as
  conditional failures**, one severity class below a global misconfiguration,
  with the `Match` criteria quoted in the detail. Reporting PASS would have been
  false assurance — the insecure state is reachable — and reporting FAIL at full
  severity would have overstated an exposure limited to a named subset of
  connections. Only the twelve keywords `sshd_config` actually permits inside a
  `Match` block are treated this way.
- **The three algorithm-list checks return UNKNOWN when the keyword is absent,
  not PASS.** The effective `Ciphers`, `MACs` and `KexAlgorithms` lists are
  compiled into the sshd binary, changed between OpenSSH releases, and are
  rewritten by Red Hat's `crypto-policies`; Plumbline does not read the binary's
  version, so asserting the default would be a guess. A relative form (`+`, `-`,
  `^`) inherits the same unknowability — except that a `+` or `^` adding a broken
  algorithm is a definite FAIL, because that algorithm is enabled whatever the
  base list holds. Same asymmetry as ADR-0014.
- **USERS module (WP-17), complete at 10 checks.** Catalog version 4 introduced
  the module; 5 completes it.
  - Accounts: root uid uniqueness (USERS-0001), system-account shells (0002),
    empty passwords (0003), password hash algorithms (0004), duplicate uids and
    names (0005), legacy NIS import entries (0006)
  - Groups: group 0 confined to root (0007), duplicate gids and group names
    (0008)
  - Password aging: bounded maximum age (0009), minimum age set (0010)
- `users.shadow` records the minimum and maximum age fields as **pointers**. An
  empty field is not a zero: an empty maximum means the password never expires,
  while a maximum of 0 would mean it expires daily, and a parser conflating them
  would report the most permissive setting in the file as the strictest
- `users.group` records NIS compatibility lines, so a negative assertion over
  the group database is held to the same completeness standard as one over
  `/etc/passwd`
- `users.passwd`, `users.shadow` and `users.group` facts — three facts rather
  than one, because an unprivileged scan can read two of the three files and a
  single fact would let the unreadable one erase them
- **KERNEL module (WP-16), complete at 16 checks.** Catalog version 2
  introduced the module, 3 completes it.
  - Memory and process protections: ASLR (KERNEL-0001), `kptr_restrict`
    (0002), Yama `ptrace_scope` (0003), `dmesg_restrict` (0004),
    `suid_dumpable` (0005), unprivileged BPF (0006),
    `perf_event_paranoid` (0013)
  - Filesystem race protections: `protected_symlinks` (0009),
    `protected_hardlinks` (0010), `protected_fifos` (0011),
    `protected_regular` (0012)
  - Core dump destination (0014) — the module's first non-integer parameter
  - Network stack: per-interface reverse-path filtering (0008),
    per-interface source routing (0015), TCP SYN cookies (0016)
  - Configuration drift between the running kernel and its own sysctl files
    (0007)
- `kernel.sysctl` fact — running values from `/proc/sys` **and** configured
  values from `/etc/sysctl.conf` and the `sysctl.d` directories, kept as
  separate observations. A host whose file says hardened and whose kernel says
  otherwise is the finding KERNEL-0007 exists to make
- Shared filesystem walker (`internal/collect/walker`) and the `fswalk`
  collector: one traversal per scan, no matter how many modules ask about the
  filesystem. Consumers register interest predicates up front and the walk
  evaluates all of them per inode in a single pass
- `fs.<interest>` facts — one per registered interest (`fs.suid`,
  `fs.world_writable`, …), each carrying the walk's truncation marker and its
  own overflow count
- Fixture manifests can describe inode identity (`inodes`) and file type
  (`modes` type prefixes), so a bind-mount cycle, a character device and a SUID
  binary are expressible without root (ADR-0013)

### Changed
- **The check-purity gate matches import *lines* rather than any occurrence of
  a quoted path.** SERVICES-0003 is about clock synchronisation so its tags
  include `"time"`, which the old grep read as an import of the `time` package.
  That is the same false positive the `net` pattern was already fixed for, and
  a gate that cries wolf is one somebody eventually silences. All nine
  forbidden import forms — bare, aliased, blank, dot, `net/...`,
  `internal/system` — were verified to still fire.
- **`system.FileInfo.LinkTarget` is removed.** It had been in the struct since
  the initial slice and nothing ever populated it. Left beside a working
  `Readlink` it is the trap ADR-0016 was written about: a future collector
  reads it, gets `""`, and concludes the path is not a link, in code that
  compiles and passes review. Not a schema change — `system.FileInfo` never
  reaches a fact or a bundle.
- `fs.mounts`, `services.units`, `network.firewall` and `auth.pam` are
  registered in the bundle decoder, so a saved bundle re-evaluates to the same
  findings as the scan that produced it. The omission was caught by
  `TestSaveBundleFromScan`, which is what that test exists for.
- `testdata/fixtures/cli-host` gains systemd enablement symlinks (real and
  **relative**, so they resolve inside the tree no matter who follows them), a
  firewall configuration, a PAM stack, and a mount table. It now measures 73
  pass / 5 fail over 78 checks at coverage 100.
- **`cmd/plumbline`'s offline test compares an offline scan against an online
  scan of the same fixture** instead of asserting every finding passes. The old
  assertion was a proxy and it broke for a reason unrelated to networking: the
  CLI fixtures are read through the *live* seam, so their files carry the
  ownership of whoever checked the repository out, and git cannot record
  ownership. Both runs go through `unshare -r` and only the offline one adds
  `-n`, because `-r` maps the calling uid to 0 inside the namespace — a bare
  online run would differ in identity as well as in networking.
- `testdata/fixtures/cli-host` is documented as a **realistic checkout
  baseline**, not a clean host. "Clean" for it means the scan exits 0, not that
  it produces no findings; the CRON ownership checks fail over it permanently
  and by construction.
- The required-fact gate attaches evidence when a fact error names a path, so a
  check that resolves to UNKNOWN because a file was unreadable now cites that
  file. `DATA-MODEL.md` §5.5 has always required every UNKNOWN to carry
  evidence; the gate was the one path that did not
- `KERNEL-0008` and `KERNEL-0015` combine `conf.all` with each interface's own
  value by the rule the kernel actually uses — `max()` for `rp_filter`,
  logical `AND` for `accept_source_route`. The two point in opposite
  directions, and a host with `conf.all.accept_source_route = 0` refuses
  source routing however its interfaces are set
- The check-purity gate matches the net **import** forms (`"net"`, `"net/`)
  rather than any string beginning with `net`. A sysctl key is called
  `net.ipv4.conf.all.rp_filter`; the old pattern reported it as an impure
  import, and a gate that cries wolf is a gate someone eventually silences
- `fake`'s `modes` override is translated rather than cast: `"4755"` now
  produces a setuid file instead of silently producing `0755`. A fixture that
  asked for SUID and quietly did not get it now gets it, which may turn a
  passing test into a failing one — that is the bug being fixed
- Bundle reads decode the `fs.*` namespace by prefix, so a walker fact
  re-evaluated from a bundle stays typed rather than falling back to
  `UnknownFact`


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

### Check corrections
None beyond the SSHD-0002 correction recorded above. Every other check in this
release is new.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
