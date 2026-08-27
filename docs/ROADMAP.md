# ROADMAP — Plumbline

**Three stable majors.** Each is a complete, defensible product on its own. If development stops after any of them, what exists is still worth using.

> **Where the project actually is — 2026-08-20.** `v0.4.0` is tagged: **79
> checks across nine modules at catalog version 13**, a human-readable terminal
> report by default with `--json` for pipelines, and a scanner that refuses to
> draw a verdict from a file it could not really parse. The output schema is
> `findings-v1`, and the tool runs offline with no network code path in any
> build.
>
> `v0.4.0` added the three things that make a scan worth running twice: a
> lynis-style terminal report, explicit `--suppress` acknowledgement of accepted
> risks, and `plumbline diff` between two bundles. The catalog did not move —
> every verdict is one `v0.3.1` would have reached. Go's floor is 1.24 and CI
> builds with 1.25.
>
> **`v0.3.0` was re-scoped on the way to being tagged.** It was originally
> "feature complete for v1" and shipped four of eighteen items; feature freeze
> now belongs to `v0.4.0`, which carries the other fourteen. The reasoning is
> recorded in the milestone below rather than left to be inferred from a
> diff.
>
> This banner is updated by **every** work package that changes a module, a
> check count or a catalog version. A roadmap that disagrees with `main` is
> worse than no roadmap, because people plan against it.

Effort figures assume one developer working part-time (~15 h/week) and are estimates, marked as such — unlike the source design, which stated durations for software that did not exist.

---

## Shape of the plan

| Release | Theme | Scope in one line | Est. effort |
|---|---|---|---|
| **v1.0.0** | *Trustworthy core* | Linux host auditing that is correct, testable and offline | ~4–6 months |
| **v2.0.0** | *Intelligence* | Vulnerabilities, containers, remediation, evidence for auditors | ~6–8 months |
| **v3.0.0** | *Reach* | Extensibility, macOS, fleets, stable public API | ~6–9 months |

Pre-1.0 there are four internal milestones (v0.1 – v0.4) that are *not* public stable releases. They exist to force integration early; the source design's eight 0.x milestones were a plan to build eight products before shipping one.

There were three until v0.3.0 was tagged. The fourth exists because v0.3.0 shipped four of the eighteen items it had been scoped for, and re-scoping the milestone was the honest response — releasing on the original terms would have meant declaring feature freeze over a tool with no suppression file and no `diff`.

---

## Pre-1.0 internal milestones

Tagged and released as pre-releases so the pipeline gets exercised, but with an
explicit "no stability guarantees" banner.

**Status at 2026-08-20:** v0.1.0, v0.2.0, v0.3.0, v0.3.1 and v0.4.0 are
complete and tagged. v0.5.0 is next and is the last feature milestone before
v1.0.0. The schema is `findings-v1` throughout.

| Milestone | State | Catalog | Checks | Shipped |
|---|---|---|---|---|
| v0.1.0 — walking skeleton | **complete** | 1 | 8 | tagged `v0.1.0` |
| v0.2.0 — catalog machinery | **complete** | 11 | 78 | tagged `v0.2.0`, 2026-08-20 |
| v0.3.0 — engine maturation and resilience | **complete** | 13 | 79 | tagged `v0.3.0`, 2026-08-20 |
| v0.3.1 — verification harness repairs | **complete** | 13 | 79 | tagged `v0.3.1`, 2026-08-20; no behaviour change |
| v0.4.0 — usable more than once | **complete** | 13 | 79 | tagged `v0.4.0`, 2026-08-20 |
| v0.5.0 — ecosystem integration | **in progress** | 13 | 79 | WP-31 SARIF; WP-32 `explain`; WP-33 profiles |

### v0.1.0 — Walking skeleton — **COMPLETE**

The thinnest possible end-to-end path, chosen so that every architectural risk
was hit on day one rather than month four. Every item below is in `main`.

- [x] `System` interface + `live` and `fake` implementations, with `--root`
      prefixing and the escape-refusal rule
- [x] Bundle format: write, read, integrity manifest, evidence store
- [x] Collectors: `osrelease`, `users` (passwd/shadow/group), `sysctl`, `sshd`
- [x] Checks across AUTH and SSHD
- [x] `plumbline scan`, `collect`, `eval` working end to end
- [x] JSON renderer + published schema
- [x] Fixture harness, one directory per scenario
- [x] CI: build, vet, test, race

**Exit criteria — met.** `collect` on a real host → `eval` elsewhere → identical
findings across two runs, asserted byte-for-byte by a test.

**What the milestone actually taught us**, recorded because it changed the
design and not just the schedule:

- The seam had to be an interface *and* a rule enforced mechanically.
  `make check-system-seam` exists because a single `os.ReadFile` in a check is
  invisible in review and fatal to fixture testing.
- `UNKNOWN` needed to be a first-class result with a mandatory reason code
  before check #10, not after. Retrofitting it would have meant re-auditing
  every check written before it.
- Operator-named paths (the bundle) must **not** go through the `--root`
  prefix, which is why `localfile.go` sits off the interface (ADR-0011).

### v0.2.0 — Catalog machinery — **COMPLETE** *(tagged 2026-08-20)*

- [x] The single-pass filesystem walker with interest predicates, plus the
      hostile-fixture corpus — FIFOs, 40-deep symlink chains, ANSI filenames,
      100 MB files, cyclic bind mounts — generated at test time, not committed
- [x] Collector DAG with cost classes, budgets and per-collector error capture
- [x] All five result states wired through, including `UNKNOWN` propagation
      from `FactError`
- [x] Scoring: posture + coverage, both able to be undefined; catalog version
      stamped into every score and bundle
- [x] Control-character sanitisation as a security control (T-03)
- [x] **78 checks across nine modules** (target was ~45 across four)
- [x] Golden-bundle round-trip: save a scan, re-evaluate it, identical findings

**Exit criteria — met.** The hostile corpus produces zero hangs, zero panics
and zero unbounded reads; the walk terminates on cycles by device+inode
identity rather than by giving up at a depth limit (ADR-0012).

#### Catalog as shipped in v0.2.0

| Module | Checks | What it rests on |
|---|---|---|
| `SSHD` | 19 | effective config: `Include` resolution, `Match` blocks, compiled defaults |
| `KERNEL` | 16 | `sysctl`, module blacklists, boot parameters |
| `USERS` | 10 | `/etc/passwd`, `/etc/shadow` (properties only, never hashes), `/etc/group` |
| `FILESYS` | 9 | the shared walk + `/proc/self/mountinfo` |
| `AUTH` | 6 | the PAM stack as a graph: `@include`, `include`, `substack` |
| `CRON` | 5 | `crontab`, `cron.d`, per-user spools |
| `LOGGING` | 5 | rsyslog, journald |
| `SERVICES` | 5 | systemd enablement **symlinks**, read offline; masking outranks enablement |
| `NETWORK` | 3 | nftables, iptables-save, ufw, firewalld — local state only |
| | **78** | catalog version 11 |

#### Deliberate reductions, recorded so they are not rediscovered as bugs

- **Check count came in at 78 against a v1 ceiling of ~110.** The gap is
  entirely checks that would have needed an allowlist of blessed binaries,
  package names or service names. The v0.2 work plan forbade a name
  list that "silently excuses a real finding", and the substitute — asserting a
  property no legitimate subject has — does not exist for every rule. Correctness
  is not the flex; check count is.
- **`SYSINFO` was not built.** Six informational, never-scored checks are the
  cheapest thing in the plan and the least useful; they are v0.3 filler.
- **`NETWORK` shipped 3 checks against a planned 12.** Listener enumeration
  needs `/proc/net/tcp` plus a socket-inode-to-process join, which is a
  collector, not a check. It is scheduled in v0.3.
- **`AUTH` shipped 6 against a planned 17.** PAM parsing was the hard part, as
  the risk table predicted; the graph model landed but the checks over it did
  not. The remaining eleven are mechanical now that the model exists.

### v0.3.0 — Engine maturation and resilience — **COMPLETE** *(tagged 2026-08-20)*

**This milestone was re-scoped, and the re-scoping is recorded rather than
quietly applied.** v0.3.0 was originally "feature complete for v1", with
eighteen items and feature freeze as its exit criterion. Four shipped. The
three that were built are substantial and coherent — they are the engine, the
output and the failure modes — but SARIF, `diff`, suppressions and `doctor` are
features, so freezing here would have been a claim nobody could act on.
**Feature freeze moves to v0.4.0**, which carries the fourteen items this
milestone did not.

The alternative was to hold the tag until all eighteen were done, and that is
worse: it makes the pre-release milestones stop exercising the release pipeline,
which is the only reason they exist.

#### What shipped

- [x] **Aggregating walker interests** *(WP-25)*. The walk recorded rows: the
      first N inodes matching a pure predicate. That answers "show me the
      setuid binaries" and cannot answer "does every uid on disk resolve to an
      account" — the join is against a fact that does not exist when the
      predicate is registered, and recording every owned inode to defer the
      join would overflow the row cap on any host that has users. A `Tally`
      folds inodes into a bounded keyspace during the walk, so cost is the
      number of *distinct owners* rather than the number of inodes and the join
      happens in the check. Fact namespace `fs.tally.<name>`
- [x] **Name-service awareness** *(WP-25)*. `users.nsswitch`. `/etc/passwd` is
      a file; the *account database* is whatever `nsswitch.conf` routes
      `passwd` to. Four USERS specs had named this as a known limitation before
      the fact existed
- [x] **FILESYS-0010, unowned files** — the check the aggregation was built
      for, and the first that can conclude an identity does not exist
- [x] **Terminal renderer, and it is the default** *(WP-26)*.
      `internal/render/text`: header, per-module listing, a full block for
      every FAIL *and* every UNKNOWN, and a summary that states the UNKNOWN
      count on its own line. `--json` keeps the pipeline path. No dependency —
      plain SGR sequences and `text/tabwriter`
- [x] **Malformed and corrupted input** *(WP-27)*. Every parser gates on
      `collect.NotText` before parsing; `SSHDConfig.SyntaxErrors` records lines
      `sshd -t` rejects, so a config sshd would refuse to load no longer
      reports compiled-in defaults; `fact.Opaque` closes the gap where a fact
      this build could not decode was read as the zero value and reported as
      "not configured on this host"

**Exit criteria — met on the re-scoped terms.** A host with four kilobytes of
random bytes in every configuration file produces zero `PASS` or `FAIL` from
any content-reading module, names every unparseable file in `fact_errors`, and
does not panic. Before WP-27 the same host produced 22 `PASS`, 23 `FAIL` and
**no fact errors at all**.

#### What this milestone taught us

- **Robustness and honesty are different properties, and only one of them was
  tested.** No parser panicked on binary input; every one of them silently
  produced an empty, confident fact. An empty configuration satisfies every
  negative assertion in the catalog, so "does not crash" was hiding "reports a
  clean host". The probe that found it took ten minutes and should have been
  written in v0.1.
- **A gate applied at every call site is a gate that gets forgotten.** Three
  checks bypassed their module's shared funnel and so carried none of its
  guards — including SSHD-0002, which is the module's own reference
  implementation. The fix is module-wide tests that loop over every check, not
  more careful authors.
- **A reason code that nothing produces is a reason code that does not work.**
  `finding.ReasonFactVersion` had been declared since v0.1 and was never once
  emitted; the case it was for reported `NOT_APPLICABLE` instead.

### v0.4.0 — Usable more than once — **COMPLETE** *(tagged 2026-08-20)*

Everything v0.3.0 did not carry, in the order it should be built. The ordering
is not the original one: it now leads with what makes the tool *usable more
than once* rather than with what adds to it.

**Started 2026-08-20 with WP-28, a CLI visual overhaul.** The terminal report
is now laid out in the manner of `lynis`: a scan phase of one line per check
under `[+] MODULE` headings, each carrying a bracketed verdict flush against a
fixed 78-column grid (`[ OK ]`, `[ WARNING ]`, `[ UNKNOWN ]`, `[ SKIPPED ]`,
`[ DISABLED ]`), and a `[=] Warnings and suggestions` phase at the bottom that
carries every detail, evidence excerpt and remediation. The previous layout
interleaved the two, which put forty lines of advice between two check results
and destroyed the column of verdicts the layout exists to provide. `UNKNOWN`
keeps its own heading at equal weight in the suggestion phase — the detail
moved, the emphasis did not. See `docs/CLI-SPEC.md` §Output.

#### 1. Make a repeat scan survivable

- **Suppression file format — DONE (WP-29, 2026-08-20).** `--suppress` applies
  a `suppressions/v1` file; a suppressed finding becomes `SKIPPED`, carries its
  justification and the result it would otherwise have had, and appears under
  `[=] Accepted risks`. Expiry is measured against the scan's start time so an
  archived bundle re-evaluates identically forever. Specified in `CLI-SPEC.md`
  §Suppressions and `DATA-MODEL.md` §5.6.

  *Original scoping:* The single largest adoption blocker. A team that
  has accepted a finding must be able to say so, or the second scan reports the
  same thing as the first and people stop reading it. Suppressions carry a
  reason and an expiry, and a suppressed check is reported as `SKIPPED` with
  that reason, **never omitted** — a suppression that silently removes a
  finding is how a finding gets lost, which is the same failure this project
  refuses everywhere else. De-risked by `finding.Fingerprint`, which is already
  stable and frozen.
- **`plumbline diff` — DONE (WP-30, 2026-08-20).** `plumbline diff OLD NEW`
  re-evaluates both bundles with today's catalog and reports only what moved,
  in five categories, with a posture delta beside a coverage delta. Suppression
  state is part of the comparison: a lapsed acceptance shows as `REGRESSED`
  rather than as a new failure. Specified in `CLI-SPEC.md` §4.

  *Original scoping:* bundle to bundle. Bundles already exist and are
  already byte-deterministic, so this is the payoff of a design that is
  finished rather than new work on it.
- **Exit code contract tested per branch.** Partly covered; the ladder needs a
  test per rung, not per scenario.

#### 2. Make the catalog legible

- **`check list` / `show` / `explain`.** The catalog is the product and is
  currently readable only by reading Go, or by reading `docs/checks/` and
  trusting it matches.
- **`plumbline doctor`** — what a scan could and could not see, *before* it
  runs: euid, readable paths, missing collectors, budget headroom. The natural
  companion to a tool whose distinguishing output is `UNKNOWN`.
- **SARIF renderer** with stable fingerprints across runs and catalog versions.
  Deliberately after suppressions: SARIF is an integration format, and it
  matters once people run the tool regularly, which suppressions gate.

#### 3. Platform reality

Started early, because none of it can be back-filled quickly and all of it is a
v1 release criterion.

- **musl and Alpine in CI.** `live` uses `syscall.Stat_t` and `O_NOFOLLOW`;
  neither is guaranteed to behave identically, and every week this is deferred
  is a week of accumulating glibc assumptions.
- **`--root` against a real mounted image and a container filesystem.** The
  escape-refusal rule has unit tests and has never met a real overlayfs.
- **Golden bundles for ≥6 distro/version combinations.** ✅ Done in WP-34; see `testdata/bundles/README.md`.
- **Determinism under adversarial ordering** — hostile directory-entry order,
  duplicate mount points, `..` in mountinfo fields.
- **Budget behaviour on a genuinely large host** — 2M+ inodes, asserting that a
  fired budget produces `UNKNOWN` rather than a truncated scan reporting `PASS`.

#### 4. Catalog toward the v1 ceiling

- **Listener enumeration** — `/proc/net/{tcp,tcp6,udp,udp6}` plus the
  socket-inode-to-process join through `/proc/*/fd`. Unlocks the NETWORK checks
  cut from v0.2.
- **Package inventory** — dpkg and rpm database reads, no CVE claims. What
  `INTEGRITY` and the whole of v2 rest on.
- **`SYSINFO`, the AUTH balance, the NETWORK balance, FILESYS mount coverage.**

**Exit criteria (met 2026-08-20):** a scan is worth running twice. The report
is readable, findings can be accepted without being hidden, and two runs can be
compared.

---

### v0.5.0 — Ecosystem integration — **NEXT**

The last feature milestone before v1.0.0, and the theme is that Plumbline stops
being a tool you read and starts being a tool other things consume. Everything
here is about handing a verdict to something else — a CI platform, a colleague,
an auditor — without losing what makes the verdict honest.

**Exit criteria:** feature freeze. Everything after v0.5.0 is bug-fixing,
documentation and fixture expansion.

#### 1. SARIF export — **DONE (WP-31, 2026-08-20)**

Shipped. `--format sarif` emits SARIF 2.1.0 on both `scan` and `eval`; the
mapping is fixed in **ADR-0018**. What follows is the reasoning that produced
it, kept because it is the argument, not the implementation.

`--format sarif`, emitting SARIF 2.1.0 for GitHub Advanced Security and
anything else that ingests it. Rule IDs are check IDs and `partialFingerprints`
carries `finding.Fingerprint`, so GitHub's deduplication lines up with the
suppression baseline rather than fighting it.

**The whole design problem is `UNKNOWN`, and SARIF has no such level.** The
levels are `error`, `warning`, `note` and `none`, and the obvious mappings are
both wrong: `none` files an UNKNOWN as informational and `error` claims a
failure that was never observed. Either way the security tab shows a cleaner or
a falser host than the scan saw, which is the one thing this project does not
do.

The decision: **`UNKNOWN` maps to `level: "warning"`**, with the reason code in
the message text and a `properties` bag carrying `plumbline/result: "UNKNOWN"`
and the reason, so a consumer that cares can tell the two apart and one that
does not still sees something it must look at. `FAIL` maps by severity —
CRITICAL and HIGH to `error`, the rest to `warning`. `SKIPPED` from a
suppression is emitted with `suppressions` (SARIF has a native concept, and it
carries a justification), which is the one place the SARIF model matches ours
exactly. `PASS` and `NOT_APPLICABLE` are not emitted as results at all; they
belong in the run's `invocation` properties, not as findings.

`schema/` gains no new file: SARIF is an external specification and validating
against the published one in CI is the correct gate, not a copy of it here.

#### 2. `plumbline explain CHECK-ID` — **DONE (WP-32, 2026-08-20)**

Catalog legibility. Prints what a check asks, which facts it needs, what each
result state means for it, and the remediation in full — the material that
`docs/checks/<ID>.md` holds today and that nobody reads because it is not where
they are. Offline, no host access, no bundle required: it is a question about
the catalog, not about a machine.

This is also the honest home for the remediation `steps` and `commands` that
the terminal report deliberately omits. A block that runs to forty lines per
finding is one an operator scrolls past; a command they asked for by ID is one
they read.

#### 3. Profile architecture and golden bundles — **DONE (WP-33 and WP-34, 2026-08-21)**

`--profile cis-level-1`, `--profile stig`, and the machinery that makes a
profile a *selection over the existing catalog* rather than a second catalog.
A profile names check IDs and may tighten a parameter; it may never introduce a
check the catalog does not have, because a finding that exists only under one
profile is a finding nobody can reproduce.

Golden bundles are the fixture half: recorded bundles from real distributions,
committed, and re-evaluated in CI so that a catalog change which moves a
verdict on a real host shows up as a diff in review rather than as a surprise
in production. `docs/FIXTURES.md` §6 reserved the concept; WP-34 implemented it.

Six bundles ship in `testdata/bundles/`, covering glibc and musl, dpkg and rpm,
systemd and OpenRC: Ubuntu 24.04 stock and hardened, Debian 13, Fedora 44,
Rocky 9 and Alpine 3.20. `TestGolden` re-evaluates all six on every
`make verify`, against per-check expectation files and against posture and
counts typed out by hand — the second gate exists because the first can be
satisfied by running the same command that reports it.

The hardened bundle is the one that carries the catalog: **every check in the
catalog reaches a real verdict on it**, which no fixture and no stock base image
manages alone. It also closes the v1.0.0 criterion below, three milestones
early.

---

## v1.0.0-rc — Release candidates

**The promise:** *no new capability, only the polish that decides whether the
capability is usable.*

The catalog, the schema and the output formats are frozen from `rc1`. What
changes is what an operator experiences, what a maintainer can rely on, and
what the documentation actually says.

#### RC-1. A progress indicator for `scan` and `collect` — **DONE (2026-08-21)**

Collection is the slow half of a scan and it was the silent half. A transient
one-line indicator now runs on stderr while the collectors do, and erases
itself before the report starts. Four conditions must all hold or nothing is
drawn: stderr is a character device, `PLUMBLINE_NO_PROGRESS` is unset, `TERM`
is set and not `dumb`, and no CI marker is present. CLI-SPEC.md §7 carries the
contract.

#### RC-2. Graceful signal handling — **DONE (2026-08-21)**

`SIGINT` and `SIGTERM` cancel the collection context, the collection phase
unwinds, the RC-1 indicator erases itself, and the run exits 130 — the code
CLI-SPEC.md §6 reserved from the beginning and nothing produced. A Ctrl-C
part-way through a walk of `/` unwinds in about 30ms.

An interrupted run produces no artifact: no findings document, no
`--save-bundle`, no bundle from `collect`. Stricter than the `--timeout` path,
which keeps what it collected, and CLI-SPEC.md §6.1 says why.

#### RC-3. `os_release` symlink resolution — **DONE (WP-37, 2026-08-21)**

`/etc/os-release` is a symlink on every systemd distribution, the seam refused
it under `O_NOFOLLOW`, and the field was silently blank on the four most common
Linux distributions. Resolved explicitly and bounded, without weakening the
seam, through one shared `collect.ResolveLinks` that the AUTH collector's Red
Hat PAM walk now uses too.

#### RC-4/RC-5. Terminal dashboard, and the supply chain it nearly cost — **DONE (2026-08-21)**

The scan summary became a posture gauge and four count cards. It shipped on
`lipgloss` in RC-4 and was rewritten without it in RC-5: the library
contributed a box border, a horizontal join and a hex downsample, and cost
thirteen modules in a binary that runs as root. **The dependency count is back
to four and the dashboard is byte-identical.** `internal/render/text` already
had the hard part — `visibleWidth`, which measures a string containing SGR
escapes.

RC-5 also added `tools/gendocs`, which generates `MODULE-CATALOG.md` and
`CHECK-REFERENCE.md` from `cli.Catalog()` with a freshness gate in
`make invariants`, and `.goreleaser.yaml` covering linux/amd64 and linux/arm64,
`.deb` and `.rpm` packages, syft SBOMs and keyless cosign signing.

#### RC-6/RC-7. Delivery, front door and baseline — **DONE (2026-08-21)**

`.github/workflows/release.yml` runs GoReleaser on a tag; `v1.0.0-rc1`
published signed `.deb`, `.rpm` and `.tar.gz` for both architectures with an
SBOM each, and the cosign verification in the README was run against the live
artifacts rather than transcribed. The README was rebuilt as a landing page,
and `docs/PERFORMANCE.md` carries the measured baseline.

**The RC phase is complete.**

---

## v1.0.0 — Trustworthy core — **SHIPPED 2026-08-21**

**The promise:** *Every finding is reproducible from a bundle you can keep, and the tool tells you what it could not see.*

### Scope

| Area | In | Out |
|---|---|---|
| Platforms | Linux, glibc + musl: Ubuntu 22.04/24.04, Debian 12/13, RHEL/Rocky 9, Fedora, Alpine, Arch | macOS, all BSD, Solaris, Windows |
| Architectures | amd64, arm64 (both in CI) | arm32, 386, riscv64 |
| Modules | 10 (below) | CONTAINERS, CLOUD, MALWARE, PRIVESC, MACOSEC, MEMORY, INTEGRITY |
| Checks | ~110 | — |
| Outputs | terminal, JSON, SARIF | HTML, PDF, CSV, YAML, JUnit |
| Compliance | Reference mappings to NIST SP 800-53 r5 and DISA STIG only, as bare control identifiers | CIS, PCI-DSS, ISO 27001, HIPAA, SOC 2, GDPR; **all** compliance scoring |
| Vulnerabilities | Package inventory only, no CVE claims | CVE correlation |
| Remediation | Text steps + commands inside findings | Generated scripts, Ansible, auto-apply |
| Network | None in any code path | — |
| Extensibility | None | Plugins of any kind |

### Modules and approximate check counts

| Module | v1 target | Shipped at v0.2.0 | Notes |
|---|---|---|---|
| `SYSINFO` | 6 | **0** | Informational facts; never scored. Not started |
| `KERNEL` | 15 | **16** | sysctl-driven, deterministic, easy to fixture |
| `AUTH` | 17 | **6** | PAM parsing was the hard part, as predicted. The graph model landed; the checks over it are the remaining work |
| `USERS` | 10 | **10** | Complete |
| `SSHD` | 20 | **19** | Resolving `Include`, `Match` blocks and compiled defaults was the real work, and it is done |
| `NETWORK` | 12 | **3** | Firewall state only so far. Listeners need a `/proc/net/*` collector, not a check |
| `SERVICES` | 10 | **5** | systemd enablement symlinks read offline. OpenRC and sysvinit degrade gracefully but have no checks |
| `FILESYS` | 14 | **9** | Consumes the shared walk. Unowned files needed walker aggregation and landed after the tag (WP-25) |
| `LOGGING` | 8 | **5** | |
| `CRON` | 8 | **5** | |
| | **~120** | **79** | 78 at v0.2.0 / catalog 11; 79 at v0.3.0 / catalog 13 |

**~120 checks was always a ceiling, not a target.** Cut to whatever fits the
schedule; check count is the flex, correctness is not. The 42-check gap at
v0.2.0 is accounted for module by module in the pre-1.0 section above, and none
of it is work that was forgotten.

### Release criteria

- [x] Every check has ≥1 PASS and ≥1 FAIL fixture; CI enforces
- [x] Zero panics across the full fixture and hostile corpus
- [x] Determinism test green: same bundle → byte-identical findings
- [x] Offline test green: full scan succeeds in a network-less namespace
- [x] Golden bundles for ≥6 distro/version combinations *(WP-34: six in `testdata/bundles/`)*
- [x] `findings-v1.schema.json` published, validated in CI, and frozen
- [x] Scan of a reference host measured and published *(`docs/PERFORMANCE.md`)*
- [x] Signed release artifacts + SBOM + provenance, and documented verification steps a user can follow
- [ ] **All v1-gating documents complete (`DOCUMENT-MAP.md` tier 0–4)** — 11 outstanding, down from 14 (WP-38)
- [x] `THREAT-MODEL.md` reviewed against the actual implementation, not the design *(WP-38, 2026-08-21)*

**One criterion remains unmet at `v1.0.0`**, and it is documentation rather than
behaviour. WP-38 closed the threat-model review and completed Tiers 0, 3 and 5 —
ten documents, including all seven user-facing ones. Eleven gating documents
remain, and `DOCUMENT-MAP.md` names each with the reason it is still open.

**The threat-model review was not a formality.** It found two places where the
document claimed a mitigation the code does not have: `openat2` described as
"scheduled for v1.0" when v1.0 shipped without it, and SLSA provenance, a
double-build reproducibility check and a verifying installer that do not exist
at all. Both entries are corrected rather than dropped, and the missing controls
are v1.1 work. A threat model that overstates its own coverage is worse than one
that admits a gap, because a reader plans around it.

Recording the remaining gap plainly, rather than marking it done because the tag
is cut, is the same discipline the tool applies to a host.

#### v1.1 — the controls v1.0.0 claimed and did not have

- **`openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)`** for atomic path
  resolution, closing the T-01 residual — the highest-priority residual risk in
  the threat model.
- **SLSA provenance** in the release workflow.
- **A double-build reproducibility check.** The build is deterministic by
  construction and verified by nothing.
- **An installer that refuses on a bad signature**, rather than verification
  steps a human is trusted to run.

- [ ] Known false positives documented per check in `FALSE-POSITIVES.md`
- [ ] At least one external person has run it and filed an issue

### Explicit non-goals for v1

Restating, because these are what the schedule is bought with: no TUI browser, no HTML, no PDF, no plugins, no CVEs, no compliance scores, no macOS, no container module, no remediation scripts, no daemon, no web UI, no hosted anything.

---

## MEMORY, started ahead of v2

`MEMORY` is a v2 module in the plan above and the first slice of it landed in
v1.x: the `memory.elf` collector and `MEMORY-0001` (PIE), catalog 14.

It went early because it is the one module on the v2 list that needs nothing the
v1 architecture does not already have. No network, no new dependency, no
privilege the scan does not hold, and no judgement a pure check cannot make from
a fact — the properties are static bits in a program header. That made it the
cheapest way to exercise the collector-and-check seam end to end before the
modules that do need new machinery arrive.

Two things it produced that outlive the module:

- **`System.ReadOpaque`.** A read whose bytes never enter the evidence store.
  It exists because binaries are large and unreadable-by-humans, and it is the
  seam `INTEGRITY` will want for package databases and `CONTAINERS` for image
  layers.
- **The recorded corpus now carries an `UNKNOWN` it cannot resolve.** Every
  golden bundle predates `memory.elf`, so `MEMORY-0001` is
  `UNKNOWN(fact_not_collected)` on all six. That is correct, and it is also the
  first concrete demonstration that adding a check devalues an old bundle's
  coverage. Re-recording needs docker; the question of how often the corpus
  should be re-recorded is now a real one rather than a hypothetical.

The module is now complete for what an ELF header and symbol table can answer:
`MEMORY-0001` (PIE), `MEMORY-0002` (full RELRO), `MEMORY-0003` (stack
protection) and `MEMORY-0004` (`_FORTIFY_SOURCE`), catalog 15.

Symbol-derived checks brought a limit the header-derived ones did not have. A
program header is present or it is not, and either way the file has answered. A
symbol's absence is only evidence if there was a table to be absent from, and
even then it is weaker than it looks: the compiler emits `__stack_chk_fail` only
for functions that needed a canary, and a binary from a memory-safe language
uses none of these mechanisms. Both are recorded in `docs/FALSE-POSITIVES.md`
and stated on the checks. Neither is fixable from a symbol table.

There is no `MEMORY-0005` planned. NX is collected and deliberately unchecked:
`PT_GNU_STACK` is absent on a meaningful share of real binaries, and the kernel
default it falls back to differs by architecture and version, so a check would
be `UNKNOWN` on exactly the hosts worth asking about. The fact carries the
tri-state for whoever wants it.

---

## CONTAINERS, started ahead of v2

The second v2 module to land early, and for the same reason as `MEMORY`: the
Docker daemon's configuration is one file, so reading it needs nothing the v1
architecture does not have. The collector reads `/etc/docker/daemon.json` into
`containers.docker_daemon`; `CONTAINERS-0001` (user-namespace remapping),
`-0002` (`no-new-privileges`), `-0003` (`icc`), `-0004` (`live-restore`) and
`-0005` (experimental features) judge it.

A second collector reads `docker.service` and its drop-ins into
`containers.docker_service`. `CONTAINERS-0006` judges the sockets on the
daemon's command line and `CONTAINERS-0007` the `hosts` key in `daemon.json` —
the module's two `CRITICAL`s, because a `tcp://` binding with no
client-certificate verification is an unauthenticated root-equivalent API and
not a weakened boundary. `CONTAINERS-0008` reads both files for one option —
the logging driver — and is the module's only `LOW`. Catalog 21, eight checks.

Six things it produced that outlive the checks:

- **The `NOT_APPLICABLE` gate is `Installed`, never the presence of the file.**
  A host with `dockerd` and no `daemon.json` runs on compiled-in defaults, and
  several of those are what a hardening check objects to. It is the most common
  Docker installation there is, and excusing it would leave the module silent on
  exactly the hosts it exists for. Every module that reads an optional config
  file will face this and should copy the shape.
- **`*bool` plus `fact.OptBool` for an option whose default is not `false`.**
  `icc` defaults to *true*, so a plain `bool` would decode an absent key as
  `false` and report an open bridge as a closed one. The tri-state is what makes
  "nobody wrote this down" expressible at all — and `CONTAINERS-0005` is what
  proves it is not a synonym for "failing": `experimental` defaults to off, so
  there an unwritten key is a pass. Same rule, opposite verdict, because the
  rule is about the daemon's default rather than about silence.
- **Every verdict states which file it read.** `dockerd` takes the same options
  as command-line flags and the stock unit passes some. The two cannot silently
  disagree — `dockerd` refuses to start when an option appears in both places —
  but a finding that claimed to describe the running daemon would be claiming
  more than the scan checked. Both caveats are now in the tree and they are
  mirrors: the `daemon.json` checks say a flag in the unit is invisible to
  them, and `CONTAINERS-0006` says a socket in `daemon.json` — or in
  `docker.socket` — is invisible to it.
- **A vendor file plus its drop-ins is not the same object as a file.** The
  vendor `docker.service` is byte-identical on an exposed host and a safe one;
  the whole of the difference is a `.conf` in a `.d` directory. Two systemd
  rules are load-bearing rather than decorative — a drop-in whose *filename*
  appears in a higher-precedence directory is dropped entirely, and the
  survivors apply in lexical order by filename across all directories — and
  getting either wrong moves verdicts. `INTEGRITY` and the v2 `CONTAINERS` work
  will meet the same shape in `containerd`'s and `crio`'s units.
- **One option in two files is one check split in two, not one check that reads
  two files.** `hosts` can be set on the command line or in `daemon.json`, and
  `dockerd` refuses to start when it is set in both — so on a running host at
  most one file decides, and a pair of checks with one subject each is
  exhaustive without double-counting. Each names the other in its own detail
  string, so a `PASS` from one is never read as covering both. What the pair
  must not do is disagree about what a socket specification *means*, which is
  why the reading of `dockerd`'s grammar is one file both import rather than
  two implementations that match today.
- **Names travel, values do not — one level below the top-level keys.** `Keys`
  established that a fact can record which options a document set without
  carrying what they were set to. `log-opts` is where that stops being a
  precaution: `splunk-token` is an authentication token and
  `awslogs-credentials-endpoint` is the path to one, so the values are never
  decoded at all. The test of whether the trade is affordable is whether the
  names still answer the question, and here they do — `json-file` is unbounded
  unless `max-size` is set. Where they would not, the answer is to record less
  and say `UNKNOWN`, not to record the value. Every nested-object option a
  later module models should be read this way first and widened only with a
  reason.

The module's honest limits are four, and all of them are worth stating plainly.

**The corpus.** All six golden bundles were recorded inside containers, so none
carries a Docker daemon: `CONTAINERS-0001` to `-0005` are `NOT_APPLICABLE` on
every one, and `-0006`, `-0007` and `-0008` are `UNKNOWN` on every one because
the bundles predate `containers.docker_service`. That is three `UNKNOWN` per
bundle from a single cause, and the coverage it costs is the corpus reporting
its own age rather than a defect to route around — declaring less than a check
reads would trade it for a `CRITICAL` false positive in `-0007` and a `LOW` one
in `-0008`. The fixtures cover the verdicts; nothing in the recorded corpus
does. Covering `CONTAINERS` against a real daemon needs a recording recipe that
installs one, which is a work package of its own, is the prerequisite for the
Podman and K8s-node work in v2, and now clears all three `UNKNOWN` at once.

**The third place a socket can be bound.** `CONTAINERS-0006` reads the unit's
`-H` flags and `-0007` reads `daemon.json`'s `hosts`. `docker.socket` has
`ListenStream=`, which is what the stock `-H fd://` actually listens on, and a
`tcp://` entry there exposes the API exactly as the other two would. Nothing
reads it yet; it is a sibling check rather than an extension of either, and
until it exists both verdicts say so in their own detail strings.

**Two files that cannot both be right.** `dockerd` refuses to start when
`hosts` is set as a flag and in `daemon.json` at once, and adding the key to a
stock installation is the well-known way to make Docker stop starting. Neither
check reports that conflict — each reads its own file and neither compares them
— so a host in that state is one whose daemon is not running and which both
checks describe as though it were. Detecting it is a check of its own.

**A credential can still reach a bundle through the one command line.**
`ExecStart=` is stored argument by argument because the flags on it decide the
API's exposure, and `dockerd` accepts `--log-opt` there as well as in
`daemon.json`. So `--log-opt splunk-token=…` in a drop-in travels, where the
`daemon.json` spelling of the same option has its value dropped. Nothing
redacts it today. The fix is narrow — replace the value of a log option this
build does not read with a visible marker in the recorded argv — and it is a
work package rather than a footnote, because it is the first place the tree
would deliberately record something other than what the file says, and the cost
lands on `CONTAINERS-0006`'s evidence excerpt. `docs/PRIVACY.md` states the
limit meanwhile.

**What the logging check cannot see.** `CONTAINERS-0008` reads the daemon's
*default* driver. A container started with its own `--log-driver`, or with a
`logging:` block in a compose file, overrides it for itself, and neither is in
either file or in any fact this build collects. Reaching those means inspecting
running containers, which is the v2 boundary rather than a gap in this check —
its detail strings say so.

What remains for v2 is everything that is not a configuration file: Podman's
configuration, K8s node hardening, and the checks that need to inspect running
containers rather than the daemon that would start them.

---

## v2.0.0 — Intelligence

**The promise:** *It tells you what is exploitable, not just what is untidy — and it is right about it more often than a naive scanner.*

Requires v1 to have been stable for at least one minor cycle. Do not start v2 work while v1 findings are still churning.

### Major work items

1. **Vulnerability correlation — done properly** *(the largest single item, ~10 weeks)*
   - Vendor security data, not NVD version matching: Debian Security Tracker + DSA, Ubuntu USN/OVAL, Red Hat OVAL + VEX, SUSE, Alpine `secdb`; OSV as the aggregation layer where vendors do not publish.
   - Distribution-aware version comparison (`dpkg --compare-versions` semantics, RPM `evr` semantics) implemented natively and fuzz-tested against the real tools.
   - The database ships as a **signed, versioned release asset**, built by a scheduled job, fetched by `plumbline db fetch`. Never fetched during a scan. Air-gap bundle available.
   - Every vulnerability finding states the vendor's fixed-version and links the vendor advisory — because "fixed in 3.0.2-0ubuntu1.15" is the actionable fact, not the CVSS score.
   - **Gate:** publish a measured false-positive comparison against a naive NVD matcher on stock Ubuntu LTS, Debian and Alpine hosts. If the numbers are not clearly better, the feature does not ship. This comparison is the feature's entire justification.

2. **New modules** — `CONTAINERS` (Docker/Podman/K8s node config, ~15; **started early: the daemon.json and docker.service collectors and eight checks landed in v1.x, see below**), `PRIVESC` (renamed from PENTEST, gated behind `--enable privesc` with an authorised-use notice, ~15), `MEMORY` (ELF hardening: RELRO, PIE, canaries, FORTIFY — self-contained and satisfying, ~10; **started early, see below**), `INTEGRITY` (package DB verification + bundle-to-bundle drift, ~9), `STORAGE`, `CRYPTO` (local certificate and key material only; still no network probing). Catalog to ~250 checks.

3. **`CLOUD` module, carefully** — IMDS queries are network access, which breaks the v1 invariant. Therefore: off by default, requires `--enable cloud`, restricted to link-local metadata addresses by an explicit allowlist, and the bundle records that network was used. The offline test asserts that the *default* path still makes zero network syscalls.

4. **Remediation generation** — Bash and Ansible only, from the structured remediation already in the catalog. Output is a reviewable script with every command commented with its finding ID. Never executed. Puppet/Chef dropped from the source design's list; nobody asked for them and each is a maintenance tail.

5. **Compliance evidence, not scores** — user-supplied mapping packs (`plumbline mapping add ./our-cis-v3.yaml`) so nothing licensed is redistributed. Output is an evidence pack: control identifier → checks → results → raw evidence → coverage statement. `LEGAL-DISCLAIMER.md` is shipped with it.

6. **HTML report** — self-contained single file, no external assets, no JS frameworks, printable to PDF by the browser. Deletes the chromedp dependency permanently.

7. **Interactive TUI browser** — Bubbletea, arrow-key navigation of findings. Now, not in v1, because it is polish.

### Release criteria

- [ ] All v1 criteria still hold
- [ ] Vulnerability false-positive comparison published and favourable
- [ ] `findings-v2.schema.json` published; v1 schema still emitted under `--schema v1` for one full major cycle
- [ ] Container-module fixtures for Docker, Podman and a K8s node
- [ ] `--enable cloud` off-path proven to make zero network syscalls
- [ ] Generated remediation scripts reviewed by someone who is not the author

---

## v3.0.0 — Reach

**The promise:** *Other people can extend it, and you can run it across a fleet.*

### Major work items

1. **Declarative check packs** — YAML checks over the existing fact model (read this fact, apply this predicate, emit this finding). Covers the majority of real checks without executing third-party code. Ships with a `plumbline pack validate` linter and a test harness so pack authors get the same fixture discipline core checks have.

2. **Subprocess extension protocol** — for checks that genuinely need logic: a plugin is any executable, receives a fact subset as JSON on stdin, returns findings as JSON on stdout, runs with dropped privileges, no network, a timeout and a memory cap. No Go `plugin`, no shared ABI, any language. Trust model documented plainly: **an extension is code you are choosing to run; signature verification tells you who published it, not that it is safe.**

3. **macOS support** — `MACOSEC` module, `system/live` for Darwin, a fixture corpus. Only announced once macOS is in CI. Realistically ~40–60 checks; the marketing claim is "macOS supported", not "full parity", and the platform matrix says so.

4. **Fleet aggregation** — `collect` on N hosts → `plumbline aggregate *.plb` → a fleet posture view with per-host drill-down and drift detection across time. This is natural because bundles already exist; it is not a daemon and not a server. Still no hosted service.

5. **Policy as code** — baseline files declaring expected state (`SSHD-0002 must PASS`, `KERNEL-* may not regress`), evaluated against a bundle, with a clean CI verdict. This is what teams actually want from "compliance" and it uses nobody's copyrighted text.

6. **Stable public Go API** — `pkg/plumbline` finally appears, *after* three majors of learning what the shape should be. Committing to a Go API at v1.0.0, as the source design did, is committing to a shape you have not yet discovered.

7. **Additional architectures** — arm32, riscv64, only once there is CI hardware. Otherwise unsupported binaries stay unsupported.

### Release criteria

- [ ] A third party has authored and published a check pack without core changes
- [ ] macOS in CI with ≥6 golden bundles
- [ ] Extension protocol threat-modelled and documented
- [ ] `pkg/plumbline` API frozen with a deprecation policy

---

## Beyond v3 — the graveyard

Named and rejected, so they stop resurfacing. The source design listed all of these as "post-stable", which is how a focused CLI tool becomes an unfinished platform.

| Idea | Verdict |
|---|---|
| Daemon / continuous monitoring | **No.** That is a different product with a different threat model. It also contradicts the stated non-goals. If you want it, start a new project that consumes bundles. |
| Web UI | **No.** A server in a security tool is a new attack surface and an ops burden. Generate HTML; let a browser open it. |
| gRPC API | **No.** Nobody has asked. The JSON schema is the API. |
| Remote scanning over SSH | **Maybe.** Cheap to add (`collect` remotely, `eval` locally) and it does not compromise the model. Consider it a v3.x minor. |
| Auto-remediation | **Never.** See `PROJECT-BRIEF.md` §1.3. |
| Hosted plugin registry | **No.** GitHub releases and a signed index file are sufficient and cost nothing to run. |
| SIEM integrations | **No.** Emit good JSON; integration is their job. |

---

## Schedule risks

| Risk | Impact | Mitigation |
|---|---|---|
| PAM and sshd effective-config parsing are harder than they look (`Include`, `Match`, defaults, distro divergence) | 2–3 week slip in v0.3 | Build the sshd effective-config collector first, in v0.1, so the difficulty is discovered early |
| Fixture corpus creation is tedious and gets skipped under pressure | Silent quality collapse — the classic failure | CI gate refuses any check without PASS+FAIL fixtures; make the gate exist before check #10, when it is cheap to comply with |
| Check-count ambition creeps back | v1 never ships | 110 is a ceiling, not a target. Cut checks, never cut criteria. |
| Vendor vulnerability feeds change format | v2 breakage | Feed parsers behind an interface; contract tests against recorded feed snapshots |
| Motivation dip after v1 ships | v2 stalls | v1 is designed to be a complete, defensible artifact on its own. Stopping there is an acceptable outcome, not a failure. |
