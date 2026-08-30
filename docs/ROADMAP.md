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
| `SERVICES` | 10 | **8** | systemd enablement symlinks read offline. OpenRC and sysvinit degrade gracefully but have no checks. `-0006`, `-0007` and `-0008` (WP-30, WP-32, WP-33) read unit *bodies*: the sandboxing triad, on three named units |
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
- **Names travel, values do not — one level below the top-level keys, and in
  both files.** `Keys` established that a fact can record which options a
  document set without carrying what they were set to. `log-opts` is where that
  stops being a precaution: `splunk-token` is an authentication token and
  `awslogs-credentials-endpoint` is the path to one, so the values are never
  decoded at all. The test of whether the trade is affordable is whether the
  names still answer the question, and here they do — `json-file` is unbounded
  unless `max-size` is set. Where they would not, the answer is to record less
  and say `UNKNOWN`, not to record the value.

  The half that took a second pass is that **a privacy posture has to hold
  across every spelling of the same option, not just the one it was written
  for.** `dockerd` takes log options on its command line too, and `ExecStart`
  is the one command line a bundle keeps — so for one work package a bundle
  disclosed more or less depending on which file an operator happened to use.
  The collector now scrubs those values out of the recorded argv, which is the
  first place in the tree that deliberately records something other than what
  the file says. The rule that makes it safe to extend is structural rather
  than a word list: a flag whose value no check needs is opaque, and a flag
  whose value a check *does* need gets modelled as a typed field instead.
  `--registry-mirror` is the next candidate and has not been done, because a
  mirror URL is a hostname far more often than it is a credential.

The module's honest limits are three, and all of them are worth stating plainly.

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

## KERNEL, persistence

`KERNEL-0017` is the module's first check about the sysctl *files* rather than
`/proc/sys`, and it exists because of a gap between two checks that both look
correct on their own.

`KERNEL-0006` reads the running value of `kernel.unprivileged_bpf_disabled` and
passes when it is hardened. `KERNEL-0007` compares every running parameter
against its configured value and reports drift — but it skips a parameter that
no file mentions, because there is nothing to compare it against, and that skip
is right for what it is doing. Between them sits the host hardened with
`sysctl -w` and never written to disk: two passes, and an unhardened kernel
after the next reboot.

**A gap between two correct checks is not visible from either of them.** Both
were reviewed, both are right about their own subject, and the hole is in the
space between the subjects. The thing that found it was writing down what each
check *does not* claim — which is the same discipline that produced the caveat
sentences on every CONTAINERS and SERVICES verdict, arriving at a missing check
instead of a missing sentence. Worth doing deliberately for the rest of the
catalog rather than waiting to trip over the next one.

**The corpus earned its keep here.** `ubuntu-2404-stock` fails the new check:
its running kernel has `unprivileged_bpf_disabled` at 2 because that is the
Ubuntu kernel's default, and no file sets it, so the host's hardening is an
accident of the kernel package rather than a decision. That is exactly the trap
the check was written for, found in a recording of a real host rather than in a
fixture built to demonstrate it.

**The symlink is fixed, and the interesting part was what the corpus said
about it.** `/etc/sysctl.d/99-sysctl.conf` is a link to `/etc/sysctl.conf`; the
seam opens with `O_NOFOLLOW`, so it was recorded as unreadable and two checks
declined to answer. Resolving it is twenty lines of the pattern
`internal/collect/unit` already uses.

Two things are worth carrying forward from it:

- **A code fix cannot move a golden pin.** The bundles are recordings; the
  `UNKNOWN` lived in the *recorded fact*, not in check logic, so `make
  golden-update` re-evaluated frozen facts and changed nothing. Clearing it
  needed `record.sh`. That is the corpus behaving correctly — it is supposed to
  freeze what a host looked like — and it is a step easy to assume away when
  planning a collector change.
- **"Every Debian-family host" was an over-claim, and the corpus caught it.**
  Only `ubuntu-2404-hardened` carried the link: the stock Ubuntu and Debian
  images do not ship that file. The mechanism is real and common on configured
  hosts; the blast radius stated from memory was wider than the evidence. Check
  the recordings before describing a distribution family.

`KERNEL-0018` and `-0019` are the third and fourth checks of this shape, and at
three copies the gate came out into `persistenceGate`. The trigger was the same
one the SERVICES triad produced: the loop encoded *correctness properties* —
excuse an unsupported kernel before calling an absent file a failure, stop on an
unreadable file before concluding an absence — and those were being restated per
check rather than held in one place.

**Neither of them passes anywhere in the corpus**, which is worth recording as a
fact about distributions rather than about the checks. No mainstream image
persists `kernel.dmesg_restrict`; Ubuntu and Rocky persist `kptr_restrict` at 1,
which hands the kernel layout to anything holding `CAP_SYSLOG`, and Alpine and
Fedora persist nothing. The severity tier — 1 at `MEDIUM`, unset at `HIGH` — is
the only thing distinguishing those two situations, and it earned itself on the
corpus rather than in a fixture.

`KERNEL-0020` and `-0021` finished the group and answered the question the two
before them raised. **-0020 passes on both Ubuntu bundles and nowhere else**,
which is what establishes that the group's uniform failures are a fact about
distributions rather than a bar set too high — a check that can pass, and does,
on a real recorded host is a different object from one that has never passed
anything.

**Decoding beats printing, and the corpus proved it.** `kernel.sysrq = 176` is a
number an operator has to look up; "syncing all filesystems, remounting all
filesystems read-only, immediate reboot or power off" is a finding they can act
on — and the decode is what makes the severity tier possible at all, since it
turns on which bits are set rather than on how large the number is. Ubuntu ships
exactly that value, so the tier separates a deliberate narrow choice from a
default on real data rather than in a fixture.

**A conservative default is still a wrong answer, and the corpus will not tell
you.** `ConfiguredConflict` treated every repeated key with differing values as
undeterminable, which is safe in the sense that `UNKNOWN` never lies — and it
declined to answer on a shape that has one right answer, on the most common
distribution family. The refinement is small: the two tools disagree only about
how they order *directories*, so a disagreement within one directory is
resolvable and only a cross-directory one is not. It moved no golden verdict,
because the corpus does not contain the shape; the live workstation did.

**Run the finished check against a live host before calling it done.**
`KERNEL-0021` parsed the mask with base 10, and systemd ships
`kernel.sysrq = 0x01b6`. Every fixture passed; the live scan reported UNKNOWN
"not a number" on a real and common value. The kernel parses with base 0 and now
so does this. Nothing in the fixture corpus would have caught it, because the
fixtures were written by the same person who wrote the parser.

**A check that fails every host is a judgement to revisit, not a bug to fix.**
It is defensible while the finding is true and the remedy is three lines in a
drop-in. It stops being defensible if the catalog accumulates several of them,
because a report where everything is red is a report nobody reads. That is a
severity-review question for the catalog as a whole rather than something to
settle by softening one true finding, and That question about `KERNEL-0019` and
`KERNEL-0004` is closed: the older check was the miscalibrated one and was
re-rated from `Low` to `High` at catalog 27, with a `### Check corrections`
entry. **A severity mismatch between a runtime check and the persistence check
beside it is a useful smell**, and it only became visible because the two were
written a work package apart by someone looking at both.

Re-recording that one bundle also cleared the six `UNKNOWN` the previous four
work packages had accumulated on it, and dropped its posture from 96.77 to
92.46 by surfacing three real findings it had been hiding. **A corpus whose
scores only ever rise is a scoring function rather than a measurement.** The
remaining five bundles still predate `containers.docker_service` and
`services.hardening`; re-recording them is the outstanding work package, and it
is now a smaller and better-understood one.

`KERNEL-0023`, `-0024` and `-0025` moved the group to the network stack: SYN
cookies, reverse path filtering, and source routing with ICMP redirects. Three
things came out of them.

**The configuration language was bigger than the parser.** `sysctl.d(5)` allows
a glob pattern, and the distributions rely on it — Red Hat's `50-redhat.conf`
sets `net.ipv4.conf.*.rp_filter` rather than naming interfaces, and systemd's
`50-default.conf` does the same and then withholds `net.ipv4.conf.all.rp_filter`
with a bare `-` line so that `all` stays at 0 and filtering can still be lowered
on one interface. Every lookup in this module was by literal key name. Shipping
`KERNEL-0024` without the glob rules would have failed `rocky-9-stock` for
having no reverse-path filtering while its vendor file configures it, which is
the class of false positive that teaches an operator to stop reading the report.

The exclusion syntax is the sharper half. `-` means two unrelated things in that
file format — "ignore failures applying this assignment" on a line with `=`, and
"withhold this key from every pattern" on a line without one — and a parser that
looks only for `=` drops the second as unparseable. It is not an obscure corner:
systemd's own default file depends on it, so the reading of the most common
configuration on the most common init system was wrong in a way no fixture
written from the same misunderstanding would have caught.

**Reading the man page beat reasoning from the values.** Both of these were
found by grepping a live workstation for the keys the new checks needed and not
recognising what came back, then reading `sysctl.d(5)` rather than guessing from
the file. The same move as the base-0 `kernel.sysrq` catch a work package
earlier, and the same lesson: the fixtures encode what their author already
believed.

**A check that passes tells you more than one that fails.** `KERNEL-0025` fails
on all five bundles that have any sysctl configuration, and on its own that is
the shape of a bar set too high. `KERNEL-0024` passing on four of them — three
of those on vendor files nobody edited — is what says the bar is reachable and
the group is measuring distributions rather than measuring itself. `KERNEL-0023`
sits between: `alpine-320-stock` is the only bundle in the corpus that writes
SYN cookies down, and all six run `tcp_syncookies = 1` on the kernel default.
That gap between "running" and "written down" is the entire subject of this
group of checks, and the network keys show it more starkly than the kernel ones
did.

`KERNEL-0026`, `-0027` and `-0028` closed the surface: router advertisements,
redirect *sending*, and the RFC 1337 TIME-WAIT protection.

**An absence has to be observable before a check can be excused for it.** The
two `accept_ra` keys are named in `probedKeys` rather than enumerated from
`/proc/sys/net/ipv6/conf`, which is how every other `conf/` parameter here is
read. A kernel booted with `ipv6.disable=1` has no such directory, and an
enumeration that finds nothing yields keys that were *never probed* — which
means "the collector did not ask" and is a wiring bug, not an observation. Only
`absent` may become `NOT_APPLICABLE`. Naming the two pseudo-interfaces is what
turns a disabled stack from a false `FAIL` into an honest excuse, and it is safe
for exactly these two because neither name contains a dot.

**A finding about a setting that does nothing invites the objection it
deserves.** `send_redirects` has no effect unless the host forwards, so
`KERNEL-0027` reads `net.ipv4.ip_forward` — a parameter no check judges — purely
so the verdict can say which situation the reader is in. On this workstation it
says forwarding is on, because Docker turned it on, so the finding is live
rather than theoretical. A supporting fact of that kind is still "what the
checks need"; the rule against collecting what nothing reads is about
parameters no finding ever mentions.

**The catalog now has a check that a defensible host will fail.** `KERNEL-0026`
requires `accept_ra = 0`, and a host that legitimately autoconfigures over IPv6
cannot comply without losing its address, its route and its DNS. `alpine-320-stock`
is the case in point: it is the only bundle that configures IPv6 at all, and it
sets `use_tempaddr = 2` — privacy addressing *for* SLAAC, the opposite posture,
and a considered one. The check documents the trade in its caution rather than
pretending there is not one, and the network-side answer (RA Guard on the access
switch) is named because it is the only control that stops the attack while
leaving autoconfiguration working. **This is the strongest argument yet for the
catalog-wide severity review**: `KERNEL-0025`, `-0026` and `-0027` each fail
every bundle that has any sysctl configuration, and a report where the network
section is uniformly red is one an operator learns to page past.

`KERNEL-0029`, `-0030` and `-0031` closed the module with the filesystem
boundaries, and were the first batch in this group to need nothing new. Every
parameter was already collected, every one has a runtime counterpart, and
**`persistenceGate` took them unmodified** — `internal/catalog/checks/kernel/kernel.go`
has zero deleted lines in that commit. Five work packages of persistence checks
have now passed through those four conditions without one of them needing to
move, which is about as much evidence as an abstraction of that size can earn.

**Two checks can disagree without the report contradicting itself, but only if
one of them says so.** `KERNEL-0029` accepts `fs.suid_dumpable = 2` — the
documented suidsafe value, and the only one at which `systemd-coredump` can
capture a setuid crash — while `KERNEL-0005` fails it at `LOW`, because its
subject is whether setuid programs write dumps *at all*. Both readings are
defensible and a host at `2` sees both findings. What makes that legible rather
than broken is that `KERNEL-0029`'s passing detail names `KERNEL-0005` and says
it holds the stricter bar, and that a test pins the two verdicts together so the
cross-reference cannot rot silently. Whether to reconcile them is severity-review
work; leaving the reader to notice the disagreement unaided was never an option.

**The distribution split here is the cleanest in the corpus.** Ubuntu and Alpine
write both link protections down — `99-protect-links.conf` and
`00-alpine.conf` — and the RPM family relies on the kernel default and writes
nothing. Since the kernel has defaulted both to 1 for years, Fedora and Rocky
are protected today and fail on the same principle every check in this group
applies: a default is not a decision. `fs.suid_dumpable` is the sharper case —
**no bundle writes it at all**, and all six run the safe default.

That question — whether "a safe default nobody wrote down" deserves the same
severity as "the dangerous value, written down" — was answered at catalog 32 by
`runtimeTier`, and the answer was the cross-reference rather than a lower base
severity for the group.

**The fix had to come from a fact the check already had.** Both halves are in
the same bundle: the files say what the host will do after a reboot, and
`/proc/sys` says what it is doing now. Lowering the base severity would have
made a genuinely exposed host easier to ignore; tiering on the runtime lowers
only the findings where nothing is exposed, which is the distinction the
severity field exists to carry. Three cases deliberately do not downgrade — an
exposed running value, an unreadable one, and any failure where a *file* sets
something wrong — and the second of those is ADR-0014 again: a downgrade has to
be earned by evidence.

**It refused to downgrade on this workstation for a reason no fixture would have
produced.** `KERNEL-0017` needs two parameters; `kernel.unprivileged_bpf_disabled`
reads 2, and `/proc/sys/net/core/bpf_jit_harden` is mode 0600, so an
unprivileged scan cannot read it. One unreadable key of two blocks the
downgrade and the finding stays HIGH — the rule working on a real host, on the
first run.

**One documented rationale had to be rewritten rather than left to rot.**
`KERNEL-0017`'s severity comment argued for HIGH on the grounds that a boundary
*scheduled to fall down* is worth more than one already down, which is exactly
the case the tiering now downgrades. The comment was corrected in place rather
than left contradicting the code: the tension is real, it was settled in favour
of a severity field that can sort a triage queue, and what was lost is emphasis
rather than information — the detail still says the setting came from outside
the files and will not survive a reboot.

The honest limit of the design is that a secure running value does not say where
it came from. For `fs.protected_symlinks` a secure runtime is very likely the
kernel's own default and will apply again after a reboot; for
`kernel.yama.ptrace_scope`, whose default is 0, it means something set it at
runtime and the host genuinely reverts. Both downgrade to LOW today. Encoding
each parameter's compiled-in default would separate them, and was rejected for
now because that default varies by build and by distribution patch — a table
that is wrong in the permissive direction would hand out downgrades nobody
earned. Worth revisiting with per-parameter evidence rather than from memory.

Two items this left, **both closed at catalog 33** and described in the section
below:

- **The correction warning had no mechanism.** VERSIONING §2.4 requires a
  `plumbline scan` startup warning for one minor cycle when a correction changes
  results on more than roughly 10% of hosts, and this one did. `internal/cli/notice.go`
  is now that mechanism.
- **`KERNEL-0005` and `KERNEL-0029` agree now.** The runtime check was widened
  to accept `fs.suid_dumpable = 2`, closing a report that carried a PASS and a
  FAIL about the same value. That was the second time a runtime check turned out
  to be the miscalibrated half of a pair — `KERNEL-0004` was the first — and the
  rest of the pairs have now been audited deliberately rather than one accident
  at a time.

One gap remains, unchanged and not started: **redirect acceptance has no runtime
check.** `KERNEL-0025` reads the files; nothing reads `/proc/sys` for
`accept_redirects`, and the same is now true of `accept_ra`, `send_redirects`
and `tcp_rfc1337`. The collector reads all four, so in each case the check is
the only missing piece. Whether the module wants a runtime counterpart for every
persistence check, or whether the persistence half is the one that matters and
the pairing should stop being the expectation, is a question worth answering
once rather than four more times.

---

## The startup notice, and the runtime/persistence audit

Two debts from the tiering work, cleared together because the second produced
the changes the first exists to announce.

### The notice

`internal/cli/notice.go` is a register of scoring changes and a renderer for
them. An entry names the catalog version it landed in, the tool version at which
it stops being shown, a headline and a body; `scan` writes the active ones to
**stderr** before it collects anything.

Four properties, and the second is the one that makes this maintainable:

- **stdout never sees it.** `reportScoringNotices` takes one writer and `scan`
  hands it stderr, so no `--format` can put a banner in a document a pipeline
  parses. A test runs all three formats and asserts it.
- **It expires without anybody remembering.** A notice nobody retires is a
  banner everybody learns to scroll past, which is the same as no banner and
  costs a line of every terminal forever. Expiry is keyed on the tool version
  because VERSIONING §2.4 is written in those terms — "one minor cycle" — and a
  build with no release identity (`go run`, a test binary, `git describe` with
  no tags) shows everything, because it has demonstrably passed no expiry.
- **It is drawn where no human is watching**, which is the deliberate opposite
  of the progress indicator's policy. That indicator is an animation and is
  useless in a log; this is one static block, and CI is exactly where an
  unexplained posture movement trips a `--threshold` gate at three in the
  morning. Terminal detection would suppress it precisely where it is needed.
- **`PLUMBLINE_NO_NOTICES` turns it off**, honoured on presence like `NO_COLOR`
  and `PLUMBLINE_NO_PROGRESS`, and weakening nothing (CLI-SPEC.md §8).

### The audit

Eleven KERNEL parameters have both a runtime check and a persistence check.
Every pair was compared on two axes: the values each accepts, and the base
severity each carries.

**One value discrepancy, and it was on every bundle in the corpus.**
`KERNEL-0002` passed `kernel.kptr_restrict = 1`; `KERNEL-0018` failed the same
value at MEDIUM. Ubuntu, Debian and Red Hat all ship 1, so every golden bundle
carried a PASS and a FAIL about one number, and an operator reading both had no
way to tell which half to believe. The runtime check was right: 1 hides pointers
from every unprivileged reader, and what it leaves open needs CAP_SYSLOG. So 1
passes both halves now, 2 is a recommendation in the verdict rather than a
requirement, and `kptrTiering` widened to match — it had demanded 2, which meant
the catalog 32 downgrade could never fire on a realistic host.

Two other pairs disagree on paper and cannot in practice, and are recorded here
so the next reader does not re-derive it: `KERNEL-0004` accepts
`dmesg_restrict >= 1` where `KERNEL-0019` accepts exactly 1, and `KERNEL-0003`
accepts `ptrace_scope >= 1` where `KERNEL-0020` accepts 1 to 3. The kernel
clamps both parameters to their documented range, so no running value can reach
the gap. Nothing was changed for an unreachable difference.

**Six severity misalignments, all of them the same leftover.** Every persistence
check sat one band above its runtime counterpart, on the argument recorded in
`KERNEL-0017` — a boundary scheduled to fall down outranks one you can see
today. Catalog 32 retired that argument, because the case it described is now
the one that gets *downgraded*. Nothing replaced it, so six pairs were a band
apart for no reason at all.

The rule now is one severity per parameter, decided on what the failing state
means rather than on which check noticed it:

| parameter | was | now | why |
|---|---|---|---|
| `kernel.kptr_restrict` | -0002 MEDIUM, -0018 HIGH | both HIGH | at 0 an unprivileged read of a text file defeats KASLR — the same mechanism `KERNEL-0004` was re-rated HIGH for at catalog 27 |
| `fs.suid_dumpable` | -0005 MEDIUM, -0029 HIGH | both HIGH | at 1, one user's privileged memory reaches a file another user can read |
| `kernel.unprivileged_bpf_disabled` | -0006 MEDIUM, -0017 HIGH | both HIGH | an attacker-supplied program run in the kernel behind a verifier with a long CVE history |
| `fs.protected_symlinks` | -0009 MEDIUM, -0031 HIGH | both HIGH | a route from an ordinary account to root that needs no exploit |
| `fs.protected_hardlinks` | -0010 MEDIUM, -0030 HIGH | both HIGH | the other half of the same problem; splitting them would be arbitrary |
| `kernel.yama.ptrace_scope` | -0003 MEDIUM, -0020 HIGH | both MEDIUM | same-uid memory access: lateral movement for an attacker who already has the account, not a privilege boundary crossed |

`kernel.yama.ptrace_scope` is the only pair that closed downward, and it is
worth saying why rather than letting it look like an exception. It is also the
upstream default and the shipped default of the whole RPM family, so rating it
HIGH would have put a red line on every Red Hat host for a setting nobody chose
— the alert fatigue catalog 32 was spent removing.

Two pairs are pairs in subject and not in key and were deliberately left out of
the mechanical comparison: `KERNEL-0008`/`-0024` and `KERNEL-0015`/`-0025`. The
runtime halves compute a value per interface from `net.ipv4.conf.<iface>.*` and
the persistence halves read `conf.all` and `conf.default`, so "do they agree
about the same value" is not a question that can be put to both. Fixtures hold
them instead.

**The audit found the kptr contradiction by hand, and a test finds it next
time.** `TestBothHalvesOfAPairAgreeAboutTheSameValue` sweeps every plausible
value of every same-key pair with the file and `/proc` set to it, and asserts
the two checks do not reach opposite verdicts;
`TestAParameterCarriesOneSeverityWhicheverHalfAsks` holds the table above.
`KERNEL-0018` also joined the tiering drift guard, which it could not be in
while its predicate and its verdict disagreed about 1.

What this leaves:

- **`eval` gets no notice.** VERSIONING §2.4 names `plumbline scan`, and that is
  what was built, but `eval` re-evaluates a stored bundle against today's
  catalog and its posture moves for exactly the same reason. One line wires it;
  the question is whether a notice on a command that reads an archived bundle
  helps or just repeats itself. Worth deciding rather than drifting into.
- **The register is prose and nothing checks it against the changelog.** A
  scoring change landing without an entry is a silent score movement again, and
  the only thing preventing it is somebody remembering. A test that compared the
  register against `### Check corrections` headings would close it.

---

## The live scan stream

`lynis` narrates. Plumbline printed a spinner for the collection phase and then
a finished report, which meant the operator's whole view of a forty-second scan
was one line of braille. This is the narration.

**The event architecture is two interfaces, deliberately not one.**
`catalog.Observer` is called once per check, synchronously, in deterministic
order, from the goroutine that called `EvaluateWith`. `collect.Runner.Observer`
is called once per collector from the collector goroutines, which run at once,
in completion order, which is not stable between runs. A single shared interface
would have had to document the weaker of the two contracts everywhere, and a
caller reading it would not be able to tell which half it was in. `rendertext.Stream`
implements both, and neither observer writes anything: both append to a queue
under one mutex and a single goroutine draws, which is what makes the concurrent
half safe by construction rather than by holding a lock across an `Fprintf`. The
joint between `collect.CollectorStatus` and the renderer's plain string is an
adapter in `internal/cli`, because the render tree may not import the collection
tree.

**Evaluation was not made concurrent and should not be.** 109 checks over a
collected fact set take 1.3 ms. The slow half of a scan is collection, which
already is concurrent, and the ordering of `Evaluate` is what makes two runs
over one bundle byte-identical. Streaming a millisecond of work is why the
collector events exist: without them, replacing the spinner would have made the
*slow* phase silent again, which is the exact failure `progress.go` was written
to fix.

**Two width policies, and the split is the point.** The report is an artifact
somebody diffs, so its grid is fixed at 78 columns and does not read the
terminal — that decision predates this work and is unchanged. The stream is
ephemeral stderr output that nobody redirects into a file they compare, so it
measures the terminal for every row. A resize mid-scan therefore reflows from
the next row; already-printed rows are somebody's scrollback and cannot be
reflowed by anyone, which is the strongest guarantee available and the reason
there is no `SIGWINCH` handler. `system.TerminalWidth` is one `TIOCGWINSZ`
ioctl inside the seam, asked freshly each time, costing about a microsecond
against a filesystem walk.

Within a row, only the middle segment gives. The check ID is in the fixed tail,
because it is what a suppression file matches on and what `plumbline explain`
takes — a row that has lost its ID has lost the only part of itself anybody can
act on. An early version clamped the layout to a 40-column floor and produced
40-column rows on a 30-column terminal, which the terminal then wrapped,
destroying the column far more thoroughly than a short row would; the floor is
now a guard against absurd arithmetic and the row drops to its compact form
instead.

**Every open question about the display was settled by watching it, and two of
them the other way from the reasoning.** Screen recordings made in a day what
the design notes had not managed: the arithmetic of a terminal is that whatever
comes *after* the stream is what an operator is left looking at, and no amount
of correct content survives being on the wrong side of the last page.

The standard mode was wrong twice for the same reason. First it carried the
whole detailed report, then — after that was withheld — it carried the severity
tally, one line per failing check, forty of them on a real host. Both times the
live output scrolled off the top before the run finished. The rule that came out
of it is worth stating as a rule: **standard mode allows itself four lines and a
hint after the last streamed row**, and anything that grows with the number of
findings belongs behind `--verbose`.
`TestStandardModeShowsTheStreamAndNothingButASummary` is that rule as a test.

**The test that was supposed to hold that rule did not.** It constructed a
`text.Stream`, did not call `Tally`, and asserted the closing block was short —
which proves the *renderer* honours `tally=false` and says nothing at all about
whether the scan command sets it. `Tally(verbose)` lives in `scan.go` and was
never executed by the test. The same blind spot covered every mode decision,
because they all live in the command: `streamPresenter`'s four conditions,
`reportDestination`'s terminal test, the hint. **None of them is reachable
through a `bytes.Buffer`**, because a buffer is not a character device and the
stream is never built for one — so the entire presentation layer was being
tested everywhere except where it was decided.

The replacement drives the real cobra command over a real pseudo-terminal
(`internal/cli/pty_internal_test.go`): `/dev/ptmx`, the three standard ioctls, a
fixed 100-column window, both stdout and stderr pointed at the slave, and a
drain goroutine because a pty buffer is smaller than a scan's output and a test
that read at the end would deadlock rather than fail. Standard mode's tail is
then asserted against a closed list of four permitted lines rather than a list
of forbidden strings, because a forbidden list is one somebody has to remember
to extend.

Two mutations show it works where the old one did not. Changing `Tally(verbose)`
to `Tally(true)` in `scan.go` leaves the component test green and fails the pty
test; removing the `s.tally &&` gate in the renderer does the same.

The rest of the settlement:

- **The report is withheld from a terminal that watched the scan.** The stream
  and the report were both on screen for a bare `plumbline scan` — the same
  checks, twice, the second time trailed by every remediation in the catalog —
  and the live output was buried within a second of finishing. This was raised
  here as defensible-but-not-obviously-right; it was neither. The cost of the
  fix is the one named at the time: stdout's content now depends on whether
  stdout is a terminal. That is confined to exactly one condition with four
  exceptions, and every scripted use — pipe, redirect, `--output`, `--format
  json`, CI — keeps the document it always had. `--verbose` brings it back,
  `--quiet` goes further and drops the per-check rows too.
- **The two vocabularies became one.** The stream said `PASS`/`FAIL`/`N/A` and
  the report said `OK`/`WARNING`/`SKIPPED`, on the argument that a commentary
  wants the verdict and a report wants the action. Both halves of that are true
  and it does not matter: they appear in one session, so an operator who watches
  `[ FAIL ]` scroll past and greps the report for "FAIL" finds nothing. The word
  now comes from `statusToken` in both, which is the only arrangement in which
  they cannot drift. Colour follows in every state but `SKIPPED`, cyan in the
  stream and dim in the report — a row with no verdict recedes correctly on a
  dense page and reads as a display failure in a scrolling list.

### The pace

The stream was correct and still not a stream. 109 checks in 1.3 ms print as a
wall of text that is complete before the eye has fixed on anything, so an
operator watching a bare `plumbline scan` learned nothing the closing two lines
would not have told them faster — and under `--verbose`, where a fourteen-hundred
line report follows, the rows were gone from the window before anyone could read
one. A row-by-row display is worth having only if a row can be read while it is
on screen, and at full speed none can.

So each row is now drawn in two halves with a pause between them: the title and
its ellipsis, a pause, then the verdict landing flush right. `--pace 0` removes
it and `--pace 500ms` slows it down.

**The number has been three numbers, and the two changes are worth recording
rather than quietly amending.** 150 ms was chosen as the fastest cadence at
which a column of brackets still reads as a sequence rather than as flicker.
Watched back on a screen recording, that turned out to answer whether a row is
*legible* and not whether a row is *read* — the eye tracks the movement down the
column without landing on a title — so it went to 500 ms, and a scan to a little
over a minute.

Both numbers were asking how long one row needs **in a flat list of a hundred
and twenty of them**, and in a flat list the pause is the only structure there
is. Grouping the rows under module headings supplies the structure instead: the
eye lands on the heading, and the ten or twenty rows below it read as a block
rather than as twenty separate events. That bought the time back, and the pace
is 100 ms — about twelve seconds for a scan, with the hierarchy legible
throughout.

**This is the one thing in the tool that costs time without doing work, and it
is confined so that it cannot be mistaken for work.**

- **It is charged to the display.** Every method on `Stream` queues an event and
  returns; one goroutine owns the terminal and does all the waiting. Evaluation
  still takes 1.3 ms and the thirteen collector goroutines keep reading the host
  instead of sitting in a sleep. Nothing the report prints is measuring the
  display.
- **The queue is unbounded and that is not laziness.** A buffered channel blocks
  its sender at capacity, and at a tenth of a second a row the queue reaches the catalog's
  full depth within a millisecond of evaluation starting — so any capacity small
  enough to write down would hand the delay straight back to the engine, and any
  capacity larger than the catalog is a constant somebody must remember to raise
  when a check is added. The real bound is arithmetic: one event per collector,
  one per check.
- **It is paid only where the rows are.** A pipe, a redirect, `--format json`,
  CI, `PLUMBLINE_NO_PROGRESS` and `--quiet` all draw no rows and none of them
  waits.

Asynchronous drawing broke three things synchronous drawing had not, and each
needed a piece:

- `Stream.Await`, because `bundle saved to ...` and the suppression notes share
  stderr with the stream and would otherwise land several rows above where they
  belong.
- `Stream.Stop`, wired to the scan's context, because a display that outlives
  outlives the work and a Ctrl-C inside it has to be felt now. The first press
  abandons the queue within milliseconds — measured at 23 ms on this host —
  finishes the row it was drawing so no half-line survives, and still prints the
  result block. **The work was already done; only the narration is cut**, so
  reporting the real posture and the real exit code is right rather than a leak.
- `Close` awaiting *and* stopping before it writes, because "the queue is empty"
  is not the same claim as "no other goroutine is writing to this terminal".

**A pause between two writes shows nothing unless the first write has reached the
screen**, and that is a property of the writer rather than of the renderer. It
was checked rather than assumed: recording the pty with `script(1)` gives one
delivery per pace, each carrying one row's verdict followed immediately by the
next row's title — the read boundary falls *inside* a row, which can only happen
if the two halves left the process at different times. `os.Stderr` is an
`*os.File`, one `write(2)` per `Write`, with no userspace buffer to hold
anything. `Stream.show` nevertheless probes the writer for `Flush() error` and
calls it after each half, because the failure it prevents is silent: a
`bufio.Writer` wrapped round stderr for some unrelated reason would produce
byte-identical output on a different schedule, and no test that inspects text
could see it. `TestTheTitleIsFlushedBeforeTheStreamSleeps` asserts against a
writer that does buffer. `Sync()` is not called — `*os.File` has it, so a type
switch listing it would `fsync(2)` the terminal twice a row, a syscall meaning
*commit to storage* that returns `EINVAL` on a character device and says nothing
about what is on screen.

**`--verbose` was reported as having lost the stream. It had not.** The rows are
all there, above the `[*] Result` block, above the detail; a run measured on this
host has the same 109 evaluation rows with the flag as without it. But no test
said so — the verbose mode test asserted the tally and the report and nothing
about the rows — so the claim could not be answered from the suite, only from a
terminal. `TestVerboseKeepsTheStreamAboveTheResultAndTheDetail` now compares the
row count against a standard-mode run and pins the order of all four sections.
The impression was real and had a real cause: the report that follows is
fourteen hundred lines, so on any ordinary window the stream is long gone by the
time the command returns. The pace is what puts it in front of the operator
while it is happening, which is the fix the report's position could not be.

### The grouping

The stream was a flat list of a hundred and twenty-two rows, and the pace was
carrying the whole burden of making it readable. Grouping the evaluation rows
under a heading per module — `[+] Module: AUTH`, a rule, then the module's checks
indented under it — gives the display a hierarchy, which is what `lynis` has and
what the pace was standing in for.

Three markers, one meaning each: `[*]` a phase, `[+]` a module, `  - ` a row.
**That also fixed a collision nobody had noticed.** `[+] ` was already the
report's module heading (`[+] SSHD  · 19 checks, 2 failing`, see `group` in
`text.go`) *and* every row of the stream, so an operator who had seen both in
one session had seen one marker mean a family of checks and a single check. The
rows moved to an indent; `[+] ` now means the same thing in both renderers.

**The current module is a local variable in the drawing goroutine**, and the
alternative is what makes that worth writing down. The obvious place to notice
a module change is `CheckDone`, which is called in catalog order — but that is
the producer, on the wrong side of the queue. It would put display state in the
struct where `CollectorDone`'s thirteen concurrent callers can reach it, needing
the mutex to be safe, and it would make the evaluating goroutine decide what the
screen looks like. In `drain` it needs nothing: one goroutine draws, so "which
module is on screen" is by construction read and written by one goroutine.

It is not a lookahead, and the failure that follows from that is deliberate.
A heading is written when a row arrives carrying a module that is not the one
showing — the only rule available to a queue whose consumer cannot see what is
behind the row in its hand, and the only one that will not open a section a
Ctrl-C is about to cancel. A catalog that stopped evaluating a module
contiguously would therefore reopen its heading. That is the right failure:
the alternative — remembering every module seen and suppressing the repeat —
files rows under a heading several screens above them, which is a display that
lies. `TestAModuleIsReopenedRatherThanMisfiled` pins the honest behaviour and
`TestTheStreamGroupsTheCatalogByModule` fails on the catalog ordering that would
trigger it, since nothing else declares that ordering.

The heading shares its row's single width measurement rather than taking its
own, so a window dragged between a heading and its first row cannot leave the
two laid out against different terminals — the same argument as the two halves
of a row. The rule under a heading is 51 columns, clamped to the terminal: wide
enough to read as a heading, narrower than the rows so it introduces the column
of brackets instead of competing with it, and never wide enough to wrap, because
a wrapped rule is two rules with a heading orphaned above them.

### The heartbeat

Rows are written on completion, which is what keeps them whole under
concurrency — and it meant the slowest collector was silent for as long as it
ran. Measured on this host with a cold page cache: eleven collector rows drew at
pace, then the terminal held still for **23.9 s** while `fswalk` walked the
filesystem, then `memory` and `fswalk (23s)` arrived and the scan carried on. A
freeze followed by a burst is the shape a paced stream exists to rule out, and
it was the one place it still happened. Twenty-four seconds of nothing reads as
a crash.

The display now says what it is waiting for:

```
  - Collecting memory...                                                [ DONE ]
[~] Still working: fswalk (17s) /
```

Measured again with it: the longest gap between deliveries on the pty is
**0.13 s**, down from 23.9 s, and the replayed screen has no heartbeat line left
on it anywhere.

**`[~]` is a fourth marker and not one of the three.** `[*]` a phase, `[+]` a
module, `  - ` a row: those are the record of what happened, and every one of
them is permanent. The heartbeat is not a record — it is one line that is
overwritten and then erased, and nothing it ever said survives the scan. Giving
it a marker of its own says that on sight.

**It is drawn by the drawing goroutine and by nothing else.** The obvious build
is a second goroutine with a ticker and its own `Fprint`, and it would have
handed two writers one terminal — the single failure this layout cannot survive,
and the reason `Phase`, `CheckDone` and `CollectorDone` queue instead of writing.
What is multiplexed onto stderr is the *decision* to draw a heartbeat, not the
drawing: a ticker sets a flag and broadcasts, `next` reports a beat when there
is nothing queued, and `drain` draws it. `sync.Cond` has no timed `Wait`, which
is why the ticker exists at all.

Two consequences fall out, and both are properties rather than precautions:

- **A queued row always beats a pending tick.** The heartbeat covers a gap; if
  there is something real to draw there is no gap. The tick is dropped rather
  than deferred, so a spinner is never drawn for one frame and erased in the
  same millisecond.
- **A heartbeat cannot land inside a row.** A paced row is a title, a pause and
  a verdict, and the pause is the longest window in the display with the cursor
  mid-line — but during it `drain` is inside `draw`, not at the top of its loop.
  The right-aligned brackets are laid out from column 0 of a line the erase has
  already cleared.

**The cursor discipline is one rule: the heartbeat never ends a line.** It writes
`\r`, erases the line the cursor is on, and writes its text with no newline, so
it occupies the line the *next* row will be drawn on and getting off it is `\r`
and an erase again. There is deliberately no cursor-up. Printing the heartbeat
on its own line and stepping back over it with `ESC[1A` fails on a terminal three
ways this cannot: the line wraps if it is wider than the window and one step up
lands in the middle of it; the scroll region moves under the cursor when the
heartbeat is on the bottom row, so up is not where the line was; and anything
else that writes to stderr in between leaves the cursor pointing at a line that
has moved. Never leaving the line removes all three. The text is truncated to
the terminal for the same reason — a heartbeat that wrapped would be two screen
lines and the erase reaches only one, leaving half a spinner above every row for
the rest of the scan.

`collect.Observer` gained `CollectorStarted`, called from the line in `runOne`
that starts the clock rather than from the goroutine above it. A collector
queued behind a dependency or behind the expensive slot is not working the host,
and announcing it would name the wrong collector as the slow one — the same
reason the reported duration is measured from there. The contract is
deliberately asymmetric: every collector finishes, only the ones that ran
started. A collector refused for privilege that was announced as started would
sit under a stalled display forever, because no `CollectorDone` is coming for it.

Testing it needed a terminal rather than a buffer. `\r` + erase + a row is, as a
string, the heartbeat followed by the row, and reads as corruption; on a
terminal it is the row alone. So the assertions that matter replay the writes
through a small model of a terminal — `screen` in `stream_test.go` — and check
what would be on it.

What this leaves:
- **The stream shows raw evaluation.** Profile scoping and suppression are
  applied to the slice afterwards, so a check the operator has formally accepted
  streams past as `FAIL` and then appears in the report as `SUPPRESSED`. The
  suppression set is already loaded by the time the stream is built, so labelling
  them live is cheap; it was left out because the stream is a view of evaluation
  and this would make it a view of the pipeline.
- **The pace is uniform, and a collector that already took twenty-five seconds
  waits another tenth of a second for its verdict.** The honest version would hold each row for
  `pace` *minus* what the work actually took, so that real duration and
  artificial duration do not add. It is a two-line change and was left out
  because collector rows arrive in a burst — they are queued in completion order
  and drawn behind whatever is ahead of them, so "how long ago did this finish"
  is not the same question as "how long has this row been waiting", and the
  arithmetic wants thinking about rather than guessing at.

### Pipeline gates, and why SARIF fixes are not SARIF `fixes`

**The exit-code contract already had the code this needed.** `ExitFindings = 2`
is "completed; findings at or above `--fail-on`", so the count gates land there
rather than acquiring one of their own: to a pipeline all three are the same
event, and a fourth code would make every CI configuration that tests for 2
wrong on the day somebody adds one of these flags. `Outcome.CountGate` carries
which one fired into the message, which is where a person reads it.

The requested scheme also proposed 1 for fatal errors generally. plumbline's
ladder is finer and is a documented contract (ARCHITECTURE.md §9): 1 is a usage
or configuration error where *nothing was scanned*, 10 is a scan that ran and
was not allowed to look, 70 is the tool being broken. Those are three different
things to a pipeline — the first is a broken invocation, the second a real
result about a host, the third a reason to distrust everything printed — and
collapsing them would lose the distinction the ladder exists for.

A count gate counts only **failing, unsuppressed** findings. Counting every
finding at a severity would count the passes and fail a clean host on its first
run; counting a suppressed one would make the suppression file unable to do the
one thing it exists for.

**SARIF's `fixes` array is the wrong home for what plumbline generates, and the
schema says so rather than taste.** A `fix` object requires `artifactChanges`
with at least one entry — it means "a textual edit a tool can apply to an
artifact", and consumers exist that will apply one. What plumbline produces is a
shell script: `sysctl -w`, `systemctl edit`, an awk that rewrites
`/etc/login.defs` in place. That is not a textual edit to a named artifact and
cannot be expressed as one, so emitting it there would be invalid SARIF *and* an
invitation to a consumer to apply something it has not understood. The property
bag is the schema's own answer for tool-specific data.

**A check with no registered generator is not a hole in the output**, which was
the question worth answering carefully. Two sources, ranked: the generated
script where one exists, marked `generated` because it names the paths and units
*this host* was found to have wrong; the catalog's own commands otherwise,
marked `advisory` because they are illustrative. Where neither exists the
property is omitted entirely rather than emitted empty — an empty array reads as
"plumbline considered this and had nothing", which is a different claim from
"this build has no proposal", and a consumer testing for the key could not tell
them apart. On the cli-host fixture that is six generated, six advisory, none
missing.

`LOW` moved from `warning` to `note` in the level mapping. That is the
conventional three-way split a consumer's default filters are built around, and
nothing is lost by it: `security-severity` is emitted numerically on every rule
and is what GitHub actually ranks by. The level decides the bucket; the number
decides the position inside it.

### Cron paths, and a false FAIL about Docker

Both halves of this were already checks, and both gaps were in what came after
them.

**`CRON-0001` is `/etc/crontab` and `CRON-0002` is the drop-in directories.**
The remediation acted on one path — the finding's subject — which is adequate
for the crontab and wrong for the directories, where the finding is a *set* by
construction and repairing one of five leaves four ways to schedule a root job.
Both now iterate the evidence, and both run ownership and mode over each path,
because a host can have either wrong and each is a no-op where only the other
was.

The fix goes to `0600` and `0700`, **stricter than either check requires**.
CRON-0001 and CRON-0002 ask whether an unprivileged account can *write* the
schedule, which `0644` satisfies; the stricter value costs nothing, since
nothing but cron reads these, and closes CRON-0005 — *can an unprivileged
account read the schedule of a root process* — in the same command. Tightening
the **checks** to `0600` was the alternative and would have been wrong: it would
duplicate CRON-0005 and move a verdict on every host that ships the distribution
default. A remediation may exceed a finding; a check may not quietly become a
different check.

**`CONTAINERS-0002` is no-new-privileges**, not userns — so the runtime-remap
check could not go there. But the concern behind the request was real and the
module already had the fact to answer it: `CONTAINERS-0001` read `daemon.json`
and never the `ExecStart`, while the collector's own package comment says *"the
file is not the running configuration"* and `dockerservice.go` exists precisely
because "that is where the command line actually lives". A daemon started with
`--userns-remap=default` in a drop-in was reported as running container uid 0 as
host root. That is a false FAIL, and it is fixed by reading the second place the
option can be set rather than by a new check.

`docker info --format '{{.SecurityOptions}}'` would have answered it too, and
would have cost the thing this project keeps choosing to protect: a scan that
works against a mounted image and against a bundle recorded months ago. It also
answers for the *scanning* host, which is the wrong machine whenever `--root` is
in play.

The file is consulted first and the unit only when it says nothing, which is not
a preference but a fact about dockerd: it refuses to start when an option is
given as a flag **and** in the file, so the two cannot disagree on a running
host. The service fact is optional rather than in `Requires`, for the reason
`AUTH-0005` established one commit earlier.

The module-wide invariant test moved with it. It asserted that every verdict
carries "this reads daemon.json only"; that sentence is now false for
`CONTAINERS-0001`, and a caveat that overstates what was missed misleads as
thoroughly as one that understates it — an operator would go and check something
the check has already checked. The invariant is now *every verdict says where it
looked*, which is what it always meant.

### login.defs, and a Requires that turned a working check off

`USERS-0012` is new. `AUTH-0005` existed and **documented the gap this closes**:
`pam_unix.so` with no algorithm argument is the shipped configuration on Debian
and Ubuntu, and the check returned UNKNOWN on all of them, saying in as many
words that the answer was in `ENCRYPT_METHOD` in `/etc/login.defs`, "neither of
which this check reads". So the work was the collector, not the check.

`USERS-0012` is the persistence half of `USERS-0010` — the shipped default for
the *next* account against what the accounts that exist are set to — which is
the `KERNEL-0004`/`KERNEL-0019` shape the catalog already uses.

**A fallback fact must not be in `Requires`, and finding that out cost a
regression.** Adding `fact.LoginDefsID` to `AUTH-0005`'s `Requires` turned it
from PASS to `UNKNOWN(fact_not_collected)` on every bundle in the recorded
corpus, because the runner marks a check unanswerable when a required fact is
missing and no bundle predating the collector has one. The check could answer
perfectly well from the PAM line. `Requires` is the list of facts a check
*cannot work without*; a fallback is consulted with `fact.Get` and the presence
flag it returns — which also lets the finding say "this scan carries no reading
of /etc/login.defs" rather than "this host has no /etc/login.defs", because the
second is a statement about a machine nobody looked at.

**login.defs takes the first match**, which is the reverse of sysctl.d, PAM
includes and systemd drop-ins. Two consequences, and both are load-bearing:

- The fact keeps **every** occurrence, not the winning one, so a finding can say
  that the line an operator edited at the bottom of the file has never been
  read. That is worse than never having written it and is invisible otherwise.
- The remediation rewrites the **first** definition in place. Appending — the
  obvious script, and what the sysctl helper does — would change nothing at all
  on precisely the hosts that need it, because those are the ones that already
  have the wrong value higher up. It would run cleanly, report success, and
  leave an operator believing a host was fixed.

Later definitions are commented rather than deleted, which is the one place this
differs from the sysctl merge: a duplicate in a plumbline-owned drop-in is noise
to collapse, and a second `ENCRYPT_METHOD` in a distribution-shipped file is a
line somebody wrote.

The two check modules share `internal/catalog/checks/logindefs` rather than
importing each other. AUTH and USERS both cite this file and both describe a
shadowed definition, and a module-to-module import would have made the USERS
package unreadable without the AUTH one and put a cycle one edit away — there is
no other cross-module import in the tree.

`SHA512` and not `YESCRYPT`: yescrypt is the better hash and needs libxcrypt
4.4. A host without it accepts the setting and then cannot hash a password,
which surfaces as `passwd(1)` failing for every user at once — the sort of
failure a generated script must not be the cause of.

### The strict tier, and a drop-in that nearly broke cron

`SERVICES-0011` is the third check on the same three units, and the case for a
third rather than a stricter bar on the first two is the case for tiering at
all: `SERVICES-0007` passes at any `ProtectSystem` other than `no`, which is the
right bar for *its* question — a daemon that cannot rewrite `/usr` cannot
persist by replacing a binary. `strict` answers a different one. `yes` protects
`/usr`, `/boot` and `/efi`; `full` adds `/etc`; only `strict` mounts the whole
hierarchy read-only and requires every writable path to be declared. Raising
0007's bar would have moved a verdict on every recorded host without anything
changing on any of them. Two checks let a host see *protected, and not at the
strongest tier*, which is one finding and the true one.

**The requested check already existed as two.** `SERVICES-0007` is ProtectSystem
and `SERVICES-0008` is ProtectHome, both since catalog 32, both with an
exemption mechanism and a caveat. What did not exist was the remediation, and
that is now four drop-in generators covering the whole sandbox family including
`SERVICES-0006`.

Two parts of the request were not implemented as written, and both for the same
reason — the fact does not carry what they ask for, and making it carry that
would cost more than it buys:

- **"Iterate through all enabled services"** would mean reading every unit
  *body* on the host, which is precisely what `services.units` exists in order
  not to do: a bundle would then carry every `ExecStart=` and every
  `Environment=` on the machine. `fact.SandboxTargets` is a named list of three
  for that reason, and widening it is a work package with a fixture per
  addition.
- **"Ignoring ones running as root"** would leave almost nothing. All three
  audited units are long-lived root daemons, and confining a root daemon is the
  entire point — `ProtectSystem=strict` on a root process is what stops it
  rewriting `/usr`. The fact does not record `User=` either, so it is not
  observable from what is collected.

**The drop-in generator's first draft wrote `ProtectSystem=strict` into
cron.service**, which is the one unit all four sandbox checks exempt and exactly
the breakage the exemption exists to prevent — cron runs arbitrary
operator-supplied jobs, and a read-only filesystem makes them fail at the job
rather than at the restart. The cause is worth recording: it read unit names out
of the finding's *detail*, and the detail names every unit the check has anything
to say about, including the excused ones and the reason they were excused. It
reads the evidence now, which these checks emit one entry per *failed* unit and
nothing else. A finding with no evidence yields no action and lands in the
unfixable list, which is visible.

`SERVICES-0007` is offered `full` and `SERVICES-0011` `strict`. That is
deliberate: `full` satisfies 0007 without the service having to be profiled
first, and `strict` is the tier that requires declaring every writable path,
which is the investigation 0011 carries.

**`ubuntu-2404-hardened` gained a real finding from this.** It is the one bundle
in the corpus recorded against the current collectors, so it is the only one
where the sandbox checks reach a verdict at all — and `systemd-journald.service`
runs there with neither `ProtectSystem` nor `ProtectHome`. Seventeen FAILs
instead of sixteen, posture 86.32 to 85.59. The other five bundles carry no
`services.hardening` fact and answer UNKNOWN.

### AppArmor, and what the firewall checks already were

`SERVICES-0010` is new; the firewall half of this work package was not.

**`NETWORK-0002` already existed, with the semantics that were asked for.**
"Pass if an active firewall is loaded with a default DROP or REJECT policy on
incoming traffic, warn if the default INPUT policy is ACCEPT" is
*The firewall's default inbound policy denies*, shipped at catalog 10, and
`NETWORK-0001` is *A host-based firewall is configured* beside it. What was
missing was the remediation action, and that is what was added.

**The collector was asked to run `ufw status`, `nft list ruleset` and
`iptables -L -n`, and does not.** That is a decision this project already made
and wrote down: a scan has to work against a mounted image and against a bundle
collected months ago, and a command run on the scanning host answers for the
scanning host. The consequence is stated in every check that depends on the
fact — the module reports what is *configured*, not what is loaded in the kernel
right now — and the SERVICES module covers the other half by seeing whether the
unit is enabled. Replacing a file-based collector with exec would trade
`--root` scanning for a property the two modules already provide between them.

The same reasoning shaped the AppArmor collector, and there it costs nothing:
`aa-status --json` parses `/sys/kernel/security/apparmor/profiles`, so reading
the file directly gives the same data without a dependency on apparmor-utils
being installed. `/sys` is a live kernel interface, so a mounted image has none
— an image scan establishes what is installed on disk and nothing about what is
loaded, and `SERVICES-0010` returns UNKNOWN rather than drawing a verdict from
the half it has.

**Three states, not two.** The check distinguishes AppArmor *absent* from
AppArmor *disabled*, because a RHEL host has no AppArmor and is not thereby
misconfigured — it runs SELinux. A check that failed every RPM-family host for
not running an LSM they deliberately do not use would be noise on exactly the
distributions this catalog is meant to be useful on.

**`SERVICES-0009` does not exist and the gap is deliberate on the caller's
side**, not an accident here: the ID was specified as 0010 and check IDs are
permanent public identifiers — a suppression file matches on them and
`docs/checks/<ID>.md` is named after them — so second-guessing a number that was
named would be the wrong kind of initiative.

**Every recorded golden bundle moved by exactly one verdict**, the same one:
`SERVICES-0010  new check, UNKNOWN`. Those bundles were recorded before the
collector existed, so they carry no `services.apparmor` fact and the check
resolves to `fact_not_collected` — the correct reading of a bundle from an older
build. `ubuntu-2404-hardened` loses its zero-UNKNOWN claim to it; the comment
now says why and that it clears when the corpus is re-recorded. Nothing else
moved on any of the six, which is the strongest signal available that the change
is additive.

### The remediation engine, phase one

`internal/remediate` turns findings into the work that would fix them, and
`scan --fix` prints that work as a shell script. **Nothing is executed**, and
the block's first line says so before anything else on it.

This is item 4 of the v2.0.0 plan arriving early — "Bash and Ansible only, from
the structured remediation already in the catalog… never executed" — and it
lands against a sentence in `PROJECT-BRIEF.md` §1.3 that said there would be no
`--fix` flag at all. That sentence has been corrected rather than quietly
outlived: the flag exists, in its proposal-only form, and the reasoning behind
the original — a tool that rewrites `/etc/ssh/sshd_config` as root from a
heuristic will eventually lock someone out of production — is unchanged and
still governs what it may ever do. **Generating is a review step; applying is
the thing this project does not do.**

**What is remediated is stated positively, in one place, because the filter is
the safety property.** A finding is fixed only when it FAILED and was not
suppressed. Everything else is left alone, and each exclusion is its own
argument:

- **UNKNOWN is the dangerous one.** The check could not read the parameter, so
  it has established nothing about the host. Writing configuration on the
  strength of that is acting on a guess, and the guess is acted on as root.
- **NOT_APPLICABLE** has nothing to fix; the subject is not on this host.
- **SKIPPED** was deliberately not run.
- **A suppressed finding is an operator saying what they want to happen.** An
  engine that silently undid one would make the suppression file a record of
  nothing. It is not even listed as unfixable, because an operator reads that
  list as work still outstanding.

Failures with no fix in this build are carried in the plan and counted in the
block. A script that listed four fixes and said nothing about the other
thirty-two failures would read as the whole of what is wrong with the host,
which is the most damaging thing a security tool can imply.

**Idempotency is the property the engine rests on, and it is a pure function.**
A host is scanned and remediated repeatedly, and a fix that appended a line each
time would grow `/etc/sysctl.d/99-plumbline-hardening.conf` until something
downstream broke on it. `Merge(existing string, pairs map[string]string) string`
is the rule: the first line setting a key is replaced in place, later duplicates
are dropped, an absent key is appended, and everything else — comments, blanks,
keys nobody asked about — is kept exactly as it was. From which
`Merge(Merge(x, p), p) == Merge(x, p)`, asserted directly at nine starting
shapes rather than inspected.

**In place rather than delete-and-append**, which was the simpler implementation
and the wrong one: appending moves a key to the end of the file on the run that
first corrects it, and sysctl applies last-wins, so a key an operator had
deliberately placed *before* a later override would silently change meaning.

The script is a second implementation of the same rule, in awk, and that cost is
paid deliberately: plumbline will apply a plan with `Merge` — pure Go, through
the seam, no shell — and the printed helper exists so an operator can read what
that would do and run it by hand on a host plumbline is not installed on. The
two are held together by a test that **runs the generated script twice against a
temporary file** and compares the result with `Merge`'s, so a change to either
that the other did not follow fails the build rather than the host. That test is
why `Options.DropIn` is a field and not a constant.

awk rather than sed because the rule is not a substitution: first occurrence
replaced, later ones removed, absent key appended. A sed one-liner does the
first of those and quietly gets the other two wrong.

**Commands are carried as argv and as text at once.** `Action.Argv` is what a
later phase would execute through `internal/system`, which takes an argument
vector and never a command line; `Action.Commands` is the same list quoted for a
human. They are generated together, so the thing reviewed and the thing run
cannot be different things.

`--fix` is refused under `--format json` and `--format sarif`. stdout is a
document there, and appending shell to it produces something no parser accepts —
out of a flag whose entire purpose is to be reviewed before anything runs.
Refused rather than quietly written to stderr: a script an operator asked for
and cannot find is worse than one they were told they could not have here.
`eval` has no `--fix` at all, because a bundle can be a month old and from
another host, and proposing changes to *this* machine from it would be proposing
them for the wrong one.

Four checks are covered: `KERNEL-0004` (dmesg_restrict), `KERNEL-0016`
(tcp_syncookies), `KERNEL-0026` (accept_ra, both pseudo-interfaces, because
neither alone is the effective setting) and `KERNEL-0030`
(protected_hardlinks). Each sets the running kernel *and* the drop-in: `sysctl
-w` alone is undone by the next reboot, and a line in a file alone does nothing
until something applies it.

The keys and values are written out in the fix rather than read back from the
catalog's remediation prose. Every one of those checks already says "Set
kernel.dmesg_restrict to 1" in English, and parsing it would make the wording of
a summary — reviewed as prose, changed freely in a patch release — the thing
that decides what plumbline writes to `/etc/sysctl.d` as root.

**Nothing applies a plan, and there is no phase that will.** plumbline is a
script generator: it produces reviewable, idempotent shell for an operator to
run, and does not execute root modifications inside the scanner process. That is
settled rather than deferred, which is why `Action.Argv` — a field that existed
only so a later execution phase would have an argv to hand to `system.Exec` — was
removed rather than kept. A field held for a phase the project has disclaimed is
a promise, and the quoting it was carrying is not lost: every command assembled
from host data still goes through `command()`, which quotes each argument.

### Beyond sysctl

Five more fixes, and they are not all one shape:

| Check | What the script does |
|---|---|
| `AUTH-0004` | Strips `nullok`/`nullok_secure` from the `pam_unix.so` rules **the finding named**, each file backed up first |
| `FILESYS-0003` | `chmod o-w` on the world-writable **files** cited |
| `FILESYS-0004` | `chmod a+t` on the world-writable **directories** cited |
| `CRON-0001` | `chown root:root` and `chmod 600` on the crontab the finding names |
| `CONTAINERS-0001` | Merges `"userns-remap": "default"` into the daemon configuration, in python, backed up first |

**`FILESYS-0004` is here because the request named `FILESYS-0003` and described
`FILESYS-0004`.** `chmod +t` was asked for; `FILESYS-0003` is *No file is
world-writable* and the sticky bit does nothing on a file. Rather than pick one
reading, both are implemented with the command that is right for each — and the
pairing is asserted, because getting them the wrong way round produces either a
script that does nothing or an outage: removing the write permission from
`/tmp` breaks the host, and that is precisely what the sticky bit exists to
avoid having to do.

**Paths come from the finding, never from a constant.** `/etc/pam.d/common-password`
is the Debian family's; RHEL keeps the same rules in `/etc/pam.d/system-auth`,
and a service that has diverged from the shared stack has diverged exactly
there. `AUTH-0004` reports every file it found the argument in, and the fix
edits those. The same holds for the crontab and for `daemon.json`, which is not
always `/etc/docker/daemon.json` — a daemon started with `--config-file` uses
another, and writing the default would produce a file the running daemon never
reads.

**A path is a string read off the machine being audited.** Pasting one into a
command line unquoted is a shell injection with a root prompt at the end of it,
out of a file name — the one thing on a Linux host that can contain very nearly
anything. `command()` quotes every argument, and
`TestAPathFromTheHostIsQuotedIntoTheScript` feeds it a world-writable file whose
name closes the argument and starts a second command.

**The backup is taken once and never overwritten.** `cp file file.bak` on a
second run would replace the backup with the already-edited file and destroy the
only copy of what the host looked like before plumbline touched it. The guard
makes the backup a record of the original rather than of the previous run, and
keeps the step idempotent with everything else. `-p` keeps mode, ownership and
timestamps, so it is a restorable original rather than a root-owned 0644
approximation.

**`daemon.json` is parsed, not edited.** It is JSON the daemon refuses to start
on if it is malformed, so a substitution that got a comma wrong takes Docker down
at the next restart — which on many hosts is every workload on the machine. The
helper parses, sets one key, writes it back with sorted keys, and *refuses* on a
file that is not valid JSON or is not an object. A run that finds the key already
correct rewrites nothing at all, so a second run does not even change the mtime.
python3 rather than jq because it is present on every distribution that ships
Docker and jq frequently is not; a host with neither gets an instruction, not a
sed expression aimed at JSON.

**The script embeds nothing from the host's `daemon.json`.** The collector
records that file's top-level key names and never their values, because it holds
registry mirrors, proxy URLs and storage paths and a bundle travels (ADR-0015) —
and a generated script that pasted the contents in would put exactly what the
bundle refuses to carry into a file an operator might attach to a ticket. The
helper reads the file on the host at the moment it runs.

**Every path fix says what it does not cover.** A finding's evidence is capped,
so a script built from it can be five `chmod`s standing for four hundred files.
A partial list that does not say so reads as a complete one, so each action
carries the count it is working from and the `find` command that enumerates the
rest.

**Helpers are emitted only where they are called**, matched on the call rather
than on which fixes are in the plan — a second registry to keep in step would be
wrong for one release and nobody would notice, because the symptom is a script
that fails on the operator's host with "command not found". The scan is
transitive, so a Docker-only script pulls in `plumbline_backup` because
`plumbline_json_set` calls it.

### `--write-script`

`--fix --write-script PATH` also writes the script to a file, at
`system.ScriptMode` — **0700**. The difference from `BundleMode` is the execute
bit rather than the secrecy: this is the exact list of commands that would change
a host's security posture, and a group-writable copy on a shared machine is an
invitation to edit it in the window between the review and the run, which is the
one moment nobody is looking at it. The mode is applied after opening, because
`O_CREATE` sets permissions only on a file that did not already exist.

It is written *after* the block is printed, so a bad path or a full disk cannot
cost the operator the script they can already see. The confirmation goes to
stderr, for the reason `bundle saved to` does: it is a note about this run rather
than part of the document, and a report redirected to a file should not end with
a line about where a different file went. `--write-script` without `--fix` is a
usage error rather than a silent no-op.

What this leaves:
- **The plan does not read the host's current drop-in.** `fact.Sysctl.Configured`
  already carries which file sets each probed key and to what, so a plan could
  say "the file is already right, only the running kernel is wrong" and propose
  `sysctl --system` alone. It was left out because the printed script has to be
  idempotent on its own terms — an operator may run it a week later, against a
  file that has changed — and a script that assumed a scan's snapshot would
  append a duplicate the moment that assumption expired.
- **Six checks of thirty-six failing on this host.** What the engine covers is
  still small, and the block says how much it does not cover every time it
  prints.
- **`chown root:root` is asserted as text and not run in tests.** It needs root,
  and the suite runs unprivileged by design. The mode half of `CRON-0001` is
  executed; the ownership half is checked by reading the generated line.

### The row loses its ID

A streamed row was `  - Checking <title> (<ID>)...`, and the ID and the ellipsis
were three-quarters of the furniture on every line. Both are gone: a row is the
verb, the title and the verdict.

**The argument that put the ID there was sound about the ID and wrong about the
stream.** It said the ID is what a suppression file matches on and what
`plumbline explain` takes, so it belongs in the row's fixed tail where a narrow
terminal cannot squeeze it out. All true — and an ID is for *copying*, while the
stream scrolls past at a tenth of a second a row and nothing can be copied out of
it. The report underneath carries the ID on every entry and is still on screen
when the scan ends. So the ID was costing the title columns on exactly the
terminals where the title had none to spare, to carry a field that was already
somewhere better.

`TestTheCheckIDSurvivesEveryWidth` is replaced by
`TestAStreamedRowIsATitleAndAVerdict`, which asserts the reverse at the same
eight widths. A collector's elapsed time stays in the tail: `(41s)` is the
answer to the question a person watching a long collector is actually asking.

The compact form went with it. It existed to keep the ID on screen when the
title had been squeezed to nothing, and with no ID there is nothing to fall back
to — a window too narrow for even one column of title now produces a row exactly
one column over rather than a wrapped one, which is the policy the gap clamp
already followed.

### The warnings list

The stream was fixed and the report it hands over to was not. `entry` printed
every field a finding held — severity, unknown reason, subject, detail, up to
five evidence excerpts with their sources and line numbers, then the remedy, its
effort and its caution. Eleven or twelve lines each. Thirty-six warnings on this
host, and `scan --verbose` produced **1,501 lines**, of which the warnings
section alone was **1,333**.

It is now a bullet and a hanging block of prose — 337 lines and 170:

```
  - [HIGH]    PAM does not accept an empty password [AUTH-0004]
      Details: Remove nullok from every pam_unix.so auth rule, and check for
               accounts that were relying on it.
  - [UNKNOWN] No setuid or setgid executable is writable by gr… [FILESYS-0001]
      Details: source truncated
```

**The argument is not that the detail was wrong; it is that the terminal was
the wrong place for it.** A reader of a scrolling report is asking one question
— what do I do next — and every field that is not the answer is between them
and the next finding. A document nobody reads is not a safety feature however
complete it is. Everything removed is still produced and still retained: the
JSON and SARIF renderers carry every field including the whole evidence array,
and `docs/checks/<ID>.md` carries the full remediation with its steps and its
commands. The terminal is the one output where being exhaustive costs the
reader something.

The details line is the remedy, falling back to the subject, falling back for an
`UNKNOWN` to why it could not be determined — spelled out (`ambiguous system
state`) rather than left as the machine token, which the JSON keeps matching on.

**The first cut of this truncated it at the grid, and that was wrong in a way
worth recording.** The reasoning was that "two lines a finding" was the property
being defended, so a remedy that reflowed to four would undo the change. It
defended the wrong thing: the details line is the one sentence in the report
that tells an operator what to type, and cutting it mid-clause left the half
restating the problem and dropped the half naming the fix. A concise section
nobody can act on is not an improvement on a long one nobody reads. It wraps,
with a hanging indent to the column the value starts in, so a three-line remedy
is still visibly one value belonging to one finding and the left edge of the
prose is a straight line down the page. `TestALongRemedyWrapsAndIsNotCutOff`
reassembles the wrapped lines and compares them against the original, so the
claim under test is "nothing was lost", not "it wrapped somewhere".

**The wrap width follows the terminal, and only for this section.** The first
cut held it to the fixed 78 columns on the grounds that the report is an
artifact somebody diffs — which is true of the artifact and false of the
terminal it was also being drawn on, where 78 columns in a 160-column window
folds a sentence that had room to finish. Both are now served, and what chooses
between them is `TIOCGWINSZ` on the *destination writer* rather than a flag: the
ioctl answers for a terminal and fails for a file, so `plumbline scan >
report.txt` produces the same bytes from any window it is run in, and no mode
can be set wrongly. Only the warnings section moves; the section rules, the scan
phase's status column and the dashboard boxes stay on `reportWidth`, because
those are the furniture a diff would be full of. The terminal width is clamped
to [40, 120] — prose at 200 columns is prose the eye loses on the return sweep,
and 120 is the ceiling `streamMaxWidth` already argues for.

**Severity is back, as a padded coloured tag ahead of the title** — red for
CRITICAL and HIGH, yellow for MEDIUM, blue for LOW, magenta for `[UNKNOWN]`,
and INFO left unpainted because colouring every row is the same as colouring
none. The tag is padded to the widest one in the section, measured across both
blocks, so the titles held a single column — and that padding was then removed
again. It cost four columns of every line on a host with anything critical on
it, to buy a column of nothing: the tag is coloured, and the colour is what the
eye runs down, so the alignment was doing the work twice and charging for it.
One space follows the tag. An `UNKNOWN` is tagged `UNKNOWN` rather than by its
severity,
which is this package's oldest argument compressed into one column — a check
that could not be evaluated has established no degree of badness, and printing
`[MEDIUM]` beside it would claim one.

`evidence`, `remediation` and the `maxEvidence` cap were **deleted** rather than
left unused. A dead printer in a file is a reader's reasonable belief that the
terminal still has a way to show that field.

`UNKNOWN` keeps equal weight, which is this package's oldest argument and the
one most easily lost to a change like this. It gets the same two lines under its
own heading, and `TestEveryWarningEntryIsExactlyTwoLines` asserts the shape by
structure rather than by a list of forbidden field names — a list is something
somebody has to remember to extend when a finding grows a field.

What this leaves:
- **The entry height is no longer fixed.** Wrapping is the right call and it
  gives up the one thing truncation bought: a section whose length can be
  predicted from the number of findings. Thirty-six warnings are eighty-one
  lines on this host and would be more on one with longer remedies. Nothing
  depends on it today; it is written down because "two lines a finding" was a
  property somebody could have built on.

---

## SERVICES, sandboxing

`SERVICES-0006` audits `NoNewPrivileges` on `cron.service`,
`systemd-journald.service` and `dbus.service`. It is the module's sixth check
and its first to open a unit body, which the other five deliberately do not.

Three things it produced that outlive the check:

- **One implementation of systemd's unit assembly, `internal/collect/unit`.**
  Search-root precedence, drop-in gathering, basename shadowing, lexical
  ordering across directories, masked and symlinked units. It came out of the
  Docker collector, which had it first and now calls it. The rules are
  systemd's, they move verdicts rather than details, and two implementations
  would have been two answers on the same host — the same argument that put
  `dockerd`'s socket grammar in one file for `CONTAINERS-0006` and `-0007`.
- **A directive allowlist enforced during the parse is a privacy boundary, not
  a filter.** `unit.Request.Directives` names what to keep and everything else
  is discarded as the file is read, so `Environment=` is never held. A filter
  applied afterwards is one a later collector forgets; there is nothing here to
  forget. It is what makes "the SERVICES module reads no unit bodies" turn into
  a bounded exception rather than an abandoned rule.
- **systemd's boolean grammar is wider than its documentation and is not
  uniformly case-insensitive.** `parse_boolean` takes `1/0` compared exactly and
  `yes/y/true/t/on` and `no/n/false/f/off` compared case-insensitively — and an
  unparseable value is *ignored with a warning*, not read as false, so the file
  can say one thing while the host does another. Any later check reading a
  systemd boolean should use the same parser rather than inventing a rule.

The module's honest limits here are three:

**The unit list is fixed and small.** Auditing every unit means reading every
unit body, which is what the enablement collector exists in order not to do.
Growing the list is a work package with a fixture per addition, not a constant
to extend casually — and the interesting question is not how to read more units
but which ones are worth the disclosure.

**The exemption mechanism is the interesting part, and it needed a guard.**
`NoNewPrivileges` breaks `cron.service` (jobs inherit `no_new_privs` and stop
being able to call `sudo`) and `dbus.service` (setuid
`dbus-daemon-launch-helper`), so both are exempt and named with the reason in
every verdict. Three properties turned out to be worth enforcing in code rather
than trusting an author with, and they generalise to any check that grows an
exemption list:

  - **An exemption is not a suppression.** A suppression belongs to a host and
    may reasonably be invisible; an exemption is a claim about the software and
    must not be. Exempt units are named whether the check passes or fails, and
    the verdict says in as many words that nothing was suppressed.
  - **It never excuses what could not be read**, because it is a claim about a
    configuration that was seen. Excusing an unreadable file turns "I could not
    look" into "it is fine", which is the substitution `UNKNOWN` exists to
    prevent.
  - **It cannot make the check vacuous.** If nothing on a host was actually
    held to the standard the result is `NOT_APPLICABLE`, not `PASS`. With two
    of three units exempt, one more reasonable entry would otherwise convert
    this check into a green tick that means nothing — silently, and with each
    step looking defensible. That is rule 3's failure mode arrived at by
    increments, and it is the thing to watch for in every later module that
    wants exemptions.

What the mechanism did not solve is that `-0006` is thin:
`systemd-journald.service` is the only audited unit that can fail it.
`SERVICES-0007` is the answer to that, and it arrived at a better place than
widening the unit list would have.

**`ProtectSystem` is the better first directive, and the exemption lists are
the evidence.** It carries one exemption where `NoNewPrivileges` carries two,
because the reason dbus needs `NoNewPrivileges` off — a setuid launch helper —
says nothing about where the daemon may write, and on a systemd host
dbus-activated services are started by systemd as their own units rather than
as children of dbus. So `-0007` has two auditable units where `-0006` has one,
at `HIGH` rather than `MEDIUM`, and on a stock systemd 259 host it finds
something: journald ships `NoNewPrivileges=yes` and no `ProtectSystem` at all.

That is also the argument for **exemptions being per-check rather than a shared
"awkward services" list**, which was the tempting shape. A shared list would
have exempted dbus from both and cost `-0007` half its subject to a reason that
did not apply to it. An exemption is a claim about one setting on one unit.

`SERVICES-0008` finished the triad and the answer was: the same unit again, for
a third distinct reason. cron is exempt from all three — jobs that escalate,
jobs that write, jobs that live in a home directory — and dbus from exactly
one. That one unit on one of three lists is the clearest evidence the lists had
to be per-check.

**Three copies of the same loop was one copy too many.** `partitionUnits` now
owns the ordering all three depend on — pass before exemption, unreadable
before either, masked neither — and each of those was a property previously
asserted three times and implementable wrongly three times. A fourth check gets
them by construction. The rule of thumb it produced: when a mechanism's
*correctness properties* are being restated per caller, the mechanism is in the
wrong place, and that is a stronger signal than the amount of duplicated code.

**A grammar's case rules are worth reading rather than assuming**, and this cost
a shipped bug. `ProtectSystem` and `ProtectHome` both take a value that is a
superset of the booleans, and the two halves disagree: `parse_boolean` compares
its words with `strcaseeq`, while the enum names go through a string table
looked up with `streq`. `ProtectSystem=Full` is therefore *rejected* by systemd
— logged, ignored, default left in force — and catalog 23 read it as `full` and
passed a host with `/usr` writable. Folding the enum half is the dangerous
direction of the two, because it converts an unprotected service into a green
tick. Any later check reading a systemd enum should assume case matters until
it has read the table.

The remaining sandboxing directives — `PrivateTmp`, `PrivateDevices`,
`RestrictAddressFamilies`, `SystemCallFilter` — are a different shape of
question. They are cheap to collect and hard to judge: the right value depends
on what the daemon does, far more than `ProtectHome` does, and a check that
demanded `SystemCallFilter=@system-service` of every unit would be exemptions
all the way down. `systemd-analyze security` exists and scores rather than
judges, which is probably the right instinct; whether this tool should
reproduce it is a design question and not a coding one.

**The corpus does not exercise it.** All six golden bundles predate
`services.hardening`, so `SERVICES-0006` is `UNKNOWN` on every one. Unlike the
CONTAINERS three this needs no new software to fix — every one of those hosts
has a `systemd-journald.service` — so a re-recording clears it on its own.

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
| Auto-*generation* of remediation | **Shipped, in its first phase.** `scan --fix` prints a script. See *The remediation engine* above. |
| Auto-*application* of remediation | **Never.** See `PROJECT-BRIEF.md` §1.3. Generating is a review step; applying is the thing this project does not do, and no flag has been added that would. |
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
