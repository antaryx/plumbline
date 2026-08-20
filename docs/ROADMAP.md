# ROADMAP — Plumbline

**Three stable majors.** Each is a complete, defensible product on its own. If development stops after any of them, what exists is still worth using.

> **Where the project actually is — 2026-08-20.** `v0.2.0` is tagged and shipped
> 78 checks across nine modules at catalog version 11. `main` is now ahead of
> it at **79 checks, catalog version 12** (WP-25: walker aggregation and
> FILESYS-0010), and the default output is a human-readable terminal report
> with `--json` for pipelines (WP-26). The output schema is `findings-v1`, and
> the tool runs offline with no network code path in any build. `v0.3.0` is
> open; its scope is in the pre-1.0 section below.
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

Pre-1.0 there are three internal milestones (v0.1 – v0.3) that are *not* public stable releases. They exist to force integration early; the source design's eight 0.x milestones were a plan to build eight products before shipping one.

---

## Pre-1.0 internal milestones

Tagged and released as pre-releases so the pipeline gets exercised, but with an
explicit "no stability guarantees" banner.

**Status at 2026-08-20:** v0.1.0 and v0.2.0 are complete and tagged. v0.3.0 is
open and has begun. The schema is `findings-v1` throughout.

| Milestone | State | Catalog | Checks | Shipped |
|---|---|---|---|---|
| v0.1.0 — walking skeleton | **complete** | 1 | 8 | tagged `v0.1.0` |
| v0.2.0 — catalog machinery | **complete** | 11 | 78 | tagged `v0.2.0`, 2026-08-20 |
| v0.3.0 — feature complete for v1 | **in progress** | 12 | 79 on `main` | — |

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
  package names or service names. `docs/BUILD-RUNBOOK-v0.2.md` forbids a name
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

### v0.3.0 — Feature complete for v1 — **IN PROGRESS**

Three themes, in this order: **engine maturation**, then **UX and CLI polish**,
then **edge-case resilience**. The ordering is deliberate — every UX decision
below is a rendering of something the engine must be able to state first, and
resilience work is only meaningful once there is a surface to be resilient at.

#### 1. Engine maturation

- ~~**Aggregating walker interests**~~ — **done, WP-25, catalog 12.** The walker
  recorded rows: the first N inodes matching a pure predicate. That answers
  "show me the setuid binaries" and cannot answer "does every uid on disk
  resolve to an account", because the join is against a fact that does not
  exist when the predicate is registered, and matching every owned inode would
  overflow the row cap on any host that has users. A `Tally` folds inodes into
  a bounded keyspace during the walk — counts and one exemplar per key — so the join
  happens in the check, where facts exist. Fact namespace `fs.tally.<name>`.
  First consumer: FILESYS-0010, unowned files.
- ~~**Name-service awareness.**~~ **done, WP-25.** `nsswitch.conf` decides
  whether `/etc/passwd` is the whole account database, and four USERS check
  specs had already named this as a known limitation. Now collected as
  `users.nsswitch`. It is a precondition for any check that concludes an
  identity does *not* exist, and FILESYS-0010 is the first to need it. The
  remaining work is retrofitting the USERS checks that documented the gap.
- **Listener enumeration** — `/proc/net/tcp`, `tcp6`, `udp`, `udp6` plus the
  socket-inode-to-process join through `/proc/*/fd`. Unlocks the NETWORK checks
  cut from v0.2.
- **Package inventory** — dpkg and rpm database reads, no CVE claims. The v1
  scope line says inventory only, and it is what `INTEGRITY` and the whole of
  v2 rest on.
- **Remaining modules and checks toward the v1 ceiling**: `SYSINFO`, the AUTH
  balance, the NETWORK balance, and the `FILESYS` mount coverage. FILESYS
  unowned files landed with the tally that made it possible.

#### 2. UX and CLI polish

- ~~**Terminal renderer**~~ — **done, WP-26.** `internal/render/text` is the
  default output: header, per-module listing, a full block for every FAIL *and*
  every UNKNOWN, and a summary that states the UNKNOWN count on its own line
  rather than burying it. An auditor who cannot see what the tool failed to see
  is reading a different report than the one it produced. `--no-color`,
  `NO_COLOR` and a non-terminal stdout each suppress colour; `--output` is
  never coloured. `--format json` (or `--json`) keeps the pipeline path, and a
  test asserts the format cannot move the exit code.
- **SARIF renderer** with stable fingerprints across runs and across catalog
  versions.
- **`plumbline diff`** — bundle to bundle, so drift is a first-class output
  rather than something a user reconstructs from two JSON files.
- **Suppression file format** — suppressions carry a reason and an expiry, and
  a suppressed check is reported as `SKIPPED` with the reason, never omitted. A
  suppression that silently disappears from the output is how a finding gets
  lost.
- **`plumbline doctor`** — what this scan could and could not see, before it
  runs: euid, readable paths, missing collectors, budget headroom.
- **`check list` / `show` / `explain`** — the catalog is the product; it needs
  to be legible without reading Go.
- **Exit code contract** implemented and tested per branch.

#### 3. Edge-case resilience

- **`--root` verified against a real mounted image and a container filesystem**,
  not only against fixtures. The escape-refusal rule has unit tests; it has
  never met a real overlayfs.
- **musl and Alpine** in CI. `live` uses `syscall.Stat_t` and `O_NOFOLLOW`;
  neither is guaranteed to behave identically.
- **Golden bundles for ≥6 distro/version combinations**, which is a v1 release
  criterion and cannot be back-filled quickly.
- **Determinism under adversarial ordering** — directory entries returned in a
  hostile order, duplicate mount points, `..` in mountinfo fields.
- **Budget behaviour on a host that is genuinely large**: 2M+ inodes, and the
  assertion that a fired budget produces `UNKNOWN` findings rather than a
  truncated scan that reports `PASS`.

**Exit criteria:** feature freeze. Everything after v0.3.0 is bug-fixing,
documentation and fixture expansion.

---

## v1.0.0 — Trustworthy core

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
| `FILESYS` | 14 | **9** | Consumes the shared walk. Unowned files needed walker aggregation and landed after the tag, at catalog 12 (WP-25) |
| `LOGGING` | 8 | **5** | |
| `CRON` | 8 | **5** | |
| | **~120** | **78** | catalog version 11; `main` is at 79 / 12 |

**~120 checks was always a ceiling, not a target.** Cut to whatever fits the
schedule; check count is the flex, correctness is not. The 42-check gap at
v0.2.0 is accounted for module by module in the pre-1.0 section above, and none
of it is work that was forgotten.

### Release criteria — all must hold

- [ ] Every check has ≥1 PASS and ≥1 FAIL fixture; CI enforces
- [ ] Zero panics across the full fixture and hostile corpus
- [ ] Determinism test green: same bundle → byte-identical findings, 100 consecutive runs
- [ ] Offline test green: full scan succeeds in a network-less namespace
- [ ] Golden bundles for ≥6 distro/version combinations
- [ ] `findings-v1.schema.json` published, validated in CI, and frozen
- [ ] Scan of a reference host completes within the published budget
- [ ] Signed release artifacts + SBOM + provenance, and documented verification steps a user can follow
- [ ] All v1-gating documents complete (`DOCUMENT-MAP.md` tier 0–4)
- [ ] `THREAT-MODEL.md` reviewed against the actual implementation, not the design
- [ ] Known false positives documented per check in `FALSE-POSITIVES.md`
- [ ] At least one external person has run it and filed an issue

### Explicit non-goals for v1

Restating, because these are what the schedule is bought with: no TUI browser, no HTML, no PDF, no plugins, no CVEs, no compliance scores, no macOS, no container module, no remediation scripts, no daemon, no web UI, no hosted anything.

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

2. **New modules** — `CONTAINERS` (Docker/Podman/K8s node config, ~15), `PRIVESC` (renamed from PENTEST, gated behind `--enable privesc` with an authorised-use notice, ~15), `MEMORY` (ELF hardening: RELRO, PIE, canaries, FORTIFY — self-contained and satisfying, ~10), `INTEGRITY` (package DB verification + bundle-to-bundle drift, ~9), `STORAGE`, `CRYPTO` (local certificate and key material only; still no network probing). Catalog to ~250 checks.

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
