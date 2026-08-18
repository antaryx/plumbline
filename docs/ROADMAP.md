# ROADMAP — Plumbline

**Three stable majors.** Each is a complete, defensible product on its own. If development stops after any of them, what exists is still worth using.

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

Tagged and released as pre-releases so the pipeline gets exercised, but with an explicit "no stability guarantees" banner.

### v0.1.0 — Walking skeleton *(~5 weeks)*

The thinnest possible end-to-end path, chosen so that every architectural risk is hit on day one rather than month four.

- `System` interface + `live` and `fake` implementations
- Bundle format v0: write, read, integrity manifest
- Collectors: `osrelease`, `passwd`, `sysctl`, `sshd_config`
- **8 checks** across AUTH and SSHD
- `plumbline scan`, `collect`, `eval` working end to end
- JSON renderer + `findings-v0.schema.json`
- Fixture harness with one Ubuntu 24.04 tree
- CI: build, vet, test, race, one distro container

**Exit criteria:** `collect` on a real host → `eval` on a different machine → identical findings across two runs, verified byte-for-byte by a test.

### v0.2.0 — Catalog machinery *(~6 weeks)*

- The single-pass filesystem walker with interest predicates, plus the hostile-fixture corpus (FIFOs, symlink chains, ANSI filenames, huge files, cyclic mounts)
- Collector DAG with cost classes, budgets and per-collector error capture
- All five result states wired through, including `UNKNOWN` propagation from `FactError`
- Scoring: posture + coverage, catalog version stamping
- Terminal renderer with `NO_COLOR`, non-TTY, and width handling
- **~45 checks:** KERNEL, AUTH, USERS, SSHD
- Suppression file format
- Golden bundles for 3 distros

**Exit criteria:** a full walk of a filesystem with 2M inodes completes inside budget; the hostile corpus produces zero hangs, zero panics, zero unbounded reads.

### v0.3.0 — Feature complete for v1 *(~7 weeks)*

- Remaining v1 modules → **~110 checks**
- SARIF renderer with stable fingerprints
- `plumbline diff`
- `plumbline doctor`, `check list/show/explain`
- Exit code contract implemented and tested per branch
- `--root` verified against a mounted image and a container filesystem
- Docs: all v1-gating documents drafted (see `DOCUMENT-MAP.md`)

**Exit criteria:** feature freeze. Everything after this is bug-fixing, documentation and fixture expansion.

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

| Module | Checks | Notes |
|---|---|---|
| `SYSINFO` | 6 | Informational facts; never scored |
| `KERNEL` | 15 | sysctl-driven, deterministic, easy to fixture |
| `AUTH` | 17 | PAM parsing is the hard part; budget for it |
| `USERS` | 10 | |
| `SSHD` | 20 | Requires resolving `Include`, `Match` blocks and defaults correctly — the effective-config collector is the real work here |
| `NETWORK` | 12 | Local state only: listeners, firewall rules present, sysctls |
| `SERVICES` | 10 | systemd + OpenRC + sysvinit |
| `FILESYS` | 14 | Consumes the shared walk |
| `LOGGING` | 8 | |
| `CRON` | 8 | |

**~120 checks.** Cut to whatever fits the schedule; check count is the flex, correctness is not.

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
