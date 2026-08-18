# PLUMBLINE — Project Brief

**Status:** v0 — pre-build
**Owner:** Antaryx
**Supersedes:** `argus-project-design.md` v0.1

---

## 1. Identity

| Field | Value |
|---|---|
| **Name** | Plumbline |
| **Binary** | `plumbline` |
| **Module path** | `github.com/antaryx/plumbline` |
| **Tagline** | *Hang a line. See what's true.* |
| **Origin** | A plumb line is a weighted cord that reveals true vertical. It does not defend the wall, it does not build it — it tells you, unarguably, how far off true the wall already is. Deviation is measured against a known reference; the measurement is repeatable and the instrument is trivially auditable. |
| **Language** | Go 1.23+ |
| **Licence** | Apache-2.0 (code) — see `COMPLIANCE-DATA-POLICY.md` for data |
| **Versioning** | SemVer for the binary, independent versions for catalog / schema / vuln data (see `VERSIONING.md`) |
| **Stable releases planned** | v1.0.0, v2.0.0, v3.0.0 |

### 1.1 Why this name

The name has to survive three filters: is it taken in the security tooling space, does it mean something that maps to what the tool does, and can you type it.

"Plumbline" passes all three. Searching security tooling and GitHub surfaces no host-auditing project using it; the metaphor is exactly right (measure against a reference, report deviation, do not pretend to fix the wall); and it is one memorable word.

It is also *not* a Greek-mythology name. Every second security tool is Argus, Aegis, Cerberus, Talos, Sentinel or Hydra — the pool is exhausted and the collision rate is near-total. A metrology metaphor puts the project in the honest half of this market: instruments, not guardians.

**Before you commit to it, verify yourself** (takes ten minutes, and the auditor of this document is not your trademark lawyer):

- [ ] `github.com/plumbline` and `github.com/antaryx/plumbline` available
- [ ] `plumbline.dev` / `plumbline.io` available
- [ ] No hit on `pkg.go.dev/search?q=plumbline`
- [ ] No live mark in your jurisdiction (India: IP India public search; US: USPTO TESS) in classes 9 / 42
- [ ] No Homebrew formula, no Debian source package, no crates.io/PyPI/npm name squatting the term
- [ ] Not offensive or unpronounceable in the languages of your likely users

**Backups, in order**, if any check fails: **Bartizan** (the overhanging turret built into a wall specifically as a lookout post — obscure, free, good logo), **Revetment** (the stone facing that protects an embankment), **Assay** (the determination of what something is actually made of — cleanest meaning, but collides with biotech tooling).

### 1.2 What Plumbline is

> A deterministic, offline, evidence-first host posture auditor for Linux.

Three properties define it, and every design decision defers to them:

1. **Collect once, evaluate many.** A scan captures a *fact bundle* — the raw system state, typed and timestamped. Findings are derived from the bundle, never read live from the machine. You can re-evaluate a six-month-old bundle against today's check catalog without touching the host.
2. **Deterministic.** The same bundle plus the same catalog version yields byte-identical findings. Two people on two machines auditing the same bundle get the same answer, always.
3. **Honest.** No invented compliance percentages, no scores that silently change meaning between releases, no confident findings from unreliable techniques. Where the tool cannot know, it says `UNKNOWN`, and that is a first-class result state.

### 1.3 What Plumbline is not

Carried forward from the source document, which got this right, and *not* contradicted later in the roadmap:

- **Not a network scanner.** It audits the host it is pointed at. No port scanning of other hosts, ever.
- **Not a SIEM or an agent.** Point-in-time bundles. No daemon, no continuous monitoring, in any planned version.
- **Not a patch manager.** It reports outdated software. It never installs anything.
- **Not an exploit framework.** Privilege-escalation surface is *mapped and explained*, never exercised.
- **Not a compliance certification.** It produces evidence. Humans and auditors produce conclusions.
- **Not a remediation robot.** From v2 it generates scripts. It does not run them. Ever. There is no `--fix` flag and there never will be — a tool that can rewrite `/etc/ssh/sshd_config` as root, based on a heuristic, on a machine you cannot see, is a tool that eventually locks someone out of production.

---

## 2. The problem

An operator who wants to know whether a Linux host is well configured has three unsatisfying options:

- **Lynis** — mature, wide, shell-based. The findings are advisory text; output is hard to consume programmatically; there is no way to re-audit a past state; correctness is hard to verify because behaviour depends on the machine it ran on.
- **OpenSCAP / SCAP profiles** — rigorous and standards-backed, but heavy, XML-centric, awkward to extend, and the tooling assumes an enterprise context.
- **Ad-hoc scripts** — every team has one. Untested, undocumented, unowned.

None of them let you answer the two questions that matter most in practice:

> *"What changed on this host between March and today?"*
> *"Was this host actually configured that way at the time of the incident, or are we reconstructing?"*

Answering those requires the state to be captured, not just judged. That is Plumbline's wedge.

---

## 3. Users

Cut from the original six personas to three, because a v1 that serves three well beats a v1 that serves six adequately.

| Persona | What they need | What they get |
|---|---|---|
| **Sysadmin / homelab operator** (primary) | "Is this box sane? What should I fix first?" | One binary, one command, a ranked list with copy-pasteable fixes |
| **DevSecOps engineer** | Machine-readable posture in CI, no false-positive noise | Stable JSON schema, SARIF, deterministic exit codes, suppression files |
| **Incident responder / auditor** | Defensible evidence of configuration at a point in time | Signed fact bundles, re-evaluable offline, diffable across time |

Deferred to v3 or never: penetration testers (v2, via the PRIVESC module), compliance officers (v2, evidence packs — never scores), plugin authors (v3).

---

## 4. Differentiation

Against the incumbent, stated honestly — this table describes **v1 as scoped**, not aspirations:

| Dimension | Lynis | Plumbline v1 |
|---|---|---|
| Implementation | POSIX shell | Single static Go binary, no interpreter, no CGO |
| Evaluation model | Judged live, on the host | Facts captured, findings derived from the bundle |
| Re-audit past state | Not possible | `plumbline eval bundle.tar.zst` — offline, any time |
| Determinism | Depends on host and environment | Same bundle + catalog = identical output |
| Scan a mounted image / container filesystem | No | `--root /mnt/host` |
| Machine-readable output | Limited | Versioned JSON Schema + SARIF, both stable APIs |
| Diff across time | No | `plumbline diff a.bundle b.bundle` |
| Check test coverage | Hard to assess | Every check has fixture-based tests; coverage published |
| Breadth of checks | ~300, mature, many platforms | ~110 at v1.0.0, Linux only |
| Platform coverage | Linux, macOS, BSD, Solaris, AIX | Linux only until v3 |
| Ecosystem maturity | 15+ years | New |

The last three rows exist deliberately. If the comparison table only lists dimensions you win, nobody believes any of it.

---

## 5. Design principles

1. **Facts before findings.** If it is not in the bundle, no check may assert it.
2. **A check is a pure function.** Facts in, findings out. No IO, no clock, no randomness, no network.
3. **`UNKNOWN` is a valid answer.** A check that cannot determine the answer says so. It never guesses PASS.
4. **Every finding carries its evidence.** The exact bytes the verdict was derived from, with the source path and how it was read. A finding without evidence is a rumour.
5. **Every finding carries a fix.** Steps a human can follow, and where safe, a command. Both, not either.
6. **Nothing runs on the target that does not need to.** No daemon, no installed agent, no persistent state on the host unless asked.
7. **The scan path never touches the network.** Not for CVE lookups, not for telemetry, not for version checks. Network use is confined to explicit, separate subcommands (`plumbline db fetch`).
8. **Stability is a feature.** Check IDs are permanent. Schema changes are versioned. Exit codes are a contract.
9. **Say what you don't know.** Coverage is reported alongside every score.

---

## 6. Scope summary

Full detail in `ROADMAP.md`. In one line each:

- **v1.0.0 — Trustworthy core.** Linux, ~110 checks in 10 modules, fact bundles, terminal + JSON + SARIF, diff, deterministic exit codes, no network, no plugins, no compliance scoring.
- **v2.0.0 — Intelligence.** Vulnerability correlation via vendor security feeds, containers module, privesc module, HTML reports, remediation generation, user-supplied compliance mapping packs, evidence packs.
- **v3.0.0 — Reach.** Declarative check packs and a subprocess extension protocol, macOS, fleet aggregation, policy-as-code baselines, stable public library API.

---

## 7. Success criteria

Deliberately modest and measurable, since this is a portfolio and learning project first.

**v1.0.0 is successful if:**
- It runs clean on Ubuntu 22.04/24.04, Debian 12/13, Fedora, and Alpine with zero crashes and zero unhandled panics across the fixture corpus.
- Check catalog test coverage ≥ 95% of checks having at least one PASS and one FAIL fixture.
- A full scan of a normal server completes in under 90 seconds (measured, then published as the budget in `PERFORMANCE.md`).
- The false-positive rate on a freshly installed, unhardened distro is understood and documented per check — not zero, but *known*.
- Someone other than the author successfully runs it and files an issue.

**v2.0.0 is successful if:** the vulnerability correlation produces fewer false positives on a stock Ubuntu LTS host than a naive NVD matcher would — and this is demonstrated with a published comparison, because that comparison is the entire argument for the feature.

**v3.0.0 is successful if:** a third party writes and ships a check pack without modifying the core.

---

## 8. Non-negotiables

Things that do not get traded away under schedule pressure:

- No telemetry, no phone-home, no analytics, in any version, ever.
- No `--fix` / auto-apply flag.
- No compliance percentage figures.
- No redistribution of licensed standards text.
- No check merged without fixture tests.
- No release without a signed, verifiable artifact and an SBOM.
- No claiming support for a platform that is not in CI.
