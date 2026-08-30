# Plumbline project brief

**Status:** v0, pre-build
**Owner:** Antaryx
**Supersedes:** `argus-project-design.md` v0.1

---

## 1. Identity

| Field | Value |
|---|---|
| Name | Plumbline |
| Binary | `plumbline` |
| Module path | `github.com/antaryx/plumbline` |
| Origin | A plumb line is a weighted cord that reveals true vertical. It does not defend the wall or build it; it measures how far off true the wall already is. Deviation is measured against a known reference, the measurement is repeatable, and the instrument is simple enough to audit. |
| Language | Go 1.23+ |
| Licence | Apache-2.0 (code); see `COMPLIANCE-DATA-POLICY.md` for data |
| Versioning | SemVer for the binary, independent versions for catalog / schema / vuln data (see `VERSIONING.md`) |
| Stable releases planned | v1.0.0, v2.0.0, v3.0.0 |

### 1.1 Why this name

The name had to pass three tests: whether it is already used in security tooling, whether it maps to what the tool does, and whether it is easy to type.

"Plumbline" passes all three. A search of security tooling and GitHub finds no host-auditing project using it, the metaphor matches the behaviour (measure against a reference, report deviation, do not fix the wall), and it is one word.

It is also not a Greek-mythology name. Argus, Aegis, Cerberus, Talos, Sentinel and Hydra are already heavily used in this space, so a collision is likely. A metrology metaphor avoids that.

Verify the name before committing to it. This takes about ten minutes, and the author of this document is not a trademark lawyer:

- [ ] `github.com/plumbline` and `github.com/antaryx/plumbline` available
- [ ] `plumbline.dev` / `plumbline.io` available
- [ ] No hit on `pkg.go.dev/search?q=plumbline`
- [ ] No live mark in your jurisdiction (India: IP India public search; US: USPTO TESS) in classes 9 / 42
- [ ] No Homebrew formula, no Debian source package, no crates.io/PyPI/npm name squatting the term
- [ ] Not offensive or unpronounceable in the languages of your likely users

Backups, in order, if any check fails: Bartizan (an overhanging turret built into a wall as a lookout post; obscure, unused, and it works as a logo), Revetment (the stone facing that protects an embankment), Assay (the determination of what something is made of, though it collides with biotech tooling).

### 1.2 What Plumbline is

> A deterministic, offline, evidence-first host posture auditor for Linux.

Three properties define it, and every design decision defers to them:

1. Collect once, evaluate many. A scan captures a fact bundle: the raw system state, typed and timestamped. Findings are derived from the bundle, never read live from the machine. A six-month-old bundle can be re-evaluated against today's check catalog without touching the host.
2. Deterministic. The same bundle plus the same catalog version yields byte-identical findings, on any machine.
3. Honest. No invented compliance percentages, and no scores that change meaning between releases. Where the tool cannot determine an answer it reports `UNKNOWN`, which is a first-class result state.

### 1.3 What Plumbline is not

Carried forward from the source document and not contradicted later in the roadmap:

- Not a network scanner. It audits the host it is pointed at, and does not port-scan other hosts.
- Not a SIEM or an agent. Point-in-time bundles only. No daemon and no continuous monitoring, in any planned version.
- Not a patch manager. It reports outdated software and installs nothing.
- Not an exploit framework. Privilege-escalation surface is mapped and explained, never exercised.
- Not a compliance certification. It produces evidence; humans and auditors produce conclusions.
- Not a remediation robot. It generates scripts and does not run them. `scan --fix` **prints** the work that would repair the failing checks it knows how to repair, and executes none of it — the block's first line says so. A tool that rewrote `/etc/ssh/sshd_config` as root from a heuristic, on a machine the operator cannot see, will eventually lock someone out of production, and that is the line: generating is review, applying is the thing this project does not do. An earlier revision of this section said there would be no `--fix` flag at all; the flag exists as of the remediation engine's first phase, in its proposal-only form, and the reasoning behind the original sentence is unchanged and still governs what it may ever do.

---

## 2. The problem

An operator who wants to know whether a Linux host is well configured has three options, each with limitations:

- Lynis: mature, wide, shell-based. The findings are advisory text, the output is hard to consume programmatically, there is no way to re-audit a past state, and correctness is hard to verify because behaviour depends on the machine it ran on.
- OpenSCAP and SCAP profiles: rigorous and standards-backed, but heavy, XML-centric, awkward to extend, and the tooling assumes an enterprise context.
- Ad-hoc scripts: common, and generally untested, undocumented and unowned.

None of them answers these two questions:

> *"What changed on this host between March and today?"*
> *"Was this host actually configured that way at the time of the incident, or are we reconstructing?"*

Answering those requires the state to be captured, not just judged. That is what Plumbline does differently.

---

## 3. Users

Cut from the original six personas to three, to keep the v1 scope achievable.

| Persona | What they need | What they get |
|---|---|---|
| Sysadmin / homelab operator (primary) | "Is this box sane? What should I fix first?" | One binary, one command, a ranked list with copy-pasteable fixes |
| DevSecOps engineer | Machine-readable posture in CI, no false-positive noise | Stable JSON schema, SARIF, deterministic exit codes, suppression files |
| Incident responder / auditor | Defensible evidence of configuration at a point in time | Signed fact bundles, re-evaluable offline, diffable across time |

Deferred to v3 or never: penetration testers (v2, via the PRIVESC module), compliance officers (v2, evidence packs rather than scores), plugin authors (v3).

---

## 4. Differentiation

The table compares against the incumbent and describes v1 as scoped, not as intended:

| Dimension | Lynis | Plumbline v1 |
|---|---|---|
| Implementation | POSIX shell | Single static Go binary, no interpreter, no CGO |
| Evaluation model | Judged live, on the host | Facts captured, findings derived from the bundle |
| Re-audit past state | Not possible | `plumbline eval bundle.tar.zst`, offline, at any time |
| Determinism | Depends on host and environment | Same bundle + catalog = identical output |
| Scan a mounted image / container filesystem | No | `--root /mnt/host` |
| Machine-readable output | Limited | Versioned JSON Schema + SARIF, both stable APIs |
| Diff across time | No | `plumbline diff a.bundle b.bundle` |
| Check test coverage | Hard to assess | Every check has fixture-based tests; coverage published |
| Breadth of checks | ~300, mature, many platforms | ~110 at v1.0.0, Linux only |
| Platform coverage | Linux, macOS, BSD, Solaris, AIX | Linux only until v3 |
| Ecosystem maturity | 15+ years | New |

The last three rows record dimensions where Lynis is ahead, and are included for that reason.

---

## 5. Design principles

1. Facts before findings. If it is not in the bundle, no check may assert it.
2. A check is a pure function. Facts in, findings out. No IO, no clock, no randomness, no network.
3. `UNKNOWN` is a valid answer. A check that cannot determine the answer says so. It never guesses PASS.
4. Every finding carries its evidence: the exact bytes the verdict was derived from, with the source path and how it was read. A finding without evidence cannot be checked by anyone else.
5. Every finding carries a fix. Steps a human can follow, and where safe, a command. Both, not either.
6. Nothing runs on the target that does not need to. No daemon, no installed agent, no persistent state on the host unless asked.
7. The scan path never touches the network. Not for CVE lookups, not for telemetry, not for version checks. Network use is confined to explicit, separate subcommands (`plumbline db fetch`).
8. Check IDs are permanent, schema changes are versioned, and exit codes are a contract.
9. Say what is not known. Coverage is reported alongside every score.

---

## 6. Scope summary

Full detail in `ROADMAP.md`. In one line each:

- v1.0.0, trustworthy core. Linux, ~110 checks in 10 modules, fact bundles, terminal + JSON + SARIF, diff, deterministic exit codes, no network, no plugins, no compliance scoring.
- v2.0.0, intelligence. Vulnerability correlation via vendor security feeds, containers module, privesc module, HTML reports, remediation generation, user-supplied compliance mapping packs, evidence packs.
- v3.0.0, reach. Declarative check packs and a subprocess extension protocol, macOS, fleet aggregation, policy-as-code baselines, stable public library API.

---

## 7. Success criteria

Deliberately modest and measurable; this is a portfolio and learning project first.

**v1.0.0 is successful if:**
- It runs clean on Ubuntu 22.04/24.04, Debian 12/13, Fedora, and Alpine with zero crashes and zero unhandled panics across the fixture corpus.
- Check catalog test coverage ≥ 95% of checks having at least one PASS and one FAIL fixture.
- A full scan of a normal server completes in under 90 seconds (measured, then published as the budget in `PERFORMANCE.md`).
- The false-positive rate on a freshly installed, unhardened distro is documented per check. It will not be zero.
- Someone other than the author successfully runs it and files an issue.

**v2.0.0 is successful if:** the vulnerability correlation produces fewer false positives on a stock Ubuntu LTS host than a naive NVD matcher, demonstrated with a published comparison. That comparison is the argument for the feature.

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
