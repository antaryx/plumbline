# Plumbline project brief

**Status:** current at `v2.0.0`, 2026-09-02.
**Owner:** Antaryx
**Supersedes:** `argus-project-design.md` v0.1

---

## 1. Identity

| Field | Value |
|---|---|
| Name | Plumbline |
| Binary | `plumbline` |
| Module path | `github.com/antaryx/plumbline` |
| Origin | A plumb line is a weighted cord that reveals true vertical. It does not defend the wall or build it. It measures how far off true the wall already is. Deviation is measured against a known reference, the measurement repeats, and the instrument is simple enough to audit. |
| Language | Go. `go.mod` floor is 1.24, releases build with 1.25 |
| Licence | Apache-2.0 for the code. See `COMPLIANCE-DATA-POLICY.md` for data |
| Versioning | SemVer for the binary, independent versions for catalog, schema and vulnerability data (see `VERSIONING.md`) |
| Stable releases planned | v1.0.0 and v2.0.0 shipped; v3.0.0 and v4.0.0 in `ROADMAP.md` |

### 1.1 Why this name

The name had to pass three tests: not already used in security tooling, maps to
what the tool does, easy to type.

Plumbline passes. A search of security tooling and GitHub found no host-auditing
project using it, the metaphor matches the behaviour, and it is one word.

It is also not a Greek-mythology name. Argus, Aegis, Cerberus, Talos, Sentinel
and Hydra are heavily used in this space, so a collision is likely. A metrology
metaphor avoids that.

The formal diligence below was drafted before the first commit and was never
recorded as completed. The project has shipped two majors under the name, so the
practical risk has been taken. Recording that plainly beats a checklist of
unticked boxes pretending to be a plan:

- `github.com/antaryx/plumbline` is in use and the name is unclaimed on
  `pkg.go.dev`
- No live-mark search has been run in any jurisdiction, in classes 9 or 42
- No check has been made for a Homebrew formula, a Debian source package, or a
  crates.io, PyPI or npm package squatting the term

Backups if any of that turns up a problem: Bartizan, an overhanging turret built
into a wall as a lookout post, obscure and unused and it works as a logo.
Revetment, the stone facing that protects an embankment. Assay, the
determination of what something is made of, though it collides with biotech
tooling.

### 1.2 What Plumbline is

> A deterministic, offline, evidence-first host posture auditor for Linux.

Three properties define it, and every design decision defers to them.

1. **Collect once, evaluate many.** A scan captures a fact bundle: raw system
   state, typed and timestamped. Findings derive from the bundle and are never
   read live from the machine. A six-month-old bundle re-evaluates against
   today's catalog without touching the host.
2. **Deterministic.** The same bundle plus the same catalog version yields
   byte-identical findings on any machine.
3. **Honest.** No invented compliance percentages, and no scores that change
   meaning between releases. Where the tool cannot determine an answer it
   reports `UNKNOWN`, which is a first-class result state.

### 1.3 What Plumbline is not

- Not a network scanner. It audits the host it is pointed at and does not
  port-scan other hosts.
- Not a SIEM or an agent. Point-in-time bundles only, no daemon, no continuous
  monitoring, in any planned version.
- Not a patch manager. It reports outdated software and installs nothing.
- Not an exploit framework. Privilege-escalation surface gets mapped and
  explained, never exercised.
- Not a compliance certification. It produces evidence. Humans and auditors
  produce conclusions.
- Not a remediation robot. `scan --fix` prints the work that would repair the
  failing checks it knows how to repair, and executes none of it. The block's
  first line says so. A tool that rewrote `/etc/ssh/sshd_config` as root from a
  heuristic, on a machine the operator cannot see, will eventually lock someone
  out of production. That is the line: generating is review, applying is the
  thing this project does not do.

An earlier revision of that last point said there would be no `--fix` flag at
all. The flag exists as of the remediation engine's first phase, in its
proposal-only form. The reasoning behind the original sentence is unchanged and
still governs what the flag may ever do. `docs/adr/0006-no-auto-remediation.md`
carries the decision and its amendment.

---

## 2. The problem

An operator who wants to know whether a Linux host is well configured has three
options, each limited.

Lynis is mature, wide and shell-based. The findings are advisory text, the
output is hard to consume programmatically, there is no way to re-audit a past
state, and correctness is hard to verify because behaviour depends on the
machine it ran on.

OpenSCAP and SCAP profiles are rigorous and standards-backed, but heavy,
XML-centric, awkward to extend, and the tooling assumes an enterprise context.

Ad-hoc scripts are common, and generally untested, undocumented and unowned.

None of them answers these two questions:

> *"What changed on this host between March and today?"*
> *"Was this host actually configured that way at the time of the incident, or
> are we reconstructing?"*

Answering those needs the state captured, not just judged. That is what
Plumbline does differently.

---

## 3. Users

Cut from the original six personas to three, to keep the scope achievable.

| Persona | What they need | What they get |
|---|---|---|
| Sysadmin or homelab operator (primary) | "Is this box sane? What should I fix first?" | One binary, one command, a ranked list, and a script they can read before running |
| DevSecOps engineer | Machine-readable posture in CI without false-positive noise | Stable JSON schema, SARIF, deterministic exit codes, suppression files |
| Incident responder or auditor | Defensible evidence of configuration at a point in time | Fact bundles, re-evaluable offline, diffable across time |

Deferred: penetration testers, via the `PRIVESC` module. Compliance officers,
via evidence packs rather than scores. Pack authors, via the extension protocol.
All three are in `ROADMAP.md` and none has started.

---

## 4. Differentiation

Against the incumbent, describing what is built rather than what is intended:

| Dimension | Lynis | Plumbline v2.0.0 |
|---|---|---|
| Implementation | POSIX shell | Single static Go binary, no interpreter, no CGO |
| Evaluation model | Judged live, on the host | Facts captured, findings derived from the bundle |
| Re-audit past state | Not possible | `plumbline eval host.plb`, offline, at any time |
| Determinism | Depends on host and environment | Same bundle plus same catalog gives identical output |
| Scan a mounted image or container filesystem | No | `--root /mnt/host` |
| Machine-readable output | Limited | Versioned JSON Schema and SARIF, both stable APIs |
| Diff across time | No | `plumbline diff a.plb b.plb` |
| Remediation | Advisory text | Generated idempotent script, never executed |
| Check test coverage | Hard to assess | Every check has fixture-based tests, coverage published |
| Breadth of checks | ~300, mature, many platforms | 112, Linux only |
| Platform coverage | Linux, macOS, BSD, Solaris, AIX | Linux only |
| Ecosystem maturity | 15+ years | New |

The last three rows record where Lynis is ahead, and are here for that reason.

---

## 5. Design principles

1. Facts before findings. If it is not in the bundle, no check may assert it.
2. A check is a pure function. Facts in, findings out. No IO, no clock, no
   randomness, no network.
3. `UNKNOWN` is a valid answer. A check that cannot determine the answer says
   so. It never guesses PASS.
4. Every finding carries its evidence: the exact bytes the verdict came from,
   with the source path and how it was read. A finding without evidence cannot
   be checked by anyone else.
5. Every finding carries a fix. Steps a human can follow, and where safe, a
   command. Both, not either.
6. Nothing runs on the target that does not need to. No daemon, no installed
   agent, no persistent state on the host unless asked.
7. The scan path never touches the network. Not for CVE lookups, not for
   telemetry, not for version checks.
8. Check IDs are permanent, schema changes are versioned, and exit codes are a
   contract.
9. Say what is not known. Coverage is reported alongside every score.
10. Generate, do not apply. The tool writes remediation for a human to read and
    run. It never runs it.

---

## 6. Scope summary

Full detail in `ROADMAP.md`. In one line each:

- **v1.0.0, trustworthy core. Shipped.** Linux, fact bundles, terminal and JSON
  and SARIF output, diff, deterministic exit codes, no network, no plugins, no
  compliance scoring.
- **v2.0.0, remediation and pipelines. Shipped.** A state-aware idempotent
  remediation generator behind `scan --fix`, pipeline gates, SARIF export, the
  `CONTAINERS` and `MEMORY` modules.
- **v3.0.0, intelligence.** Vulnerability correlation from vendor security
  feeds, the `CLOUD` and `PRIVESC` modules, compliance evidence packs, HTML
  reports.
- **v4.0.0, reach.** Declarative check packs, a subprocess extension protocol,
  macOS, fleet aggregation, a stable public Go API.

---

## 7. Success criteria

Deliberately modest and measurable. This is a portfolio and learning project
first.

**v1.0.0 was successful if:**

- It runs clean on Ubuntu 22.04 and 24.04, Debian 12 and 13, Fedora, and Alpine
  with zero crashes and zero unhandled panics across the fixture corpus. Met.
- Check catalog coverage reaches 95% of checks having at least one PASS and one
  FAIL fixture. Met at 100%, enforced by CI.
- A full scan of a normal server completes in under 90 seconds, measured and
  published in `PERFORMANCE.md`. Met.
- The false-positive rate on a freshly installed unhardened distro is documented
  per check. Partly met, in `FALSE-POSITIVES.md`. It is not zero.
- Someone other than the author runs it and files an issue. Not yet met.

**v2.0.0 is successful if:** an operator can read a generated script, understand
every command in it from the comments, run it twice without corrupting anything,
and end up with a host that passes the checks it was generated from. The
`SERVICES-0011` incident is the counter-example that shaped the rule, and it is
recorded in `ROADMAP.md`.

**v3.0.0 is successful if:** vulnerability correlation produces fewer false
positives on a stock Ubuntu LTS host than a naive NVD matcher, demonstrated with
a published comparison. That comparison is the argument for the feature.

**v4.0.0 is successful if:** a third party writes and ships a check pack without
modifying the core.

---

## 8. Non-negotiables

Things that do not get traded away under schedule pressure.

- No telemetry, no phone-home, no analytics, in any version, ever.
- **No auto-apply.** `scan --fix` writes a script and never runs one. No flag
  will be added that changes this, and `internal/remediate` holds no `System`
  so the boundary is structural rather than a promise.
- No compliance percentage figures.
- No redistribution of licensed standards text.
- No check merged without fixture tests.
- No release without a signed, verifiable artifact and an SBOM.
- No claiming support for a platform that is not in CI.
