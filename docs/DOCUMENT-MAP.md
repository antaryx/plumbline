# DOCUMENT MAP — Plumbline

Every document the project needs, what goes in it, and which release it gates.

**Gate column:** `v1` = must exist and be accurate before v1.0.0 ships. `v2`/`v3` = created when that release's features arrive. `ongoing` = living document, never "finished".

**Rule:** a document that is not gating any release and has no owner does not get written. Documentation debt is real debt, but so is documentation nobody reads. The list below is 34 documents, which sounds like a lot until you notice that 12 of them are under a page and 6 are generated.

---

## Tier 0 — Repository surface

The files a visitor and a contributor hit first. All are v1-gating and most are short.

| Doc | Gate | Contents |
|---|---|---|
| `README.md` | v1 | What it is in two sentences, one honest screenshot, install (verified), 60-second quickstart, what it does *not* do, link to docs. No feature-table cosplay. |
| `LICENSE` | v1 | Apache-2.0. |
| `NOTICE` | v1 | Attribution for vendored data and dependencies requiring it. |
| `CHANGELOG.md` | ongoing | Keep-a-Changelog. Mandatory `### Check corrections` section whenever a verdict changed (`VERSIONING.md` §2.4). |
| `CONTRIBUTING.md` | v1 | Dev setup, branch and commit conventions, the fixture requirement (no check merged without PASS+FAIL fixtures), review expectations, DCO/CLA stance. |
| `CODE_OF_CONDUCT.md` | v1 | Contributor Covenant. |
| `SECURITY.md` | v1 | How to report a vulnerability **in Plumbline**, response SLA you can actually meet, supported versions, disclosure policy, PGP/contact. Distinct from `THREAT-MODEL.md`. |
| `SUPPORT.md` | v1 | Where to ask questions, what is and is not supported, expected response times for a solo maintainer. |
| `MAINTAINERS.md` | v1 | Who decides. One name is a fine answer; ambiguity is not. |
| `.github/` templates | v1 | Bug report template that asks for `plumbline version --json` and a redacted bundle; false-positive template; feature request; PR checklist. |

---

## Tier 1 — Product definition

| Doc | Gate | Contents |
|---|---|---|
| `PROJECT-BRIEF.md` | v1 | ✅ **written** — identity, naming rationale, problem, users, differentiation, principles, non-negotiables. |
| `ROADMAP.md` | ongoing | ✅ **written** — three majors, exit criteria, the graveyard of rejected ideas. |
| `REQUIREMENTS.md` | v1 | Functional and non-functional requirements with IDs (`FR-012`, `NFR-004`), each traceable to a test. This is the missing link between the roadmap and the test suite, and it is what "acceptance criteria" actually means in practice. |
| `GLOSSARY.md` | v1 | Fact, bundle, check, finding, evidence, catalog, posture, coverage, profile, suppression. Small doc, disproportionate value — these words get used inconsistently within a week otherwise. |
| `adr/` | ongoing | Architecture Decision Records. ADR-0001 *Collect/evaluate split*; -0002 *Go plugin rejected*; -0003 *No compliance scoring*; -0004 *Vendor feeds over NVD*; -0005 *Five result states*; -0006 *No auto-remediation*; -0007 *JSON schema is the public API*. Each: context, decision, consequences, status. Fifteen minutes each and they end every re-litigation six months later. |

---

## Tier 2 — Technical design

| Doc | Gate | Contents |
|---|---|---|
| `ARCHITECTURE.md` | v1 | ✅ **written** — layers, System seam, collection, bundle, evaluation, scoring, safety rules, layout, error model, test strategy. |
| `DESIGN.md` | v1 | Component-level detail below the architecture: package responsibilities, sequence diagrams for `scan`/`collect`/`eval`/`diff`, concurrency model, cancellation propagation, memory budgets, key internal interfaces. This is what the architecture doc deliberately does not descend into. |
| `DATA-MODEL.md` | v1 | Fact, FactSet, FactError, Bundle, Finding, Evidence, Remediation, Result, Severity. Per-fact versioning rules. Fingerprint derivation. Authoritative alongside `schema/*.json`. |
| `schema/findings-v1.schema.json` | v1 | The public API. Machine-readable, CI-validated. |
| `schema/bundle-v1.schema.json` | v1 | Bundle format. Read-compatibility is forever. |
| `CHECK-AUTHORING.md` | v1 | How to add a check end to end: pick an ID, declare fact dependencies, write `Applies`/`Eval`, write PASS and FAIL fixtures, write the remediation, map to a public-domain control, review checklist. The single highest-leverage contributor document. |
| `COLLECTORS.md` | v1 | Every collector: facts produced, dependencies, privilege required, cost class, timeout, failure modes, distro variations handled. |
| `CLI-SPEC.md` | v1 | Every command and flag, defaults, mutual exclusions, precedence rules, exit codes with the precedence ladder, environment variables, stdout/stderr discipline. |
| `CONFIG-REFERENCE.md` | v1 | Every key, type, default, precedence chain, deprecations, worked examples. |
| `OUTPUT-FORMATS.md` | v1 | Per format: intended consumer, guarantees, stability level, examples. SARIF rule-ID and fingerprint mapping in detail. |
| `PLATFORM-SUPPORT.md` | v1 | Support tiers with honest definitions: *Tier 1 = in CI with golden bundles; Tier 2 = builds, spot-checked; Tier 3 = compiles, untested*. Per-distro notes. Replaces the source design's decorative ✅/🔶/🔲 table. |
| `PERFORMANCE.md` | v1 | Budgets per phase (walk, collect, evaluate, render), the reference host definition, measured baselines, how the CI assertion works. Numbers appear here only after being measured. |
| `MODULE-CATALOG.md` | v1 | *Generated* from the catalog. Modules, checks, severities, mappings. Never hand-maintained. |
| `CHECK-REFERENCE.md` | v1 | *Generated*. One page per check: rationale, what it reads, PASS/FAIL conditions, false-positive notes, remediation, references. This is the documentation users actually read. |

---

## Tier 3 — Security, legal, privacy

The tier the source document omitted entirely, and the one that carries the actual project-ending risks.

| Doc | Gate | Contents |
|---|---|---|
| `THREAT-MODEL.md` | v1 | Threats *to Plumbline*: hostile filesystem contents, TOCTOU/symlink attacks against a root reader, FIFO and device-node hangs, ANSI injection into operator terminals, resource exhaustion, malicious bundles fed to `eval`, config from an attacker-controlled CWD, sensitive report contents. Assets, trust boundaries, mitigations, accepted risks. **Gates running as root at all.** |
| `SUPPLY-CHAIN.md` | v1 | Reproducible build procedure, signing identities, SBOM generation, provenance, dependency policy (adding a dependency to a root-privileged tool needs justification), how a third party independently verifies a release. |
| `PRIVACY.md` | v1 | Exactly what a bundle and a report contain, the no-telemetry commitment stated unambiguously, redaction options, guidance on sharing bundles for bug reports, retention advice. |
| `COMPLIANCE-DATA-POLICY.md` | v1 | Which frameworks may be shipped (NIST 800-53, DISA STIG — US Government works) and which may not (CIS, PCI-DSS, ISO 27001, SOC 2 — copyrighted, redistribution restricted). The user-supplied mapping-pack model. How contributors must handle control text. **Prevents the takedown scenario in audit finding A-02.** |
| `LEGAL-DISCLAIMER.md` | v1 | Plumbline produces evidence, not compliance conclusions; no warranty; the PRIVESC module is for systems you are authorised to assess; no endorsement by any standards body. Shipped with the tool, not buried in a website footer. |

---

## Tier 4 — Delivery and operations

| Doc | Gate | Contents |
|---|---|---|
| `VERSIONING.md` | v1 | ✅ **written** — four version numbers, SemVer rules, check ID lifecycle, schema policy, score stability, exit-code contract, support windows. |
| `DEPLOYMENT.md` | v1 | ✅ **written** — build, sign, publish, distribute, install, container, air-gap, upgrade, rollback, bad-release incident response. |
| `RELEASE-PROCESS.md` | v1 | The human runbook: cut a release branch, RC soak periods, who reviews the golden-bundle diff, the release checklist, what to do when a step fails mid-release. |
| `TESTING.md` | v1 | Test taxonomy, the fixture corpus and how to record a new one, golden bundles and their review process, determinism/offline/hostile suites, distro matrix, coverage targets, what CI blocks on. |
| `CI-CD.md` | v1 | Workflow inventory, required checks, branch protection, secrets and OIDC setup, runner requirements, nightly jobs. |
| `PACKAGING.md` | v2 | Homebrew tap, container variants, community packaging contacts, what the project will and will not maintain. |
| `SUPPORT-POLICY.md` | v1 | Supported versions, security-fix windows, the compatibility matrix (tool × schema × bundle), EOL announcements. |
| `runbooks/` | v1 | `RUNBOOK-bad-release.md` (v1), `RUNBOOK-security-report.md` (v1), `RUNBOOK-vulndb-outage.md` (v2). |
| `postmortems/` | ongoing | One per incident. Each must end with a new test. |

---

## Tier 5 — User documentation

| Doc | Gate | Contents |
|---|---|---|
| `INSTALLATION.md` | v1 | Verified install first, convenience script second, `go install`, container, air-gap, upgrade, **uninstall**. Signature verification commands inline and copy-pasteable. |
| `QUICKSTART.md` | v1 | Zero to a first useful scan in under five minutes. One page. |
| `USAGE.md` | v1 | Every command with realistic examples: scanning, splitting collect/eval, diffing over time, filtering, suppressions, profiles, output formats. |
| `CI-INTEGRATION.md` | v1 | GitHub Actions, GitLab CI, Jenkins. Pinned and verified downloads, gating strategy, SARIF upload, why `--min-coverage` matters. |
| `FALSE-POSITIVES.md` | v1 | Why they happen, known ones per check, how to write a suppression with a justification and an expiry, how to report one well. **Shipping this admits imperfection up front, which is the fastest way to be trusted.** |
| `TROUBLESHOOTING.md` | v1 | Permission errors, slow scans, container gotchas, distro quirks, how to read `plumbline doctor`. |
| `FAQ.md` | v1 | "How is this different from Lynis?", "Why no compliance score?", "Why does it not fix things?", "Can I run it unprivileged?", "Why is coverage only 60%?" |
| `REMEDIATION-GUIDE.md` | v2 | Applying generated fixes safely, staging, what can lock you out, rollback. |
| `PACK-AUTHORING.md` | v3 | Writing declarative check packs and subprocess extensions; the trust model, stated bluntly. |

---

## Build order

Writing all of this before coding is procrastination with good posture. Writing none of it is the source document's failure mode. The sequence:

**Before the first commit** *(~2 days)*
`PROJECT-BRIEF` → `ARCHITECTURE` → `DATA-MODEL` + `schema/*.json` → ADR-0001 → `README` (a stub) → `LICENSE` → `CONTRIBUTING`

The schema comes before any code because it is the public API, and retrofitting a contract onto an implementation always loses.

**Before the first check** *(~1 day)*
`CHECK-AUTHORING` → `GLOSSARY` → `TESTING` → `COMPLIANCE-DATA-POLICY`

The last one before check #1 because the first check that maps to a framework is where the licensing decision gets made by accident if it has not been made on purpose.

**Before running as root on a machine you care about**
`THREAT-MODEL`

**During v0.2–v0.3, incrementally**
`CLI-SPEC` · `CONFIG-REFERENCE` · `OUTPUT-FORMATS` · `COLLECTORS` · `DESIGN` · `REQUIREMENTS`

**Release-hardening, before v1.0.0**
`VERSIONING` (done) · `DEPLOYMENT` (done) · `RELEASE-PROCESS` · `SUPPLY-CHAIN` · `SECURITY` · `PRIVACY` · `SUPPORT-POLICY` · `PLATFORM-SUPPORT` · `PERFORMANCE` · all Tier 5 · generated references · `CI-CD` · runbooks

**Deferred by design**
`PACKAGING` (v2) · `REMEDIATION-GUIDE` (v2) · `PACK-AUTHORING` (v3)

---

## Documentation rules

1. **Generated docs are generated.** `MODULE-CATALOG.md` and `CHECK-REFERENCE.md` are produced by `make docs` from the catalog. CI fails if they are stale. Hand-maintained check lists are wrong within a month — the source document's "300+ checks" claim against 253 enumerated is exactly this failure.
2. **Every number is measured or marked.** No invented durations, no invented coverage percentages.
3. **Docs ship in the repository**, versioned with the code. A website, if one ever exists, renders the repository.
4. **A feature is not done until its doc is.** Enforced by the PR checklist, not by good intentions.
5. **Say what is not supported**, in the same document and the same font size as what is.

---

## Status — audited 2026-08-21 (WP-38)

Counted mechanically against this map, not asserted.

| Tier | Present | Required | Missing |
|---|---|---|---|
| Tier 0 | 9 | 9 | — |
| Tier 1 | 5 | 6 | `REQUIREMENTS.md` |
| Tier 2 | 8 | 13 | `DESIGN.md`, `COLLECTORS.md`, `CONFIG-REFERENCE.md`, `OUTPUT-FORMATS.md`, `PLATFORM-SUPPORT.md` |
| Tier 3 | 5 | 5 | — |
| Tier 4 | 2 | 7 | `RELEASE-PROCESS.md`, `TESTING.md`, `CI-CD.md`, `SUPPORT-POLICY.md`, `runbooks/` |
| Tier 5 | 7 | 7 | — |

**Tier 5 is complete**, and so are Tiers 0 and 3. WP-38 added all seven
user-facing documents, plus `SUPPORT.md`, `PRIVACY.md` and `SUPPLY-CHAIN.md` —
ten in total. `README.md` no longer carries a load it was never shaped for.

**Eleven gating documents remain, so the v1.0.0 criterion "all v1-gating
documents complete (Tier 0–4)" is still NOT met.** It was 14 before WP-38.
Recording that plainly is the point of this table: a project whose entire
argument is that an unverified thing must not be reported as verified does not
get an exception for its own checklist.

What is left divides into two kinds, and neither is a writing job that can be
done from the source alone:

- **Reference documents that should be generated, not written** —
  `COLLECTORS.md` and `CONFIG-REFERENCE.md` enumerate things the code already
  knows (`collect.Default()`, the flag set). `tools/gendocs` is the precedent:
  generate them and gate freshness in `make invariants`, rather than writing
  prose that drifts within a month.
- **Process documents that describe habits not yet settled** —
  `RELEASE-PROCESS.md`, `TESTING.md`, `CI-CD.md`, `SUPPORT-POLICY.md` and the
  runbooks. Writing these before the practice exists produces a document
  describing a process nobody follows, which is worse than an absent one.
  `RELEASE-PROCESS.md` is the most valuable of them and now has real material:
  three tag mints, one of them a re-cut after a shipped defect, and a flaky
  module-proxy failure that starved the jobs carrying the evidence.

`DESIGN.md`, `PLATFORM-SUPPORT.md` and `REQUIREMENTS.md` are genuine writing
tasks and are the honest v1.1 backlog.
