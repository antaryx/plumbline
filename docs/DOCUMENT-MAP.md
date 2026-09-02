# Document map

Every document the project needs, what goes in it, and which release it gates.

**Gate column:** `v1` means it had to exist and be accurate before v1.0.0
shipped. `v3` and `v4` mean it gets created when that release's features arrive.
`ongoing` means a living document that is never finished.

**Rule:** a document that gates no release and has no owner does not get
written. Documentation debt is real debt, and so is documentation nobody reads.
The list below is 34 documents, which sounds like a lot until you notice that 12
are under a page and 2 are generated.

---

## Tier 0: repository surface

The files a visitor and a contributor hit first. All v1-gating, most short.

| Doc | Gate | Contents |
|---|---|---|
| `README.md` | v1 | What it is in two sentences, one honest screenshot, verified install, a 60-second quickstart, what it does not do, a link to the docs. The liability warning sits above the table of contents. No feature-table cosplay. |
| `LICENSE` | v1 | Apache-2.0. |
| `NOTICE` | v1 | Third-party attribution, required by Apache-2.0 section 4(d). Also carries the Contributor Covenant's CC BY 4.0 attribution. |
| `CHANGELOG.md` | ongoing | Keep-a-Changelog. A `### Check corrections` section is mandatory whenever a verdict changed (`VERSIONING.md` §2.4). |
| `CONTRIBUTING.md` | v1 | Dev setup, branch and commit conventions, the fixture requirement, review expectations, DCO and CLA stance. No check merges without PASS and FAIL fixtures. |
| `CODE_OF_CONDUCT.md` | v1 | Contributor Covenant 2.1, verbatim under CC BY 4.0. Do not rewrite it. |
| `SECURITY.md` | v1 | How to report a vulnerability in Plumbline, a response SLA that can actually be met, supported versions, disclosure policy, contact. Distinct from `THREAT-MODEL.md`. |
| `SUPPORT.md` | v1 | Where to ask questions, what is and is not supported, response times for a solo maintainer. |
| `MAINTAINERS.md` | v1 | Who decides. One name is a fine answer. Ambiguity is not. |
| `.github/` templates | v1 | Bug report asking for `plumbline version --json` and a redacted bundle. False-positive template. Feature request. PR checklist. |

---

## Tier 1: product definition

| Doc | Gate | Contents |
|---|---|---|
| `PROJECT-BRIEF.md` | v1 | **Written.** Identity, naming rationale, problem, users, differentiation, principles, non-negotiables. |
| `ROADMAP.md` | ongoing | **Written.** Four majors, exit criteria, the graveyard of rejected ideas, and the work log of how each shipped. |
| `REQUIREMENTS.md` | v1 | Functional and non-functional requirements with IDs like `FR-012` and `NFR-004`, each traceable to a test. This is the missing link between the roadmap and the test suite, and it is what "acceptance criteria" means in practice. |
| `GLOSSARY.md` | v1 | **Written.** Fact, bundle, check, finding, evidence, catalog, posture, coverage, profile, suppression. Small doc, disproportionate value. These words drift within a week otherwise. |
| `adr/` | ongoing | **Written**, 18 records. Architecture decision records: context, decision, consequences, status. Fifteen minutes each, and they end every re-litigation six months later. ADR-0006 carries an amendment rather than a rewrite, which is the pattern to copy. |

---

## Tier 2: technical design

| Doc | Gate | Contents |
|---|---|---|
| `ARCHITECTURE.md` | v1 | **Written.** Layers, the System seam, collection, bundle, evaluation, scoring, safety rules, layout, error model, test strategy, and the three decisions that shape the tool. |
| `DESIGN.md` | v1 | Component detail below the architecture: package responsibilities, sequence diagrams for `scan`, `collect`, `eval` and `diff`, concurrency model, cancellation propagation, memory budgets, key internal interfaces. What the architecture doc deliberately does not descend into. |
| `DATA-MODEL.md` | v1 | **Written.** Fact, FactSet, FactError, Bundle, Finding, Evidence, Remediation, Result, Severity. Per-fact versioning. Fingerprint derivation. Authoritative alongside `schema/*.json`. |
| `schema/findings-v1.schema.json` | v1 | **Written.** The public API. Machine-readable, CI-validated. |
| `schema/bundle-v1.schema.json` | v1 | **Written.** Bundle format. Read-compatibility is forever. |
| `CHECK-AUTHORING.md` | v1 | **Written.** How to add a check end to end: pick an ID, declare fact dependencies, write `Applies` and `Eval`, write PASS and FAIL fixtures, write the remediation, map to a public-domain control, review checklist. The highest-leverage contributor document. |
| `FIXTURES.md` | v1 | **Written.** The fixture corpus, the manifest format, how to record a new one. Covers much of what `TESTING.md` was scoped for. |
| `COLLECTORS.md` | v1 | Every collector: facts produced, dependencies, privilege required, cost class, timeout, failure modes, distro variations handled. |
| `CLI-SPEC.md` | v1 | **Written.** Every command and flag, defaults, mutual exclusions, precedence, exit codes with the precedence ladder, environment variables, stdout and stderr discipline. |
| `CONFIG-REFERENCE.md` | v1 | Every key, type, default, precedence chain, deprecations, worked examples. |
| `OUTPUT-FORMATS.md` | v1 | Per format: intended consumer, guarantees, stability level, examples. SARIF rule-ID and fingerprint mapping in detail. |
| `PLATFORM-SUPPORT.md` | v1 | Support tiers with honest definitions. Tier 1 is in CI with golden bundles, Tier 2 builds and is spot-checked, Tier 3 compiles and is untested. Per-distro notes. Replaces the source design's decorative tick-and-circle table. |
| `PERFORMANCE.md` | v1 | **Written.** Budgets per phase, the reference host, measured baselines, and which figures are stale. Numbers appear here only after being measured. |
| `MODULE-CATALOG.md` | v1 | **Generated** from the catalog. Modules, checks, severities, mappings. Never hand-maintained. |
| `CHECK-REFERENCE.md` | v1 | **Generated.** One entry per check: rationale, what it reads, PASS and FAIL conditions, false-positive notes, remediation, references. The documentation users actually read. |

---

## Tier 3: security, legal, privacy

The tier the source document omitted entirely, and the one carrying the actual
project-ending risks.

| Doc | Gate | Contents |
|---|---|---|
| `THREAT-MODEL.md` | v1 | **Written.** Threats to Plumbline: hostile filesystem contents, TOCTOU and symlink attacks against a root reader, FIFO and device-node hangs, ANSI injection into operator terminals, resource exhaustion, malicious bundles fed to `eval`, config from an attacker-controlled CWD, sensitive report contents, and a generated script that damages the host. Assets, trust boundaries, mitigations, accepted risks. **Gates running as root at all.** |
| `SUPPLY-CHAIN.md` | v1 | **Written.** Build procedure, signing identities, SBOM generation, dependency policy, how a third party independently verifies a release, and what is not yet in place. |
| `PRIVACY.md` | v1 | **Written.** Exactly what a bundle and a report contain, the no-telemetry commitment stated unambiguously, redaction, guidance on sharing bundles, retention advice. |
| `COMPLIANCE-DATA-POLICY.md` | v1 | **Written.** Which frameworks may be shipped and which may not, the user-supplied mapping-pack model, how contributors must handle control text. **Prevents the takedown scenario in audit finding A-02.** |
| `LEGAL-DISCLAIMER.md` | v1 | **Written.** Plumbline produces evidence, not compliance conclusions. No warranty. The operator owns what a generated script does. Ships with the tool, not buried in a website footer. |

---

## Tier 4: delivery and operations

| Doc | Gate | Contents |
|---|---|---|
| `VERSIONING.md` | v1 | **Written.** Four version numbers, SemVer rules, check ID lifecycle, schema policy, score stability, exit-code contract, support windows. |
| `DEPLOYMENT.md` | v1 | **Written.** Build, sign, publish, distribute, install, container, air-gap, upgrade, rollback, bad-release incident response, and a closing section listing what the pipeline does not actually do. |
| `RELEASE-PROCESS.md` | v1 | The human runbook: cut a release branch, RC soak periods, who reviews the golden-bundle diff, the release checklist, what to do when a step fails mid-release. |
| `TESTING.md` | v1 | Test taxonomy, golden bundles and their review process, determinism and offline and hostile suites, distro matrix, coverage targets, what CI blocks on. `FIXTURES.md` already covers the corpus half. |
| `CI-CD.md` | v1 | Workflow inventory, required checks, branch protection, secrets and OIDC setup, runner requirements, nightly jobs. |
| `PACKAGING.md` | later | Homebrew tap, container variants, community packaging contacts, what the project will and will not maintain. |
| `SUPPORT-POLICY.md` | v1 | Supported versions, security-fix windows, the compatibility matrix across tool, schema and bundle, EOL announcements. |
| `runbooks/` | v1 | `RUNBOOK-bad-release.md` and `RUNBOOK-security-report.md`. |
| `postmortems/` | ongoing | One per incident. Each must end with a new test. |

---

## Tier 5: user documentation

| Doc | Gate | Contents |
|---|---|---|
| `INSTALLATION.md` | v1 | **Written.** Verified install first, `go install`, air-gap, upgrade, uninstall. Signature verification commands inline and copy-pasteable. |
| `QUICKSTART.md` | v1 | **Written.** Zero to a first useful scan in under five minutes. One page. |
| `USAGE.md` | v1 | **Written.** Every command with realistic examples: scanning, splitting collect and eval, diffing over time, filtering, suppressions, profiles, output formats, generated remediation. |
| `CI-INTEGRATION.md` | v1 | **Written.** GitHub Actions, GitLab CI, Jenkins. Pinned and verified downloads, gating strategy, SARIF upload, why `--min-coverage` matters. |
| `FALSE-POSITIVES.md` | v1 | **Written.** Why they happen, known ones per check, how to write a suppression with a justification and an expiry, how to report one well. **Shipping this admits imperfection up front, which is the fastest way to be trusted.** |
| `TROUBLESHOOTING.md` | v1 | **Written.** Permission errors, slow scans, container gotchas, distro quirks. |
| `FAQ.md` | v1 | **Written.** How it differs from Lynis, why no compliance score, why it does not fix things, whether it runs unprivileged, why coverage is low. |
| `REMEDIATION-GUIDE.md` | v2 | **Written.** Applying generated fixes safely: what to read first, the three risk tiers, the five actions that can end your session, per-action rollback, and what the engine refuses to generate. |
| `PACK-AUTHORING.md` | v4 | Writing declarative check packs and the subprocess extension protocol, with the trust model stated bluntly. |

---

## Build order

Writing all of this before coding is procrastination with good posture. Writing
none of it was the source document's failure mode. The sequence that was
actually used:

**Before the first commit.** `PROJECT-BRIEF`, then `ARCHITECTURE`, then
`DATA-MODEL` with `schema/*.json`, then ADR-0001, then a `README` stub, then
`LICENSE` and `CONTRIBUTING`.

The schema comes before any code because it is the public API, and retrofitting
a contract onto an implementation always loses.

**Before the first check.** `CHECK-AUTHORING`, `GLOSSARY`, `TESTING`,
`COMPLIANCE-DATA-POLICY`. The last one before check number one, because the
first check that maps to a framework is where the licensing decision gets made
by accident if it has not been made on purpose.

**Before running as root on a machine you care about.** `THREAT-MODEL`.

**Release hardening.** `VERSIONING`, `DEPLOYMENT`, `SUPPLY-CHAIN`, `SECURITY`,
`PRIVACY`, all of Tier 5, the generated references.

**Still deferred.** `PACKAGING` and `PACK-AUTHORING`.

---

## Documentation rules

1. **Generated docs are generated.** `MODULE-CATALOG.md` and
   `CHECK-REFERENCE.md` come from the catalog via `make docs`, and CI fails if
   they are stale. Editing them by hand is wasted work: the next build reverts
   it. Hand-maintained check lists are wrong within a month, which is what the
   source document's "300+ checks" claim against 253 enumerated actually was.
2. **Every number is measured or marked.** No invented durations, no invented
   coverage percentages. A figure taken on an older build says so.
3. **Docs ship in the repository**, versioned with the code. A website, if one
   ever exists, renders the repository.
4. **A feature is not done until its doc is.** Enforced by the PR checklist, not
   by good intentions. `REMEDIATION-GUIDE.md` trailed `scan --fix` by one
   release, which is the standing counter-example.
5. **Say what is not supported**, in the same document and the same font size as
   what is.
6. **A document that describes a control states whether the control exists.**
   `SUPPLY-CHAIN.md` and `DEPLOYMENT.md` both carry a closing section listing
   what they describe and the pipeline does not do. That pattern came out of the
   threat-model review and belongs anywhere a reader might plan around a
   claim.

---

## Status, audited 2026-09-02

Counted mechanically against this map, not asserted.

| Tier | Present | Required | Missing |
|---|---|---|---|
| Tier 0 | 10 | 10 | none |
| Tier 1 | 5 | 5 | `REQUIREMENTS.md` |
| Tier 2 | 9 | 14 | `DESIGN.md`, `COLLECTORS.md`, `CONFIG-REFERENCE.md`, `OUTPUT-FORMATS.md`, `PLATFORM-SUPPORT.md` |
| Tier 3 | 5 | 5 | none |
| Tier 4 | 2 | 8 | `RELEASE-PROCESS.md`, `TESTING.md`, `CI-CD.md`, `SUPPORT-POLICY.md`, `runbooks/` |
| Tier 5 | 8 | 8 | none |

Tiers 0, 1, 3 and 5 are complete. Eleven gating documents remain, so the
v1.0.0 criterion "all v1-gating documents complete" is still not met at v2.0.0.
It was 14 before WP-38 and 11 after. It went to 12 when v2.0.0 shipped
`scan --fix` without a guide, and back to 11 when the guide was written.

Recording that plainly is the point of this table. A project whose entire
argument is that an unverified thing must not be reported as verified does not
get an exception for its own checklist.

What is left divides into three kinds, and only one is a writing job that can be
done from the source alone.

**Reference documents that should be generated rather than written.**
`COLLECTORS.md` and `CONFIG-REFERENCE.md` enumerate things the code already
knows: `collect.Default()` and the flag set. `tools/gendocs` is the precedent.
Generate them and gate freshness in `make verify`, rather than writing prose
that drifts within a month.

**Process documents describing habits not yet settled.**
`RELEASE-PROCESS.md`, `TESTING.md`, `CI-CD.md`, `SUPPORT-POLICY.md` and the
runbooks. Writing these before the practice exists produces a document
describing a process nobody follows, which is worse than an absent one.
`RELEASE-PROCESS.md` is the most valuable of them and now has real material:
four tag mints, one a re-cut after a shipped defect, and a flaky module-proxy
failure that starved the jobs carrying the evidence.

**Genuine writing tasks.** `DESIGN.md`, `PLATFORM-SUPPORT.md` and
`REQUIREMENTS.md`. None of the three gates a shipped feature, which is why they
have survived three majors unwritten.
