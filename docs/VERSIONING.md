# VERSIONING — Plumbline

**Applies from:** v1.0.0
**Status:** binding contract once v1.0.0 ships

---

## 1. Four independent version numbers

The source design had one version number and implicitly assumed it covered everything. It does not. A security auditor has at least four separately-evolving contracts, and conflating them is how users get silently broken.

| Version | Format | Governs | Changes when |
|---|---|---|---|
| **Tool version** | SemVer `1.4.2` | The binary, CLI, config, exit codes | Every release |
| **Catalog version** | Monotonic integer `catalog/17` | The set of checks and their severities | Any check added, removed, retitled, or re-severitied |
| **Schema version** | Major integer `findings/v1` | The JSON output contract | Only on breaking output changes |
| **Vuln DB version** | Date-stamped `vulndb/2026-08-18` | Vendor security data (v2+) | Daily build |

All four are printed by `plumbline version --json`, stamped into every bundle manifest, and included in every report header. A report that does not name all four is not reproducible.

```
$ plumbline version
plumbline 1.4.2 (linux/amd64)
  catalog  17
  schema   findings/v1, bundle/v1
  vulndb   not installed
  built    2026-08-18T09:14:22Z  commit 8a3f21c  go1.23.4
```

---

## 2. Tool version — SemVer

Standard SemVer 2.0.0. What counts as breaking is the part that needs writing down.

### 2.1 MAJOR — breaking

- Removing or renaming a command, subcommand, or flag
- Changing the meaning of an existing flag
- Changing exit-code semantics (§5)
- Removing a supported output format
- Emitting a new default schema major
- Removing support for reading an older bundle format
- Removing a supported platform
- Raising the minimum kernel or distro baseline
- Changing the default posture formula (§6)

### 2.2 MINOR — additive

- New checks, new modules, new collectors
- New flags with backward-compatible defaults
- New output formats
- New optional fields in existing schema output
- New platform support
- Performance work with no behavioural change

### 2.3 PATCH — corrective

- Bug fixes, including **fixing a check that returned the wrong verdict**
- Documentation and message wording
- Dependency updates with no behavioural change

### 2.4 The awkward case: a check was wrong

A check that incorrectly reported PASS and is fixed to report FAIL changes users' scores in a patch release. This is unavoidable — the alternative is knowingly shipping a wrong security verdict — but it must never be silent.

The rule:

- Correcting a check's verdict logic is a **PATCH**, and it bumps the **catalog version**.
- It must appear in `CHANGELOG.md` under a mandatory `### Check corrections` heading, stating the check ID, the old behaviour, the new behaviour, and who is affected.
- If the correction is likely to change results on more than roughly 10% of hosts, it also carries a `plumbline scan` startup warning for one minor cycle.
- **Making a check stricter** (new conditions cause new failures) is *not* a correction — it is a new check with a new ID, or a MINOR release. Never sneak stricter checks into a patch, because someone's pipeline goes red overnight for no reason they can see.

### 2.5 Pre-1.0

Anything may break in a `0.x` release. `0.x` releases are marked pre-release on GitHub and print a banner. There are exactly three of them (`0.1`, `0.2`, `0.3`) and they are not intended for production use.

---

## 3. Catalog version

The catalog is the set of checks and their metadata. It has its own monotonically increasing integer because **scores are only comparable within one catalog version**.

### 3.1 Rules

- Any change to the catalog increments the version. Adding a check, removing one, changing a base severity, changing a weight — all of it.
- The catalog version is embedded in every findings document, every bundle, and every score.
- `plumbline diff` **refuses** to compare scores across catalog versions unless `--allow-catalog-drift` is passed, and even then annotates the output: `posture 71 → 68 (catalog 16 → 17: +4 checks, 1 severity change — not directly comparable)`.
- Findings themselves (not scores) always diff cleanly across catalog versions, keyed by check ID and fingerprint, with added/removed checks reported separately from changed results. This distinction matters: "SSHD-0009 now fails" and "SSHD-0009 did not exist before" are different facts and must never be rendered the same way.

### 3.2 Check ID lifecycle

Check IDs are **permanent identifiers**, in the same class as CVE IDs.

| Rule | Detail |
|---|---|
| Format | `MODULE-NNNN`, e.g. `SSHD-0009`. Four digits, zero-padded, allocated sequentially within a module. |
| Never reused | A retired ID is never assigned to a different check. Ever. Suppression files, SARIF baselines, and users' documentation all key on these. |
| Never renumbered | Not for tidiness, not on module reorganisation. If a check moves module, the ID stays and the module field changes. |
| Deprecation | A check is marked `Deprecated{Since: catalog/N, Reason, ReplacedBy}`. It keeps running and reporting for **two minor versions** with a deprecation notice, then stops being evaluated but remains in `plumbline check show <id>` output forever with its history. |
| Splitting | If one check becomes two, the original is deprecated and two new IDs are issued. Do not silently change what an existing ID means — that corrupts every historical bundle evaluation. |

### 3.3 Severity changes

Changing a check's base severity changes users' scores without any change to their systems. Therefore:

- Severity changes require a documented rationale in the changelog.
- They are batched into MINOR releases, never PATCH.
- Never more than one severity level of movement at a time.

---

## 4. Output schema version

**The JSON output is the public API.** Not `pkg/`, not the Go types. This is the single most important stability commitment in the project, because it is what CI pipelines, dashboards and scripts depend on.

### 4.1 Schema rules

- Published as JSON Schema at `schema/findings-v1.schema.json`, validated in CI against every rendered output.
- The version is a **major-only integer**: `findings/v1`. There is no `v1.1`.
- Within a major, **only additive changes**: new optional fields, new enum values in fields documented as open. Consumers must be told, in the schema documentation, to ignore unknown fields and tolerate unknown enum members.
- Every findings document carries `"schema": "findings/v1"` as its first key.

### 4.2 What forces a new schema major

- Removing or renaming a field
- Changing a field's type or cardinality
- Changing the meaning of an existing value
- Adding a value to an enum that consumers were told was closed (`result` is closed: PASS, FAIL, NOT_APPLICABLE, SKIPPED, UNKNOWN — a sixth state is a breaking change)

### 4.3 Schema transition policy

When `findings/v2` arrives:

1. `v2` becomes the default output.
2. `--schema v1` continues to emit the old shape for **one full major tool version** (i.e. all of v2.x), with a deprecation warning on stderr.
3. `v1` emission is removed in v3.0.0, announced in the v2.0.0 release notes and in every v2.x changelog.

The same policy governs the bundle schema, with one addition: **Plumbline reads all historical bundle schemas indefinitely.** A bundle is an archival artifact; if a three-year-old bundle cannot be evaluated by a current binary, the core promise of the product is broken. Read support is forever; write support is current-version only.

### 4.4 SARIF

SARIF output tracks the SARIF 2.1.0 specification. Rule IDs are check IDs; `partialFingerprints` uses the finding fingerprint (`ARCHITECTURE.md` §4.3). Fingerprint stability is a **schema-level guarantee**: changing how fingerprints are computed is a schema-major change, because it silently invalidates every user's suppression baseline in GitHub's security tab.

---

## 5. Exit codes are a contract

Exit codes are how CI consumes this tool, so they get the same protection as the schema.

- The meaning of an existing code never changes within a major version.
- New codes may be added in MINOR releases, but only in ranges documented as reserved for expansion (`5–9`, `12–19`, `71–79`).
- The precedence ladder (`ARCHITECTURE.md` §9) is part of the contract and is tested per branch.
- `plumbline scan --explain-exit-codes` prints the current table, machine-readably with `--json`, so a pipeline can assert against it.

---

## 6. Score stability

Posture scores are the thing users track over months and put in slide decks. They must not move for reasons users cannot see.

| Guarantee | Detail |
|---|---|
| Formula stability | The posture formula changes only in a MAJOR tool release |
| Weight stability | Severity weights change only in a MAJOR release |
| Comparability | Scores compare only within one catalog version; violations are annotated, never silently allowed |
| Coverage always attached | No renderer may display a posture score without its coverage figure |
| Provenance | Every score carries tool version, catalog version, profile, and the count of each result state |
| No compliance percentages | Ever. Coverage statements only. (See `audit/argus-design-audit.md` A-07.) |

---

## 7. Configuration compatibility

- Config files carry `version: 1` at the top level.
- Unknown keys are a **warning, not an error** — forward compatibility matters when one config is shared across a fleet running mixed versions.
- Unknown *values* for known keys are an error, because silently ignoring `fail_on: hgih` is how a pipeline stops failing without anyone noticing.
- Removing a config key requires a MAJOR release, preceded by two minors of deprecation warning.
- `plumbline config validate` and `plumbline config migrate` exist from v1.0.0.

---

## 8. Vulnerability database versioning (v2+)

| Property | Policy |
|---|---|
| Version format | `vulndb/YYYY-MM-DD` plus a content hash |
| Compatibility | Each DB declares `min_tool_version`; the binary refuses a DB it cannot parse rather than misinterpreting it |
| Staleness | A DB older than 7 days produces a warning; older than 30 days, findings are marked `stale_data` and the report says so |
| Reproducibility | Every vulnerability finding records the exact DB version it came from, so an old report can be explained later |
| Retention | The last 90 daily builds stay downloadable, so an old bundle can be re-evaluated against the DB of its time |

---

## 9. Branching, tagging, commits

Aligned with existing Antaryx practice.

- **Trunk:** `main`, always releasable, protected, linear history.
- **Work:** one branch per task, `feat/sshd-effective-config`, `fix/walker-fifo-hang`.
- **Release branches:** `release/1.x` cut at `1.0.0-rc.1`, kept alive for the support window, receiving cherry-picked patches only.
- **Commits:** Conventional Commits. `feat:` → MINOR, `fix:` → PATCH, `feat!:`/`BREAKING CHANGE:` → MAJOR. `check:` is an additional type for catalog changes, and the release tooling refuses a `check:` commit that does not touch the catalog version.
- **Tags:** `v1.4.2`, signed, annotated with the release notes.
- **Pre-releases:** `v1.0.0-rc.1`. At least two RCs before any major, each soaking for a minimum of one week.

---

## 10. Support windows

| Line | Supported until | What that means |
|---|---|---|
| Current major | Ongoing | Features, fixes, security |
| Previous major | 12 months after its successor's release | Security fixes and critical correctness fixes only |
| Older | Unsupported | Documented as such in `SUPPORT-POLICY.md` |
| Bundle read support | Indefinite | Any version reads any historical bundle |

For a solo-maintained project these must be honest. A 12-month security-fix window on one previous major is achievable; a 3-year LTS is not, and promising it is worse than not offering it.

---

## 11. Release checklist

Executed for every release; automated where possible, and the manual steps are manual on purpose.

```
[ ] CHANGELOG.md updated, including any `### Check corrections` section
[ ] Catalog version bumped if the catalog changed (CI enforces)
[ ] Schema validated; if the schema major moved, migration notes written
[ ] Full test suite green: unit, fixtures, determinism, offline, hostile corpus, distro matrix
[ ] Performance budget assertion green
[ ] Golden-bundle findings diff reviewed by a human, not just green in CI
[ ] Docs updated: version references, generated check reference, compatibility matrix
[ ] Version bumped in one place only (ldflags, not hardcoded anywhere)
[ ] Tag signed and pushed
[ ] GoReleaser: binaries, checksums, SBOM, cosign signature, provenance
[ ] Release notes: highlights, breaking changes, check corrections, upgrade notes, verification instructions
[ ] Artifacts verified by downloading them fresh and running the documented verification steps
[ ] Container image published and its digest recorded in the release notes
```
