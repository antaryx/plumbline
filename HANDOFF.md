# PLUMBLINE — Project Handoff

**Prepared:** 18 August 2026
**For:** an AI assistant or developer picking this project up with no prior context
**Accompanies:** `plumbline.zip` (77 files)
**Repository target:** `github.com/antaryx/plumbline`

Read this document fully before touching the archive. It explains not just what
exists, but *why* — and several design decisions look arbitrary until you know
what they are correcting.

---

## 1. What Plumbline is

> A deterministic, offline, evidence-first host security auditor for Linux.

A single static Go binary that inspects a Linux host's configuration and reports
what is misconfigured, with the evidence attached. Comparable in ambition to
Lynis, but built on a different foundation.

| Field | Value |
|---|---|
| Name | Plumbline |
| Binary | `plumbline` |
| Module | `github.com/antaryx/plumbline` |
| Language | Go 1.23+, `CGO_ENABLED=0`, standard library plus a minimal dependency set |
| Licence | Apache-2.0 (code); see `docs/COMPLIANCE-DATA-POLICY.md` for data |
| Tagline | *Hang a line. See what's true.* |
| Owner | Antaryx |
| Status | Pre-v0.1. Reference vertical slice implemented, tested, green. |

**The name:** a plumb line is a weighted cord that reveals true vertical. It does
not defend the wall or build it — it tells you, unarguably and repeatably, how
far off true the wall already is. That is precisely the tool's role: measure
against a reference, report deviation, never pretend to fix anything.

---

## 2. How this project came to exist

A friend shared a design document for a security tool called **ARGUS** — 1,529
lines describing 20 modules, 253 checks, 8 compliance frameworks, 8 output
formats, 7 operating systems, 5 CPU architectures, an embedded CVE database, and
a hosted plugin registry with a signed marketplace.

That document was audited. The audit is preserved at
`docs/audit/argus-design-audit.md` and is **essential reading** — every
significant architectural decision in Plumbline traces to a finding in it.

The audit raised **34 issues: 6 blockers, 17 major, 11 minor**. The six blockers:

| ID | Blocker | Correction in Plumbline |
|---|---|---|
| A-01 | Scope was ~3–5 engineer-years with no shippable slice | v1 rescoped to ~110 checks, Linux only, no network, no plugins |
| A-02 | Shipping CIS / PCI-DSS / ISO 27001 control data under Apache-2.0 is a copyright problem | Public-domain frameworks only; user-supplied mapping packs for the rest (`COMPLIANCE-DATA-POLICY.md`) |
| A-03 | CVE matching by installed version against NVD is *wrong* for distro packages — vendors backport fixes without bumping versions, producing hundreds of false criticals | Vendor security feeds (Debian/Ubuntu/RHEL/SUSE/Alpine OVAL, OSV), deferred to v2 with a measured false-positive comparison as the release gate (ADR-0004) |
| A-04 | No fact-collection layer: a dozen checks each needed a full filesystem walk, run in parallel goroutines | Collect-once/evaluate-many split, single shared walk with interest predicates (ADR-0001) |
| A-05 | 253 checks were untestable — checks read the live machine, so verifying them needed ~1000 VMs | Checks are pure functions over facts; fixture-backed `System` implementation (ADR-0001) |
| A-06 | "Stable plugin ABI" is impossible in Go — the `plugin` package requires identical toolchain and dependency versions, and breaks static linking | Go `plugin` never used; declarative packs and a subprocess protocol in v3 (ADR-0002) |

Other notable findings that shaped the design: the original claimed "300+
checks" while enumerating 253; called a self-embedded SHA-256 a "digital
signature"; promised "no network during scan" while the CLOUD module queried
IMDS; and documented a `docker run` invocation that scans the *container*
rather than the host and reports the result as if it were the host.

**If you are asked to add a feature, check the audit first.** Several obvious
ideas — auto-remediation, compliance percentages, a plugin ABI, a `--fix` flag —
were considered and rejected with reasons recorded in `docs/adr/`.

---

## 3. The core architecture, in one page

This is the single most important section. Everything else follows from it.

```
            ┌──────────────┐                     ┌──────────────┐
  host ───► │  COLLECTORS  │ ───► FACT BUNDLE ───►│    CHECKS    │ ───► FINDINGS
            │  (touch OS)  │      (serialisable) │  (pure func) │
            └──────────────┘                     └──────────────┘
             privileged, IO-bound,                unprivileged, CPU-only,
             runs once, ordered, budgeted         deterministic, testable
```

**Collectors** are the only code that touches the operating system. They produce
typed, serialisable **facts**.

**Checks** are pure functions from facts to findings. No IO, no clock, no
network, no randomness. The function signature is the enforcement.

Between them sits the **fact bundle**: a zstd-compressed tar containing the raw
system state, its evidence, and any collection errors.

### What this buys

| Property | Consequence |
|---|---|
| One filesystem walk, shared | Fixes the concurrency disaster in the original design |
| Checks are pure | ~110 checks become unit-testable against fixtures instead of VMs |
| Bundles are portable | Collect on a locked-down production host, evaluate on a laptop |
| Bundles are archival | Re-evaluate a six-month-old bundle against today's catalog, offline |
| Bundles are diffable | "What changed since March" is a first-class feature |
| Fixtures *are* bundles | The test corpus is recorded real system state, not hand-written mocks |

Lynis, OpenSCAP and every shell-based auditor structurally cannot do the middle
four. That is the product's wedge.

### The five result states

Four states existed in the original design: PASS, FAIL, N/A, SKIP. There was
nowhere to put *"I could not determine this"* — so a permission error, an
unparseable file, or an unresolvable include would become either a crash or a
`PASS`.

Plumbline adds `UNKNOWN` as a first-class result with a machine-readable reason.

| State | Scores? | Affects coverage? |
|---|---|---|
| `PASS` | numerator + denominator | no |
| `FAIL` | denominator | no |
| `NOT_APPLICABLE` | no | no — leaves the population entirely |
| `SKIPPED` | no | **reduces coverage** |
| `UNKNOWN` | no | **reduces coverage** |

This is also the scoring fix. Because `SKIPPED` and `UNKNOWN` leave the
denominator, an unprivileged run reports `posture 82 (coverage 44%)` — which is
true — rather than the original design's `40`, which punished the user for not
being root. **No renderer may display posture without coverage.**

### The governing principle

> **A check that cannot verify something must never report `PASS`.**

Returning `UNKNOWN` is always correct when you do not know. Returning `PASS`
because a file was unreadable tells an operator their system is fine when it may
not be — and unlike a crash, there is no symptom that would ever prompt them to
look again. This is the worst bug the codebase can contain, and most of the
architecture exists to make it structurally difficult.

---

## 4. What is built and verified

The reference vertical slice is **complete, compiling, and tested**. This is not
illustrative pseudocode; Go 1.22 was installed and everything below was run.

```
make verify
  → gofmt clean
  → go vet clean
  → 9/9 fixture cases pass
  → race-clean
  → ok: system seam intact
  → ok: checks are pure
```

### Packages

| Package | Role |
|---|---|
| `internal/system` | The single OS seam. Interface plus `live` (scan-root aware, safety-hardened) and `fake` (fixture-backed). |
| `internal/fact` | Typed facts, `FactSet`, typed fact errors, generic `Get[T]` returning a three-state result. |
| `internal/finding` | Result, Severity, Evidence, Remediation, Fingerprint. Serialises directly into the public schema. |
| `internal/catalog` | Check type, immutable registry, evaluation runner with required-fact gating and panic isolation. |
| `internal/collect/collectors/sshd` | The sshd configuration collector. |
| `internal/catalog/checks/sshd` | SSHD-0002, the reference check. |

### The reference check: SSHD-0002 (root login over SSH disabled)

Chosen deliberately as the first check because it is the hardest of the easy
ones — `Include` resolution, `Match` block scoping, first-value-wins precedence
and distro divergence all appear here. Building it first surfaced the difficulty
at the start rather than in month four.

Nine fixtures cover all five result states. Three of them are the cases that
separate a real auditor from a naive one:

| Fixture | What it proves |
|---|---|
| `sshd-include` | Value arrives via `/etc/ssh/sshd_config.d/50-cloud-init.conf`, included on line 1, so it wins over a later `PermitRootLogin yes` in the main file. A tool reading only `sshd_config` returns the **opposite verdict**. |
| `sshd-match-trap` | The only `no` sits inside `Match Address 10.0.0.0/8` and does not govern the global config. The finding attaches that line as evidence explaining *why* it does not count — otherwise the operator sees the tool contradicting their file and stops trusting it. |
| `sshd-unresolved-include` | Keyword absent, but an `Include` matched nothing. Returns `UNKNOWN`, not the documented default. **This single test case is the thesis of the entire project.** |

### The two enforced invariants

Both are mechanical, run by `make invariants`, and blocked on by CI:

1. **`make check-system-seam`** — greps for `os.ReadFile`, `os.Open`, `os.Stat`,
   `exec.Command`, `ioutil.*` outside `internal/system`. Violating this makes
   every check untestable.
2. **`make check-check-purity`** — blocks `context`, `time`, `net`, `math/rand`
   and `internal/system` imports inside `internal/catalog/checks/`.

These gates exist now, at check #1, when complying costs nothing — not at check
#40, when it costs a refactor.

### Security hardening already in `internal/system/live`

Derived from `docs/THREAT-MODEL.md`. The binary runs as root and parses
attacker-influenceable input, which the original design never considered.

- `O_NOFOLLOW` on open, then `fstat` on the **already-open descriptor** —
  verifying after opening, not before, is what closes the TOCTOU window
- Only regular files are ever read; a FIFO where a config is expected would
  otherwise hang a root process forever (a trivial local DoS)
- `O_NONBLOCK` so the open returns rather than blocking
- Every read size-capped (8 MiB default), truncation recorded as a fact error
- `Exec` takes `argv []string` — there is no shell anywhere in the collection path
- Environment **replaced**, not extended: `LC_ALL=C`, `LANG=C`, `TZ=UTC`,
  minimal `PATH`. Locale-dependent output parsing is a silent-wrong-answer bug.
- `Include` recursion depth-bounded with cycle detection

---

## 5. The archive: what is in it

**77 files.** Everything is one self-contained tree.

### Governance and contract (11 root files + 3 dotfiles)

`README.md` · `CLAUDE.md` · `LICENSE` (canonical Apache-2.0) · `NOTICE` ·
`CHANGELOG.md` · `CONTRIBUTING.md` · `SECURITY.md` · `CODE_OF_CONDUCT.md` ·
`MAINTAINERS.md` · `LEGAL-DISCLAIMER.md` · `Makefile` ·
`.gitignore` · `.gitattributes` · `.golangci.yml`

`.gitattributes` is not boilerplate: it marks `testdata/fixtures/**` as `-text`
so git cannot normalise line endings. The CRLF fixture exists specifically to
test CRLF handling, and normalisation would silently delete the test.

### `.github/` (6 files)

CI workflow, dependabot, CODEOWNERS, PR template, and two issue templates — one
for bugs, one specifically for **false positives / wrong verdicts**, which are
the most valuable reports this kind of project receives.

### `docs/` (13 documents)

| Document | Purpose |
|---|---|
| `PROJECT-BRIEF.md` | Identity, naming rationale and verification checklist, users, differentiation, non-negotiables |
| `ARCHITECTURE.md` | Layers, the OS seam, collection, bundles, evaluation, scoring, safety rules, repo layout, error model, test strategy |
| `DATA-MODEL.md` | **Normative.** Facts, findings, bundles, versioning, invariants, worked example |
| `CHECK-AUTHORING.md` | How to add a check, end to end |
| `FIXTURES.md` | Fixture format, the `system/fake` contract, the cases people forget |
| `CLI-SPEC.md` | Commands, flags, precedence, exit codes with a precedence ladder |
| `THREAT-MODEL.md` | Plumbline's own attack surface — 11 threats, mitigations, residual risks |
| `COMPLIANCE-DATA-POLICY.md` | What may and may not be shipped; the takedown-risk prevention |
| `VERSIONING.md` | Four independent version numbers and their contracts |
| `DEPLOYMENT.md` | Build, sign, publish, distribute, install, air-gap, upgrade, incident response |
| `ROADMAP.md` | Three stable majors with exit criteria, plus a graveyard of rejected ideas |
| `DOCUMENT-MAP.md` | Every document the project needs, tiered and gated by release |
| `BUILD-RUNBOOK-v0.1.md` | Sequenced, session-sized work packages |
| `GLOSSARY.md` | Vocabulary, and the words we deliberately never use |

### `docs/adr/` (8 files)

Seven decision records for choices that would be expensive to reverse:

| ADR | Decision |
|---|---|
| 0001 | Split collection from evaluation |
| 0002 | Go's `plugin` package is never used |
| 0003 | No compliance percentages, ever |
| 0004 | Vendor security data, not NVD version matching |
| 0005 | Five result states, with UNKNOWN first-class |
| 0006 | Plumbline never applies a change |
| 0007 | The JSON schema is the public API, not a Go package |

**Never edit an accepted ADR's decision.** Supersede it with a new one so the
reasoning history stays intact.

### `docs/checks/` (2 files)

`_TEMPLATE.md` — the per-check specification template, and `SSHD-0002.md` — the
worked example. Ten sections including a verdict table, a "where this check
cannot know" section, distribution variations, and known false positives.

### `docs/audit/` (1 file)

The full ARGUS audit. Background, but load-bearing background.

### `schema/` (2 files)

`findings-v1.schema.json` and `bundle-v1.schema.json`. Both validated as JSON
Schema Draft 2020-12, with the findings schema's conditional rules tested
against negative cases. The `allOf` blocks enforce structurally:

- `UNKNOWN` requires an `unknown_reason`
- `FAIL` requires both `remediation` and `evidence`
- any non-`FAIL` result must **not** carry `remediation`
- `check_id` must match `^[A-Z][A-Z0-9]*-[0-9]{4}$`

All four were confirmed to reject violating documents.

### `internal/` (9 Go files) and `testdata/` (18 fixture files)

~1,800 lines of Go, deliberately over-commented in the reference paths.

---

## 6. Non-negotiable rules

`CLAUDE.md` in the archive is the authoritative version. Summary:

1. **Only `internal/system` touches the OS.** Enforced.
2. **Checks are pure.** No `context`, `time`, `net`, `math/rand`, `internal/system`. Enforced.
3. **A check never guesses.** Cannot verify ⇒ `UNKNOWN` with a reason code.
4. **Check IDs are permanent.** Never renumbered, never reused, never repurposed. They live in users' suppression files.
5. **Every check needs PASS and FAIL fixtures** at minimum.
6. **Never invent a schema.** `schema/*.json` is the contract.
7. **No new dependencies without asking.** This binary runs as root.
8. **No shell.** `Exec` takes argv.
9. **Never claim done without running `make verify` and pasting the output.**
10. **No auto-remediation.** No `--fix` flag, in any version, permanently.

Additionally, from `CONTRIBUTING.md`:

- **No speculative scaffolding.** An empty package or a TODO stub looks like a
  decision that was never made.
- **No flags, config keys or output fields nobody asked for.** Surface area is
  permanent.
- **Ambiguity is a question, not a choice.** A wrong guess in a security check
  ships a wrong verdict, and it survives review because it looks confident.

---

## 7. What to do next

Follow `docs/BUILD-RUNBOOK-v0.1.md`. WP-00 through WP-05 are **complete**.

| WP | Work | Notes |
|---|---|---|
| **06** | Fixture coverage gate (`tools/fixturegate`) | **Start here.** Parses check IDs and test tables with `go/ast`, asserts PASS+FAIL coverage. Makes the rule mechanical before compliance gets expensive. |
| 07 | Bundle write and read | First external dependency: `klauspost/compress` for zstd. Pure Go, no CGO. |
| 08 | Collector registry and runner | DAG ordering, cost classes, timeout budgets, panic isolation, `Expensive` collectors serialised to concurrency 1 |
| 09 | Evidence blobs | Content-addressed, deduplicated; also where excerpt sanitisation lands (a security control, not formatting) |
| 10 | Scoring | Posture + coverage. Note: all-`SKIPPED` yields coverage 0 and posture **undefined**, not 0 — different statements. |
| 11 | JSON renderer | Deterministic ordering; CI validates every output against the schema |
| 12 | CLI: `collect`, `eval`, `scan` | Exit-code precedence ladder as one tested function |
| 13 | Offline and hostile-input proof | Network-namespace test; FIFO, symlink chains, huge files, ANSI filenames, cyclic includes |
| 14 | CI expansion | Distro matrix containers |

Each work package has explicit acceptance criteria. **Execute one per session
and audit against those criteria before merging** — batching two makes the
review surface too large to audit properly, which defeats the purpose.

After v0.1, catalog expansion follows a known-good pattern, ordered
cheapest-facts-first so the pattern is well-worn before the hard parsing
arrives: KERNEL → USERS → SSHD remainder → CRON → LOGGING → SERVICES → NETWORK
→ FILESYS (needs the shared walker, its own work package) → AUTH (PAM parsing,
hardest, deliberately last).

---

## 8. The three-release plan

| Release | Theme | Scope | Estimated effort |
|---|---|---|---|
| **v1.0.0** | Trustworthy core | Linux only, ~110 checks in 10 modules, fact bundles, terminal + JSON + SARIF, diff, deterministic exit codes. **No** network, plugins, CVEs, compliance scoring, macOS, containers, or remediation generation. | ~4–6 months part-time |
| **v2.0.0** | Intelligence | Vulnerability correlation via vendor feeds, CONTAINERS and PRIVESC and MEMORY and INTEGRITY modules (~250 checks), HTML reports, remediation script generation, user-supplied compliance mapping packs, TUI browser | ~6–8 months |
| **v3.0.0** | Reach | Declarative check packs, subprocess extension protocol, macOS, fleet aggregation, policy-as-code baselines, public Go API | ~6–9 months |

Each is a complete, defensible product on its own. If development stops after
v1, what exists is still worth using — that is deliberate.

---

## 9. Verification status — what was actually run

Stated precisely, because the audited design's central failure was numbers that
were decorative rather than measured.

| Claim | Verified how |
|---|---|
| Code compiles | `go build ./...`, Go 1.22.2 |
| Code vets clean | `go vet ./...` |
| Formatting clean | `gofmt -l .` returns empty |
| 9 fixture cases pass | `go test -v`, all subtests named and passing |
| Race-clean | `go test -race ./...` |
| Determinism | 50 consecutive evaluations produce identical output |
| Fingerprint stability | PASS and FAIL fixtures produce the same fingerprint |
| Panic safety | Empty `FactSet` yields `UNKNOWN(fact_not_collected)`, no crash |
| System seam intact | `make check-system-seam` |
| Checks pure | `make check-check-purity` |
| Schemas valid | `jsonschema` Draft 2020-12 `check_schema` on both |
| Schema invariants bite | Four negative cases confirmed rejected |
| Rename complete | Zero `scorpio` matches across all 77 files |

**Not verified:** anything requiring Go 1.23 (only 1.22 was available — bump
`go.mod` and re-run; nothing uses 1.23-only features), and any runtime behaviour
of code that does not yet exist (WP-06 onward).

---

## 10. Documents deliberately not yet written

Honest accounting. The **build-enabling** set is complete; the
**release-hardening** set is not, and writing it now would be premature.

### Needed before v1.0.0 ships, not before code is written

| Document | Why deferred |
|---|---|
| `TESTING.md` | Strategy is summarised in `ARCHITECTURE.md` §10; the full document should describe practices that exist, not intentions |
| `RELEASE-PROCESS.md` | Human runbook; write it while cutting the first real release |
| `SUPPLY-CHAIN.md` | Signing and reproducibility detail; `DEPLOYMENT.md` §3 covers the design |
| `PRIVACY.md` | Depends on what bundles actually contain after WP-07 |
| `SUPPORT-POLICY.md` | Compatibility matrix needs releases to describe |
| `PLATFORM-SUPPORT.md` | Tiers must reflect what is genuinely in CI |
| `PERFORMANCE.md` | **Every number must be measured.** Cannot be written before WP-12. |
| `CI-CD.md` | Workflow inventory; the workflow exists, the document describes it after WP-14 |

### User documentation — needed at v1.0.0

`INSTALLATION.md` · `QUICKSTART.md` · `USAGE.md` · `CI-INTEGRATION.md` ·
`TROUBLESHOOTING.md` · `FAQ.md` · `FALSE-POSITIVES.md`

### Generated, never hand-written

`MODULE-CATALOG.md` and `CHECK-REFERENCE.md` are produced by `make docs` from
the catalog. Hand-maintained check lists are wrong within a month — the original
design's "300+ checks" claim against 253 enumerated is exactly this failure.

### The real remaining backlog

**~110 per-check specifications** in `docs/checks/`. This is the largest body of
work left, and it is domain research rather than writing: for each check, the
facts consumed, the exact PASS predicate, what makes it N/A, what makes it
UNKNOWN, distribution variations, known false positives.

**Do not write these all at once.** Write one module's worth immediately before
that module's work package, while the previous module's lessons are fresh.
Specifying AUTH before KERNEL has been built means specifying AUTH wrongly.

---

## 11. Open items for whoever continues

1. **Verify the name.** Searching found no security tool using "Plumbline", but
   confirm independently: GitHub org, `plumbline.dev`/`.io`, `pkg.go.dev`,
   trademark registries in classes 9 and 42, and package registries. Backups in
   `PROJECT-BRIEF.md` §1.1 are **Bartizan**, **Revetment**, **Assay**.
2. **Bump `go.mod` to 1.23** and re-run `make verify`.
3. **Decide on the bundle schema.** A bundle schema was found already present
   during preparation, with a different member layout (`collection`/`members`/
   `signature`). It was replaced with one matching `DATA-MODEL.md` §6
   (`manifest.json` + `facts/` + `evidence/` + `errors.json` + `integrity.json`)
   and validated. If the earlier layout was intentional, reconcile deliberately —
   do not let the two drift.
4. **Highest residual security risk:** `THREAT-MODEL.md` T-01. Intermediate path
   components are not yet resolved atomically. `openat2(RESOLVE_NO_SYMLINKS|
   RESOLVE_BENEATH)` on Linux 5.6+ closes it properly and is scheduled for
   v1.0.0. Until then, **no collector may read a path beneath a world-writable
   directory.**

---

## 12. Working with this project

If you are an AI assistant picking this up:

- **`CLAUDE.md` is your contract.** Read it before your first edit, in every
  session. The invariants are cheap to violate and expensive to discover.
- **Copy the reference implementation's shape.** `sshd0002.go` and `sshd.go` are
  deliberately over-commented for exactly this purpose.
- **Read before writing.** `DATA-MODEL.md` and `FIXTURES.md` are normative. If
  your code disagrees with them, your code is wrong until the document is
  changed deliberately.
- **Run `make verify` and paste the output.** "It should work" is not a status
  report, and this project's owner audits before merging.
- **Say so when you disagree with the design.** It has been audited once and was
  wrong in six places. It can be wrong again.
- **Stop and ask when a spec is ambiguous.** Do not resolve ambiguity by
  choosing. In a security tool, a confident wrong guess passes review.

The owner's established working pattern: an assistant authors the runbook
prompt, the owner executes it through a coding agent, and results are audited
against acceptance criteria before any irreversible action. Verify-first,
always.
