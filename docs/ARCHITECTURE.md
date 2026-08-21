# ARCHITECTURE — Plumbline

**Applies to:** v1.x
**Status:** design
**Companion docs:** `DATA-MODEL.md` (schemas), `CHECK-AUTHORING.md` (how to write one), `THREAT-MODEL.md` (the tool's own attack surface)

---

## 1. The central idea

The source design ran checks against the live machine. Plumbline splits that in two:

```
            ┌──────────────┐                    ┌──────────────┐
  host ───► │  COLLECTORS  │ ───► FACT BUNDLE ──►│    CHECKS    │ ───► FINDINGS
            │  (touch OS)  │      (serialisable)│  (pure func) │
            └──────────────┘                    └──────────────┘
             privileged, IO-bound,               unprivileged, CPU-only,
             runs once, ordered                  deterministic, testable
```

Everything downstream follows from this split:

| Consequence | Why it matters |
|---|---|
| One filesystem walk, not twelve | Fixes the concurrency disaster in the source design (audit A-04) |
| Checks are pure functions | 110 checks become unit-testable against fixtures (A-05) |
| Bundles are portable | Re-evaluate old state, offline, after the catalog improves |
| Bundles are diffable | "What changed since March" becomes a first-class feature |
| Collection and evaluation can be separated in time and space | Collect on a locked-down prod host, evaluate on your laptop |
| Fixtures *are* bundles | Test corpus is real recorded system state, not hand-written mocks |

This is the one architectural decision that everything else defers to. Record it as ADR-0001.

---

## 2. Layers

```
┌─────────────────────────────────────────────────────────────────┐
│ CLI (cobra)                                                     │
│ scan · collect · eval · diff · report · check · doctor · version│
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│ ORCHESTRATOR                                                    │
│  resolve config → plan collection → collect → evaluate → score  │
│  → render.  Owns cancellation, timeouts, partial-failure state. │
└──────┬──────────────────────────────┬───────────────────────────┘
       │                              │
┌──────▼───────────────┐   ┌──────────▼──────────────────────────┐
│ COLLECTION           │   │ EVALUATION                          │
│  ┌────────────────┐  │   │  ┌───────────────┐ ┌─────────────┐  │
│  │ Collector      │  │   │  │ Check catalog │ │ Check runner│  │
│  │ registry (DAG) │  │   │  │ (immutable)   │ │ (pure, par.)│  │
│  └────────────────┘  │   │  └───────────────┘ └─────────────┘  │
│  ┌────────────────┐  │   │  ┌───────────────────────────────┐  │
│  │ Walker (single │  │   │  │ Scoring · coverage · grading  │  │
│  │ pass, shared)  │  │   │  └───────────────────────────────┘  │
│  └────────────────┘  │   └──────────┬──────────────────────────┘
└──────┬───────────────┘              │
       │                              │
┌──────▼──────────────────────────────▼───────────────────────────┐
│ FACT BUNDLE  (in memory during `scan`; on disk as .plb archive)  │
│  meta · facts (typed, versioned) · evidence blobs · integrity    │
└──────┬──────────────────────────────┬───────────────────────────┘
       │                              │
┌──────▼───────────────┐   ┌──────────▼──────────────────────────┐
│ SYSTEM (interface)   │   │ RENDERERS                           │
│  fs · exec · proc    │   │  terminal · json · sarif · (v2 html) │
│  sysctl · net · clock│   └─────────────────────────────────────┘
│  ─────────────────── │
│  real │ rooted │ fake│
└──────────────────────┘
```

### 2.1 The `System` interface

Everything that touches the operating system goes through one seam. Nothing else in the codebase is allowed to call `os.Open`, `exec.Command`, or read `/proc` directly — enforced with a lint rule in CI, because this boundary is the whole test strategy and it will erode the first time someone is in a hurry.

```go
// internal/system
type System interface {
    // Filesystem, always relative to the scan root.
    Stat(path string) (FileInfo, error)
    ReadFile(path string) ([]byte, int64, error) // bytes, truncated-at, error
    ReadDir(path string) ([]DirEntry, error)
    Walk(root string, opts WalkOpts, fn WalkFunc) error
    Readlink(path string) (string, error)

    // Processes and kernel state.
    Processes() ([]Process, error)
    Sysctl(key string) (string, error)
    KernelModules() ([]Module, error)

    // External commands. Always argv, never a shell string.
    Exec(ctx context.Context, argv []string, opts ExecOpts) (ExecResult, error)

    // Network state, read locally (never probes remote hosts).
    Listeners() ([]Listener, error)
    Interfaces() ([]Interface, error)

    // Ambient.
    Now() time.Time
    Env(key string) (string, bool)
    Euid() int
    Root() string       // "" for live, "/mnt/host" when rooted
}
```

Three implementations:

| Implementation | Used by | Notes |
|---|---|---|
| `system/live` | `plumbline scan`, `plumbline collect` | Real host. Applies all safety rules from §7. |
| `system/rooted` | `--root /mnt/host` | Same as live, prefixes every path, refuses absolute symlink escapes out of the root. Makes container and mounted-image scanning correct. |
| `system/fake` | tests | Backed by a `testdata/` tree plus a YAML manifest of command outputs, process lists and sysctls. |

`ReadFile` returning a truncation offset is deliberate: a check must never be able to blow up memory because someone made `/etc/passwd` a 4 GB file. Every read has a cap (default 8 MiB, per-collector overridable); exceeding it is a fact-level error, not a panic.

`Exec` takes `argv []string`, never a command string. There is no shell in the collection path. This eliminates an entire vulnerability class before the first check is written.

---

## 3. Collection

### 3.1 Collectors

A collector produces one or more typed facts.

```go
type Collector interface {
    ID() CollectorID              // "passwd", "sshd_config", "mounts", "fswalk"
    DependsOn() []CollectorID     // DAG edges
    Requires() Capability         // None | Root | CapDacReadSearch
    Cost() Cost                   // Trivial | Cheap | Expensive
    Collect(ctx context.Context, s System, in FactSet) (FactSet, error)
}
```

Properties:

- **The registry is a DAG**, topologically sorted before execution. `sshd_effective_config` depends on `sshd_config_files`, which depends on `fs_stat`. Cycles are a startup panic in tests, never in production.
- **Independent branches run concurrently, but concurrency is capped by cost class.** `Expensive` collectors (anything touching the whole filesystem) run with a concurrency of 1. This directly prevents the source design's twelve-simultaneous-`find` problem.
- **Failure is local.** A collector that fails records a `FactError` in the bundle with its reason. Every check that depends on that fact resolves to `UNKNOWN`, with the collector's error as its explanation. The scan continues. There is no path where a collector failure becomes a silent PASS.
- **Collectors are budgeted.** Each declares a timeout; exceeding it is a `FactError{Kind: Timeout}`, not a hang.

### 3.2 The single filesystem walk

One collector, `fswalk`, performs at most one traversal per scan. Consumers register *interest predicates* up front; the walker evaluates all of them per inode in a single pass.

```go
type WalkInterest struct {
    Name      string          // "suid", "world_writable", "unowned", "sticky_dirs"
    Match     func(FileInfo) bool
    Collect   func(path string, fi FileInfo) FactRow
    MaxHits   int             // hard cap; overflow is recorded, not silently dropped
}
```

Walk rules, all non-negotiable and all tested:

- Never crosses filesystem boundaries by default (`--walk-crossfs` opts in).
- Skips by fstype: `proc`, `sysfs`, `devtmpfs`, `cgroup*`, `tracefs`, `debugfs`, `fuse.*`, `nfs*`, `cifs`, `autofs`. Network filesystems are the classic hang.
- Never follows symlinks. Never opens anything that is not a regular file or directory — no FIFOs, no character devices, no sockets. (Opening an unprivileged user's FIFO as root hangs the scanner forever; this is a trivially exploitable local DoS in the source design.)
- Depth limit, inode-count limit, and wall-clock budget. Hitting any limit produces a `Truncated` marker in the fact, and every downstream finding is annotated "based on a partial filesystem scan" rather than pretending to completeness.
- Bind-mount and cycle detection via device+inode set.

### 3.3 The fact bundle

The bundle is the durable artifact. Format: zstd-compressed tar, extension `.plb`.

```
bundle.plb
├── manifest.json          schema version, bundle version, tool version, capabilities used
├── meta.json              hostname*, os-release, kernel, arch, uptime, scan root, timestamps
├── facts/
│   ├── passwd.json        typed, one file per collector
│   ├── sshd.json
│   ├── mounts.json
│   ├── fswalk.json
│   └── ...
├── evidence/
│   └── <sha256>.blob      raw captured bytes, content-addressed and deduplicated
├── errors.json            every FactError, with collector, reason, and timestamp
└── integrity.json         sha256 of every member; optional detached signature alongside
```

Notes:

- `hostname*` and other identifying fields are subject to `--redact` (see `PRIVACY.md`). Redaction happens at collection time, not render time, so a redacted bundle is safe to send.
- Facts are **typed and independently versioned**. `passwd.json` carries `"fact_version": 2`. A check declares which fact versions it understands. Evaluating a new catalog against an old bundle is therefore well-defined: unsupported fact version → `UNKNOWN(fact_version_mismatch)`, never a wrong answer.
- Evidence is content-addressed so that ten checks citing `/etc/login.defs` store it once.
- Bundles are **not** guaranteed to be byte-identical between two collections of the same host — timestamps and process lists move. *Findings* derived from a bundle are guaranteed identical. That is the determinism claim, stated precisely.

---

## 4. Evaluation

### 4.1 The check

```go
type Check struct {
    ID          CheckID       // "SSHD-0009" — permanent, never reused
    Title       string
    Description string
    Severity    Severity      // static default; see §4.4
    Category    Category
    Tags        []string
    Requires    []FactRef     // fact id + minimum fact version
    Applies     func(FactSet) Applicability
    Eval        func(FactSet) Result
    Remediation Remediation
    References  []Reference
    Mappings    []ControlRef  // public-domain frameworks only in v1
    SinceCatalog CatalogVersion
    Deprecated   *Deprecation
}
```

`Eval` receives a `FactSet` and returns a `Result`. It has no `System`, no `context`, no clock, no network. It cannot be slow in any interesting way, and it cannot be flaky. This is enforced by the type signature, which is the only enforcement that actually holds.

### 4.2 Result states

Five, not four. The missing fifth is where the source design's worst failure mode lived.

| State | Meaning | Counts toward score? |
|---|---|---|
| `PASS` | The condition was tested and met | Yes (numerator + denominator) |
| `FAIL` | The condition was tested and not met | Yes (denominator) |
| `NOT_APPLICABLE` | The subject does not exist here (no sshd installed) | No |
| `SKIPPED` | Not run by choice (profile, filter, privilege) | No, but counted in coverage |
| `UNKNOWN` | Could not be determined — fact missing, unparseable, truncated, collector errored, privileges insufficient | No, but counted in coverage **and surfaced prominently** |

`UNKNOWN` is the honesty valve. A hardening tool that reports PASS when it could not read the file is worse than useless, because it converts ignorance into false assurance. Every `UNKNOWN` carries a machine-readable reason code and appears in the report summary, not buried in an appendix.

### 4.3 Findings

```go
type Finding struct {
    CheckID     CheckID
    Result      Result
    Severity    Severity      // effective severity after context adjustment
    BaseSeverity Severity     // catalog default, for auditability
    Title       string
    Detail      string        // rendered message with actual observed values
    Evidence    []Evidence    // source path, byte range, sha256, excerpt
    Remediation *Remediation
    Mappings    []ControlRef
    Fingerprint string        // stable across runs; used by SARIF and suppressions
}
```

**Fingerprint** is `sha256(check_id ‖ normalised_subject)` where subject is the specific thing that failed — the path, the account name, the port. Findings must be stable across runs so that CI can suppress a known-accepted finding, and so SARIF's deduplication in GitHub's security tab works. This is missing from the source design and is the single most-requested feature of every scanner that ships without it.

### 4.4 Severity and context

Static per-check severity is wrong (audit A-20): `PermitRootLogin yes` on an internet-facing bastion is not the same finding as on an air-gapped lab box.

v1 does the minimum honest thing: the catalog ships a `BaseSeverity`, and the *scan context* can adjust it by at most one level, using only facts already collected:

| Context signal | Adjustment |
|---|---|
| Service listening on a non-loopback address and no host firewall present | +1 for network-exposed checks |
| Host has no interactive login accounts besides root | −1 for interactive-session checks |
| `--exposure internal\|internet\|airgapped` supplied by the operator | ±1 per category; the scoring formulas it feeds are in §5 |

Both severities are always reported. No hidden adjustment.

### 4.5 Execution

Checks are pure and fast, so parallelism is trivial and bounded by `GOMAXPROCS`. Each check runs under a `recover()`; a panic becomes `UNKNOWN(internal_error)` with the check ID and a stack trace in the debug log, and CI treats any panic in the fixture corpus as a test failure. One bad check never takes down a scan.

---

## 5. Scoring

The architectural commitments, which are also the implementation:

```
Evaluated  = PASS + FAIL                       // the only states that score
Coverage   = Evaluated / (Total − NOT_APPLICABLE)
Posture    = Σ(weight of PASS) / Σ(weight of Evaluated) × 100
```

- `SKIPPED` and `UNKNOWN` **leave the denominator** and instead reduce **Coverage**. An unprivileged run therefore reports something like `Posture 82 (coverage 44%)`, which is truthful, instead of the source design's `40`, which punishes the user for not being root.
- **Coverage is always displayed next to Posture.** A posture score without its coverage is forbidden in every renderer. This is a rendering-layer invariant, tested.
- Every score is stamped with the **catalog version**. Comparing scores across catalog versions is refused by `plumbline diff` unless `--allow-catalog-drift` is passed, and even then it is annotated.
- **One score, not two.** The source design's Risk Score double-counted the Hardening Index with arbitrary constants. Dropped. Exposure context is expressed through severity adjustment (§4.4), where it is visible and explainable, instead of as a magic additive term.

---

## 6. Command surface

```
plumbline scan     [--root R] [--profile P] [--format ...]   collect + evaluate + render
plumbline collect  -o bundle.plb                             collect only (privileged step)
plumbline eval     bundle.plb [--format ...]                 evaluate only (unprivileged, offline)
plumbline diff     old.plb new.plb                           findings added / resolved / changed
plumbline report   <bundle|findings.json> --format html      re-render without re-evaluating
plumbline check    list | show <id> | explain <id>           catalog introspection
plumbline doctor                                             self-diagnostic, capability report
plumbline version  [--json]                                  tool, catalog, schema versions
plumbline completion <shell>
```

`scan` is `collect | eval` fused for convenience. That the two are genuinely separable is the point: the privileged step and the analysis step are different trust domains, and a hardened environment can run `collect` under audit and `eval` anywhere.

Flag precedence, resolved in this order and documented in `CLI-SPEC.md` (the source design left this ambiguous): explicit flags → `--profile` → config file → built-in defaults. `--module` and `--skip-module` are applied as include-then-exclude. Mode flags (`--quick`, `--full`) are a single mutually exclusive enum, not independent booleans.

---

## 7. Safety rules for the collection path

These derive from `THREAT-MODEL.md` and are stated here because they constrain the architecture. Plumbline runs as root and reads attacker-influenced input; the source design did not consider this at all.

| Rule | Rationale |
|---|---|
| Privileged reads use `openat2` with `RESOLVE_NO_SYMLINKS` / `RESOLVE_BENEATH` where available; fall back to `O_NOFOLLOW` plus post-open `fstat` verification | Defeats symlink swap and TOCTOU against a root reader |
| Only regular files and directories are ever opened | FIFOs block forever; device nodes have side effects |
| Every read is size-capped and the cap is recorded | Prevents memory exhaustion via a hostile `/etc` file |
| No shell, ever. `exec` takes argv | Removes command injection from the collection path |
| `LC_ALL=C`, `LANG=C`, `TZ=UTC`, minimal `PATH`, cleared environment on every exec | Locale-dependent output parsing is the classic silent-wrong-answer bug (audit A-31) |
| All rendered strings are sanitised for terminal control sequences | Filenames containing ANSI escapes otherwise attack the operator's terminal |
| Output files created `0600`, directories `0700`, via `O_EXCL` | Reports are a reconnaissance goldmine (audit A-17) |
| Config from the current working directory is ignored when euid == 0 unless passed explicitly with `--config` | An attacker-controlled `./plumbline.yaml` should not steer a root-run scanner (audit A-30) |
| No network syscalls in the `collect` or `eval` path — enforced by an integration test that runs the binary in a namespace with no network and asserts success | Makes the offline claim testable rather than aspirational |

---

## 8. Repository layout

```
plumbline/
├── cmd/plumbline/main.go
├── internal/
│   ├── cli/                     cobra commands, flag precedence, exit codes
│   ├── orchestrator/            plan → collect → evaluate → score → render
│   ├── system/                  the OS seam
│   │   ├── system.go            interface + shared types
│   │   ├── live/                real host
│   │   ├── rooted/              --root prefixing, escape prevention
│   │   └── fake/                fixture-backed, for tests
│   ├── collect/
│   │   ├── registry.go          DAG, cost classes, budgets
│   │   ├── walker/              the single filesystem pass
│   │   └── collectors/          one package per collector
│   ├── fact/                    typed fact structs + per-fact versioning
│   ├── bundle/                  read/write .plb, integrity, redaction
│   ├── catalog/
│   │   ├── catalog.go           immutable registry, version stamp
│   │   └── checks/              one package per module: kernel, auth, sshd, ...
│   ├── evaluate/                runner, panic isolation, fingerprinting
│   ├── score/                   posture, coverage, severity adjustment
│   ├── render/                  terminal, json, sarif  (+ html from v2)
│   ├── suppress/                suppression files, expiry, justification
│   └── version/                 build info, catalog + schema versions
├── schema/
│   ├── findings-v1.schema.json  THE public API
│   └── bundle-v1.schema.json
├── testdata/
│   ├── fixtures/<distro>/       recorded system trees
│   └── bundles/                 golden bundles + expected findings
├── docs/                        (see DOCUMENT-MAP.md)
├── .github/workflows/
├── Makefile · go.mod · .goreleaser.yaml · LICENSE · README.md
└── SECURITY.md · CONTRIBUTING.md · CHANGELOG.md
```

Note what is absent versus the source design: no `pkg/` public API (v1 keeps everything `internal/`; the JSON schema is the API — see `VERSIONING.md`), no `plugins/`, no `compliance/` data directory, no PDF renderer.

---

## 9. Error and exit model

Findings are one thing; the tool's own health is another. Both must reach CI unambiguously.

| Exit | Meaning |
|---|---|
| 0 | Completed; nothing at or above `--fail-on`; coverage above `--min-coverage` |
| 1 | Usage or configuration error (nothing was scanned) |
| 2 | Completed; findings at or above `--fail-on` |
| 3 | Completed; posture below `--threshold` |
| 4 | Completed **degraded** — one or more collectors errored, or coverage below `--min-coverage` |
| 10 | Insufficient privileges for the requested profile and `--strict-privileges` was set |
| 11 | Timeout exceeded |
| 70 | Internal error (panic escaped, bundle corrupt) |
| 130 | Interrupted |

Precedence, evaluated top-down and **documented as a contract**: `130 > 70 > 11 > 1 > 10 > 4 > 2 > 3 > 0`. The source design's scheme had three codes match a single common outcome with no tiebreak (audit A-20).

Exit code 4 is the one the source design lacked entirely, and it is the important one: CI must be able to tell "your host is misconfigured" apart from "the scanner could not see your host."

---

## 10. Testing strategy

Summarised here because it is an architectural property, not an afterthought. Full detail in `TESTING.md`.

| Layer | Method | Gate |
|---|---|---|
| Checks | Table tests over `system/fake` fixtures | Every check needs ≥1 PASS and ≥1 FAIL fixture. CI fails on any check without both. |
| Collectors | Fixture trees + recorded command output | Parser tests per distro format variant |
| Determinism | Evaluate the same bundle twice, assert byte-identical findings JSON | Every CI run |
| Golden bundles | Real bundles recorded from Ubuntu/Debian/Fedora/Alpine/Arch containers, committed | Findings diff reviewed on every catalog change — this is the regression net |
| Schema | Every rendered JSON validated against `findings-v1.schema.json` | Every CI run |
| Offline | Run the binary in a no-network namespace | Every CI run |
| Robustness | Fuzz the config parsers; hostile-fixture corpus (deep symlink chains, FIFOs, huge files, ANSI filenames, cyclic bind mounts) | Every CI run |
| Integration | Real containers per distro, assert no panics and non-empty coverage | Nightly |
| Performance | Timed scan of a standard fixture host, assert against budget | Every PR |

The golden-bundle corpus is the highest-leverage asset in the repository. Once ~20 recorded bundles exist across distros, any catalog change instantly shows its blast radius as a findings diff — which no shell-based auditor can do at all.

---

## 11. Dependencies

Kept deliberately small; every dependency in a root-privileged security tool is
supply-chain surface (`CONTRIBUTING.md` rule 7).

**Four, as shipped at v1.0.0:**

| Need | Choice | Note |
|---|---|---|
| CLI | `spf13/cobra` (+ `spf13/pflag`) | Standard |
| Compression | `klauspost/compress/zstd` | Pure Go; the bundle format |
| Schema validation | `santhosh-tekuri/jsonschema/v5` | Test-time, validates `findings-v1` |
| Build and release | `goreleaser`, `syft`, `cosign` | Tooling, not linked in — see `SUPPLY-CHAIN.md` |

Everything else is the standard library. Config parsing is hand-rolled, tests
use `testing` and nothing else, and the terminal report — grid, colour, box
drawing, ANSI-aware padding — is this project's own code in
`internal/render/text`.

**This table previously listed `charmbracelet/lipgloss`, `charmbracelet/bubbles`,
`gopkg.in/yaml.v3`, `google/go-cmp` and `testify`.** None of them is in
`go.mod`; the list described an intention from the design phase that the
implementation never took up, except for lipgloss, which was added during the
release candidates and removed before GA when it proved to cost thirteen
transitive modules for a box border. Corrected in the v1.0.0 documentation
review (WP-38); the history is in `CHANGELOG.md` under `v1.0.0-rc1`.

The dependency count is itself a control, and the SBOM published with every
release is what makes it checkable rather than a claim.

## 12. What is explicitly deferred

So that "we'll add it later" is a decision on record rather than an omission:

| Deferred | To | Why |
|---|---|---|
| Vulnerability correlation | v2 | Needs vendor security feeds; doing it with NVD alone is wrong (audit A-03) |
| Compliance mapping beyond public-domain frameworks | v2, as user-supplied packs | Licensing (audit A-02) |
| Containers / cloud modules | v2 | Larger fixture surface; cloud needs IMDS network access, which breaks the offline invariant and needs its own opt-in flag |
| Remediation script generation | v2 | The check catalog must stabilise first, or every fix is rewritten |
| Interactive TUI browser | v2 | Value is real, cost is high, JSON + terminal covers v1 |
| Extension mechanism | v3 | Not Go `plugin` under any circumstances (audit A-06) |
| macOS | v3 | Needs hardware and a fixture corpus; do not claim it before then |
| Fleet aggregation | v3 | Bundles make it natural later; premature now |
