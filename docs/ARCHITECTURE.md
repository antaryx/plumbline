# Plumbline architecture

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
| One filesystem walk, not twelve | Fixes the concurrent-walk problem in the source design (audit A-04) |
| Checks are pure functions | 110 checks become unit-testable against fixtures (A-05) |
| Bundles are portable | Re-evaluate old state, offline, after the catalog improves |
| Bundles are diffable | "What changed since March" becomes a first-class feature |
| Collection and evaluation can be separated in time and space | Collect on a locked-down prod host, evaluate on your laptop |
| Fixtures are bundles | Test corpus is real recorded system state, not hand-written mocks |

Everything else defers to this decision. It is recorded as ADR-0001.

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

Everything that touches the operating system goes through one seam. Nothing else in the codebase may call `os.Open`, `exec.Command`, or read `/proc` directly. A lint rule in CI enforces this, because the boundary is the whole test strategy and it erodes without enforcement.

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

`ReadFile` returns a truncation offset so a check cannot exhaust memory because someone made `/etc/passwd` a 4 GB file. Every read has a cap (default 8 MiB, overridable per collector); exceeding it is a fact-level error, not a panic.

`Exec` takes `argv []string`, never a command string. There is no shell in the collection path, which removes command injection as a class.

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

- The registry is a DAG, topologically sorted before execution. `sshd_effective_config` depends on `sshd_config_files`, which depends on `fs_stat`. Cycles are a startup panic in tests, never in production.
- Independent branches run concurrently, but concurrency is capped by cost class. `Expensive` collectors (anything touching the whole filesystem) run with a concurrency of 1. This prevents the source design's twelve-simultaneous-`find` problem.
- Failure is local. A collector that fails records a `FactError` in the bundle with its reason. Every check that depends on that fact resolves to `UNKNOWN`, with the collector's error as its explanation. The scan continues, and there is no path where a collector failure becomes a silent PASS.
- Collectors are budgeted. Each declares a timeout; exceeding it is a `FactError{Kind: Timeout}`, not a hang.

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

Walk rules, all tested:

- Never crosses filesystem boundaries by default (`--walk-crossfs` opts in).
- Skips by fstype: `proc`, `sysfs`, `devtmpfs`, `cgroup*`, `tracefs`, `debugfs`, `fuse.*`, `nfs*`, `cifs`, `autofs`. Network filesystems are a common cause of hangs.
- Never follows symlinks. Never opens anything that is not a regular file or directory: no FIFOs, no character devices, no sockets. (Opening an unprivileged user's FIFO as root blocks indefinitely, which was a local denial of service against the source design.)
- Depth limit, inode-count limit, and wall-clock budget. Hitting any limit produces a `Truncated` marker in the fact, and every downstream finding is annotated "based on a partial filesystem scan" rather than reported as complete.
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
- Facts are typed and independently versioned. `passwd.json` carries `"fact_version": 2`. A check declares which fact versions it understands. Evaluating a new catalog against an old bundle is therefore well-defined: unsupported fact version → `UNKNOWN(fact_version_mismatch)`, never a wrong answer.
- Evidence is content-addressed so that ten checks citing `/etc/login.defs` store it once.
- Bundles are not guaranteed to be byte-identical between two collections of the same host, because timestamps and process lists move. Findings derived from a bundle are guaranteed identical. That is the determinism claim.

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

`Eval` receives a `FactSet` and returns a `Result`. It has no `System`, no `context`, no clock and no network, so it cannot block and cannot be flaky. The type signature is what enforces this.

### 4.2 Result states

Five, not four. The fifth state is the one the source design lacked.

| State | Meaning | Counts toward score? |
|---|---|---|
| `PASS` | The condition was tested and met | Yes (numerator + denominator) |
| `FAIL` | The condition was tested and not met | Yes (denominator) |
| `NOT_APPLICABLE` | The subject does not exist here (no sshd installed) | No |
| `SKIPPED` | Not run by choice (profile, filter, privilege) | No, but counted in coverage |
| `UNKNOWN` | Could not be determined: fact missing, unparseable, truncated, collector errored, privileges insufficient | No, but counted in coverage and surfaced in the summary |

`UNKNOWN` is what keeps the other four states honest. A tool that reports PASS when it could not read the file converts ignorance into false assurance. Every `UNKNOWN` carries a machine-readable reason code and appears in the report summary rather than in an appendix.

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

The fingerprint is `sha256(check_id ‖ normalised_subject)`, where the subject is the specific thing that failed: the path, the account name, the port. Findings have to be stable across runs so CI can suppress a known-accepted finding and so SARIF deduplication in GitHub's security tab works. The source design had no equivalent.

### 4.4 Severity and context

Static per-check severity is wrong (audit A-20): `PermitRootLogin yes` on an internet-facing bastion is not the same finding as on an air-gapped lab box.

v1 does the minimum: the catalog ships a `BaseSeverity`, and the scan context can adjust it by at most one level, using only facts already collected:

| Context signal | Adjustment |
|---|---|
| Service listening on a non-loopback address and no host firewall present | +1 for network-exposed checks |
| Host has no interactive login accounts besides root | −1 for interactive-session checks |
| `--exposure internal\|internet\|airgapped` supplied by the operator | ±1 per category; the scoring formulas it feeds are in §5 |

Both severities are always reported; no adjustment is hidden.

### 4.5 Execution

Checks are pure and fast, so parallelism is trivial and bounded by `GOMAXPROCS`. Each check runs under a `recover()`; a panic becomes `UNKNOWN(internal_error)` with the check ID and a stack trace in the debug log, and CI treats any panic in the fixture corpus as a test failure. A single failing check does not stop the scan.

---

## 5. Scoring

The architectural commitments, which are also the implementation:

```
Evaluated  = PASS + FAIL                       // the only states that score
Coverage   = Evaluated / (Total − NOT_APPLICABLE)
Posture    = Σ(weight of PASS) / Σ(weight of Evaluated) × 100
```

- `SKIPPED` and `UNKNOWN` leave the denominator and instead reduce coverage. An unprivileged run therefore reports something like `Posture 82 (coverage 44%)` rather than the source design's `40`, which penalised the user for not being root.
- Coverage is always displayed next to posture. A posture score without its coverage is rejected in every renderer. This is a rendering-layer invariant, and it is tested.
- Every score is stamped with the catalog version. Comparing scores across catalog versions is refused by `plumbline diff` unless `--allow-catalog-drift` is passed, and even then it is annotated.
- One score, not two. The source design's Risk Score double-counted the Hardening Index with arbitrary constants and was dropped. Exposure context is expressed through severity adjustment (§4.4), where it is visible and explainable, rather than as an additive term.

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

`scan` is `collect | eval` fused for convenience. The two remain separable because the privileged step and the analysis step are different trust domains: a hardened environment can run `collect` under audit and `eval` anywhere.

Flag precedence, resolved in this order and documented in `CLI-SPEC.md` (the source design left this ambiguous): explicit flags → `--profile` → config file → built-in defaults. `--module` and `--skip-module` are applied as include-then-exclude. Mode flags (`--quick`, `--full`) are a single mutually exclusive enum, not independent booleans.

---

## 7. Safety rules for the collection path

These derive from `THREAT-MODEL.md` and are stated here because they constrain the architecture. Plumbline runs as root and reads attacker-influenced input; the source design did not consider it.

| Rule | Rationale |
|---|---|
| Privileged reads use `openat2` with `RESOLVE_NO_SYMLINKS` / `RESOLVE_BENEATH` where available; fall back to `O_NOFOLLOW` plus post-open `fstat` verification | Defeats symlink swap and TOCTOU against a root reader |
| Only regular files and directories are ever opened | FIFOs block indefinitely; device nodes have side effects |
| Every read is size-capped and the cap is recorded | Prevents memory exhaustion via a hostile `/etc` file |
| No shell, ever. `exec` takes argv | Removes command injection from the collection path |
| `LC_ALL=C`, `LANG=C`, `TZ=UTC`, minimal `PATH`, cleared environment on every exec | Locale-dependent output parsing is a common silent-wrong-answer bug (audit A-31) |
| All rendered strings are sanitised for terminal control sequences | Filenames containing ANSI escapes otherwise attack the operator's terminal |
| Output files created `0600`, directories `0700`, via `O_EXCL` | Reports contain reconnaissance-grade detail (audit A-17) |
| Config from the current working directory is ignored when euid == 0 unless passed explicitly with `--config` | An attacker-controlled `./plumbline.yaml` should not steer a root-run scanner (audit A-30) |
| No network syscalls in the `collect` or `eval` path, enforced by an integration test that runs the binary in a namespace with no network and asserts success | Makes the offline claim testable |

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

Note what is absent versus the source design: no `pkg/` public API (v1 keeps everything `internal/`, and the JSON schema is the API; see `VERSIONING.md`), no `plugins/`, no `compliance/` data directory, no PDF renderer.

---

## 9. Error and exit model

Findings are one thing and the tool's own health is another. Both have to reach CI unambiguously.

| Exit | Meaning |
|---|---|
| 0 | Completed; nothing at or above `--fail-on`; coverage above `--min-coverage` |
| 1 | Usage or configuration error (nothing was scanned) |
| 2 | Completed; findings at or above `--fail-on` |
| 3 | Completed; posture below `--threshold` |
| 4 | Completed degraded: one or more collectors errored, or coverage below `--min-coverage` |
| 10 | Insufficient privileges for the requested profile and `--strict-privileges` was set |
| 11 | Timeout exceeded |
| 70 | Internal error (panic escaped, bundle corrupt) |
| 130 | Interrupted |

Precedence, evaluated top-down and documented as a contract: `130 > 70 > 11 > 1 > 10 > 4 > 2 > 3 > 0`. The source design's scheme had three codes match a single common outcome with no tiebreak (audit A-20).

Exit code 4 is the one the source design lacked. CI has to be able to tell "your host is misconfigured" apart from "the scanner could not see your host."

---

## 10. Testing strategy

Summarised here because it constrains the architecture. Full detail in `TESTING.md`.

| Layer | Method | Gate |
|---|---|---|
| Checks | Table tests over `system/fake` fixtures | Every check needs ≥1 PASS and ≥1 FAIL fixture. CI fails on any check without both. |
| Collectors | Fixture trees + recorded command output | Parser tests per distro format variant |
| Determinism | Evaluate the same bundle twice, assert byte-identical findings JSON | Every CI run |
| Golden bundles | Real bundles recorded from Ubuntu/Debian/Fedora/Alpine/Arch containers, committed | Findings diff reviewed on every catalog change |
| Schema | Every rendered JSON validated against `findings-v1.schema.json` | Every CI run |
| Offline | Run the binary in a no-network namespace | Every CI run |
| Robustness | Fuzz the config parsers; hostile-fixture corpus (deep symlink chains, FIFOs, huge files, ANSI filenames, cyclic bind mounts) | Every CI run |
| Integration | Real containers per distro, assert no panics and non-empty coverage | Nightly |
| Performance | Timed scan of a standard fixture host, assert against budget | Every PR |

The golden-bundle corpus is what makes a catalog change reviewable. Once around 20 recorded bundles exist across distros, any catalog change shows its blast radius as a findings diff.

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
| Build and release | `goreleaser`, `syft`, `cosign` | Tooling, not linked in; see `SUPPLY-CHAIN.md` |

Everything else is the standard library. Config parsing is hand-rolled, tests
use `testing` and nothing else, and the terminal report (grid, colour, box
drawing, ANSI-aware padding) is this project's own code in
`internal/render/text`.

This table previously listed `charmbracelet/lipgloss`, `charmbracelet/bubbles`,
`gopkg.in/yaml.v3`, `google/go-cmp` and `testify`. None of them is in `go.mod`.
The list described an intention from the design phase that the implementation
never took up, except for lipgloss, which was added during the release
candidates and removed before GA because it cost thirteen transitive modules for
a box border. Corrected in the v1.0.0 documentation review (WP-38); the history
is in `CHANGELOG.md` under `v1.0.0-rc1`.

The dependency count is itself a control, and the SBOM published with every
release is what makes it checkable.

## 12. What is explicitly deferred

So that "we'll add it later" is a decision on record rather than an omission:

| Deferred | To | Why |
|---|---|---|
| Remediation script generation | **shipped in v2.0.0** | The check catalog had to stabilise first, or every fix gets rewritten. See §13.1 |
| Containers module | **shipped in v2.0.0** | Landed early; the fixture surface turned out tractable |
| Vulnerability correlation | v3 | Needs vendor security feeds; doing it with NVD alone is wrong (audit A-03) |
| Compliance mapping beyond public-domain frameworks | v3, as user-supplied packs | Licensing (audit A-02) |
| Cloud module | v3 | IMDS needs network access, which breaks the offline invariant and needs its own opt-in flag |
| Interactive TUI browser | v3 | High cost; JSON and terminal output cover the need |
| Extension mechanism | v4 | Not Go `plugin` under any circumstances (audit A-06) |
| macOS | v4 | Needs hardware and a fixture corpus; do not claim it before then |
| Fleet aggregation | v4 | Bundles make it straightforward later; premature now |

---

## 13. Three decisions that shape the tool

Most of what follows from the architecture above can be reconstructed from three
choices. They are collected here because they are the ones people ask about, and
because two of them look like missing features until you know why they are not.

### 13.1 The scanner and the mutator are separate programs, and Plumbline is only the first

Plumbline never edits the host it audits. There is no code path that applies a
plan, not behind a flag, not behind a confirmation prompt, and not in a
privileged helper. `scan --fix` renders a shell script to the report and
`--write-script` saves it to a file. Both stop there.

The reason is an asymmetry rather than a preference. A tool that repairs what it
finds is convenient roughly 95% of the time. The other 5% is a root process
acting on a heuristic verdict, on a machine its author cannot see, rewriting
`sshd_config` or a firewall rule, and locking an operator out of a host in
another country. Recovery needs console or physical access that many people do
not have. The upside is saved keystrokes; the downside is unrecoverable loss of
access to production. That trade does not balance at any confidence level a
scanner can reach from configuration files.

The boundary is structural, not a policy someone remembers to follow.
`internal/remediate` builds an `Action` whose commands are strings, and
`Script` renders a plan to text. Neither has a `System`, so neither can open a
file, run a process, or write anything. The one package that can touch the OS is
`internal/system`, and `make verify` fails the build if anything outside it
calls `os.Open`, `os.ReadFile`, `exec.Command` or their neighbours. A future
contributor who wanted to add `--apply` could not do it inside the remediation
package at all; they would have to cross the seam, and the seam is checked.

Two consequences are worth stating because they are load-bearing.

The generated script is an artifact. You can diff it, attach it to a change
request, hand it to someone with more context about the host, run it under
Ansible, or run three of its eight sections. An in-tool mutation is none of
those things; it is an opaque event with a log line after it.

The script is also the honest place for the warnings. Every command is preceded
by its check ID and by whatever caution the fix carries, in the file the
operator is about to run, rather than in documentation they may never open.

See [ADR-0006](adr/0006-no-auto-remediation.md), including its amendment.

### 13.2 Every generated script is idempotent, by construction

Running the script twice leaves the host in the same state as running it once.
This is a property of how each fix is written and it is tested by running the
generated script twice against a temporary tree and comparing the results, not
asserted in a comment.

The general rule is that a fix rewrites in place and appends only when the key
is absent. Getting this wrong is not a tidiness problem. It produces a file with
two settings for one parameter, and the operator who later edits the wrong one
changes nothing while believing otherwise.

`sysctl.d` goes through `plumbline_sysctl_set`, an `awk` pass that walks the
file, finds the first live assignment of the key, replaces its value, passes
every other line through untouched, and appends the setting only if it reached
the end without finding one. Comments survive. So does the `-` prefix that marks
a setting whose failure should be ignored, because the matcher strips it before
comparing keys rather than treating the line as unparseable.

`login.defs` needs the same mechanism for the opposite reason, and it is the
clearest example of why this matters. `shadow(3)` reads the file top to bottom
and takes the *first* definition of a key; every later one is dead. Appending
`ENCRYPT_METHOD SHA512` to a file that already says `ENCRYPT_METHOD MD5`
higher up therefore changes nothing at all, on exactly the hosts that need the
change, while the script runs cleanly and exits 0. The operator now believes a
host is fixed that is not. The generated editor rewrites the first definition
and comments out the later ones with a marker saying why.

systemd drop-ins are written whole rather than appended to, so a second run
produces identical bytes instead of a second copy of a directive for systemd to
resolve. `daemon.json` is parsed, modified and re-serialised through `python3`
rather than edited with `sed`, and the helper exits before writing when the key
already holds the wanted value, so a no-op run leaves the file's mtime and
formatting alone. Every helper that edits a file copies it to `.bak` once,
before its first change.

Idempotency is also what makes the script safe to run after a partial failure.
Under `set -eu` a script that dies halfway can be read, fixed and re-run from
the top without the completed half doing damage on the second pass.

### 13.3 SERVICES-0011 reports a problem it refuses to fix

`SERVICES-0011` fails a service that is not sandboxed at the strict tier, and
Plumbline will not write the directive that would satisfy it. This is the one
place where the catalog knows a fix and the generator declines to emit it, so it
is worth reading as a rule rather than as an exception.

`ProtectSystem=strict` mounts the entire filesystem hierarchy read-only apart
from `/dev`, `/proc` and `/sys`. That includes `/run` and `/var`, which is the
detail that catches people, since `ProtectSystem=full` (what `SERVICES-0007`
proposes) covers only `/usr`, `/boot`, `/efi` and `/etc` and leaves the rest
writable. A daemon that writes a path it never declared fails at the write and
not at the restart, so it starts cleanly and misbehaves later.

Plumbline used to generate this drop-in. The action carried six lines of warning
in bold, telling the operator to run `systemd-analyze filesystems` first and to
declare `ReadWritePaths=` for anything the service legitimately writes. An
operator ran the script, followed its own printed instruction to restart the
units it had written for, and `systemd-journald` (which writes `/var/log`) and
`dbus` (whose socket lives under `/run`) did not come back.

The warning was accurate and it failed anyway. It was attached to a file the
script had already written, and every other action Plumbline generates is safe
to run first and read afterwards, so the format itself teaches that comments are
context rather than preconditions. A caution that only works if it is read in a
different register from every other caution in the same document is not a
control.

That reframes the question. It is not how loudly a fix should warn, but whether
the fix can be written correctly from what a scan knows. Here it cannot. The
three sandbox fixes that still generate each need one decision an operator can
make from a unit's purpose: does it call a setuid helper (`SERVICES-0006`), does
it write `/etc` (`SERVICES-0007`), does it read a user's home (`SERVICES-0008`).
`strict` needs the complete set of paths a daemon writes at runtime. That is an
enumeration, not a decision, and the check does not collect it, cannot infer it,
and would be wrong about it on the next host or the next workload.

So the check reports and hands over the procedure: profile the unit,
`systemctl edit`, declare `ReadWritePaths=` or better `StateDirectory=` and
`LogsDirectory=`, then restart under real load rather than checking that the
unit comes up. Nothing was special-cased to make this work. A check with no
registered generator already had a defined path through every surface:
`remediationFor` in the SARIF renderer ranks the generated script above the
catalog's own commands and emits the latter with `"source": "advisory"`, the
`--fix` block counts the finding under "still failing with no automated fix",
and the warnings section never consulted the registry at all. Unregistering the
fix was one deletion and every surface reported the new state correctly.

The rule this produced, kept in `internal/remediate/systemd.go` where the
registration used to be: a proposal can itself be too dangerous to make, when
the operator's realistic behaviour on receiving it is to run it. Generating is
still not applying. It is not free either.

Re-introducing a generator here needs the missing fact, not better wording. A
collector that records what each unit actually writes would let a fix emit
`strict` together with the `ReadWritePaths=` that make it survivable, and that
fix would be worth having.
