# BUILD RUNBOOK — v0.1.0 walking skeleton

Work packages sized to roughly one Claude Code session each. Execute in order;
each one leaves the tree green.

**How to use this:** open a session, paste the work package verbatim as the
brief, let it run, then audit against the acceptance criteria before merging.
Do not batch two packages into one session — the review surface gets too large
to audit properly, which defeats the point of working this way.

**Already complete** (shipped with this runbook):

| Done | What |
|---|---|
| WP-00 | `System` interface, `live` and `fake` implementations |
| WP-01 | `fact` package: Fact, FactSet, FactError, typed `Get` |
| WP-02 | `finding` package: Result, Severity, Evidence, Fingerprint |
| WP-03 | `catalog` package: Check, registry, evaluation runner |
| WP-04 | sshd collector with Include resolution and Match tracking |
| WP-05 | SSHD-0002 reference check, 9 fixtures, table tests |
| — | `Makefile` with `verify` and architectural invariant gates |
| — | `schema/findings-v1.schema.json`, validated with positive and negative cases |

`make verify` passes. Start at WP-06.

---

## WP-06 — Fixture coverage gate

**Goal:** make the "every check needs PASS and FAIL fixtures" rule mechanical
before there are enough checks for compliance to be expensive.

**Build:** `tools/fixturegate/main.go`. It walks `internal/catalog/checks/`,
extracts every check ID, then walks the corresponding `_test.go` table cases
and asserts each ID has at least one case expecting `PASS` and one expecting
`FAIL`. Exits non-zero with a list of offenders.

Parse the test tables with `go/ast` rather than regex — regex over Go source is
a maintenance trap, and the AST route is about thirty lines.

**Acceptance:**
- [ ] `make check-fixture-coverage` passes with SSHD-0002 present
- [ ] Deleting the `sshd-hardened` case from the test table makes it fail with a
      clear message naming the check and the missing state
- [ ] `make verify` green

**Do not:** add a config file, flags, or exemptions. If a check cannot have both
fixtures it should not be in the catalog.

---

## WP-07 — Bundle write and read

**Goal:** facts become a portable artifact. This is the feature the whole
architecture exists for.

**Build:** `internal/bundle`.
- `Write(w io.Writer, b Bundle) error` — zstd-compressed tar per
  `DATA-MODEL.md` §6: `manifest.json`, `meta.json`, `facts/<id>.json`,
  `errors.json`, `integrity.json`
- `Read(r io.Reader) (Bundle, error)`
- Fact serialisation is by registered `fact.ID` → decoder; a fact ID the binary
  does not know is preserved as raw JSON so an old binary reading a new bundle
  degrades to `UNKNOWN` rather than failing to open it
- `integrity.json` carries a sha256 per member; `Read` verifies and returns a
  typed error on mismatch

**Dependency:** zstd. `github.com/klauspost/compress` — pure Go, no CGO. This is
the first external dependency; add nothing else.

**Acceptance:**
- [ ] Round trip: write a `FactSet` with `sshd.config` plus one `FactError`,
      read it back, assert deep equality
- [ ] Tampering with a member byte makes `Read` fail with an integrity error
- [ ] A bundle containing an unregistered fact ID opens successfully and the
      unknown fact is preserved
- [ ] `make verify` green

**Do not:** implement evidence blobs yet (WP-09), signing (v1.0), or redaction
(WP-12).

---

## WP-08 — Collector registry and the collection runner

**Goal:** more than one collector, ordered and budgeted.

**Build:** `internal/collect`.
- `Collector` interface: `ID()`, `DependsOn()`, `Requires() Capability`,
  `Cost() Cost`, `Collect(ctx, System, *fact.Set) error`
- Registry with topological sort; a cycle panics at init, which surfaces in
  tests, never in production
- Runner: independent branches concurrent, `Expensive` collectors serialised to
  concurrency 1 — this is the fix for the audited design's twelve-simultaneous-
  `find` problem, so it must be enforced by the runner, not by convention
- Per-collector timeout → `fact.Error{Kind: ErrTimeout}`
- Panic isolation → `fact.Error{Kind: ErrInternal}`
- A collector whose `Requires()` exceeds the current euid is skipped with
  `fact.Error{Kind: ErrPermission}`, never silently omitted

Port the sshd collector to the interface.

**Acceptance:**
- [ ] A collector that sleeps past its budget yields `ErrTimeout` and the run
      completes
- [ ] A collector that panics yields `ErrInternal` and the run completes
- [ ] Dependency order is respected; a test with a synthetic 4-node DAG proves it
- [ ] Two `Expensive` collectors never overlap; assert with timestamps
- [ ] Running as euid 1000 against `sshd-unreadable` yields `ErrPermission`, not
      a crash and not a missing fact
- [ ] `make verify` green

---

## WP-09 — Evidence blobs

**Goal:** findings cite content-addressed sources rather than inline excerpts
alone.

**Build:** an evidence store in the bundle: `evidence/<sha256>.blob`,
deduplicated. `system.ReadResult` already carries the hash; wire collectors to
register the bytes, and have `finding.Evidence.SHA256` reference them.

Add excerpt sanitisation here: strip terminal control sequences, cap length,
mark truncation. This is a security control (`THREAT-MODEL.md`), not
formatting — filenames containing ANSI escapes are an attack on the operator's
terminal.

**Acceptance:**
- [ ] Two checks citing one file produce one blob
- [ ] A filename containing `\x1b[2J\x1b[H` renders inert in the terminal output
- [ ] A 10 MB source produces a capped excerpt and a truthful truncation marker
- [ ] `make verify` green

---

## WP-10 — Scoring

**Goal:** posture and coverage, computed the way `ARCHITECTURE.md` §5
specifies rather than the way the audited design did.

**Build:** `internal/score`.

```
Evaluated = PASS + FAIL
Coverage  = Evaluated / (Total − NOT_APPLICABLE) × 100
Posture   = Σ(weight of PASS) / Σ(weight of Evaluated) × 100
```

Carry `catalog.Version` on the result. Provide `Comparable(a, b Score) bool`
returning false across catalog versions.

**Acceptance:**
- [ ] All-`SKIPPED` input yields coverage 0 and posture is reported as
      undefined, not 0 — these are different statements and conflating them is
      the audited scoring bug
- [ ] `NOT_APPLICABLE` affects neither figure
- [ ] An unprivileged run over the fixture corpus yields high posture at low
      coverage, not a punitive low posture
- [ ] Weights match `finding.Severity.Weight()`; a table test pins the arithmetic
- [ ] `make verify` green

**Do not:** implement a second score. There is no Risk Score; the audit removed
it and the reasons are in `audit/argus-design-audit.md` A-13.

---

## WP-11 — JSON renderer

**Goal:** emit `findings/v1`, schema-validated in CI.

**Build:** `internal/render/json`. Deterministic key order, findings sorted by
check ID, `schema` as the first key.

Add a CI step validating rendered output against
`schema/findings-v1.schema.json` on every run. The schema's `allOf` rules
already enforce the finding invariants (UNKNOWN needs a reason, FAIL needs
remediation and evidence, non-FAIL must not carry remediation) — wire them up
so a violation fails the build rather than reaching a user.

**Acceptance:**
- [ ] Output validates against the schema for every fixture
- [ ] Rendering one bundle twice is byte-identical
- [ ] Renderer refuses to emit posture without coverage; a test asserts the
      invariant holds structurally, not by convention
- [ ] `make verify` green

---

## WP-12 — CLI: `collect`, `eval`, `scan`

**Goal:** the walking skeleton walks.

**Build:** `cmd/plumbline` with cobra.
- `collect --root R -o bundle.plb`
- `eval bundle.plb --format json`
- `scan` = collect + eval, in memory
- `version [--json]` printing tool, catalog and schema versions
- `--redact` at collection time, dropping hostname and non-loopback addresses

Exit codes per `ARCHITECTURE.md` §9, with the precedence ladder implemented
as a single function and tested per branch.

Config from the current working directory is ignored when euid is 0 unless
passed explicitly with `--config` (`THREAT-MODEL.md`; audit A-30).

**Acceptance:**
- [ ] `collect` on the live host then `eval` on the resulting bundle produces
      findings identical to `scan`
- [ ] `collect --root testdata/fixtures/sshd-include` works against a fixture
      tree, proving `--root` before any container work depends on it
- [ ] Exit code precedence: a run that is both degraded and failing returns 4,
      and a test covers every branch of the ladder
- [ ] `--redact` output contains no hostname
- [ ] Bundle written `0600`; asserted by a test
- [ ] `make verify` green

---

## WP-13 — Offline and hostile-input proof

**Goal:** turn two of the project's central claims into tests, so they cannot
quietly stop being true.

**Build:**
1. An integration test running the built binary in a network namespace with no
   network, asserting a full scan succeeds.
2. A hostile fixture corpus and the tests that survive it: a FIFO where a config
   is expected, a symlink chain 40 deep, a symlink to `/etc/shadow`, a 100 MB
   file, filenames containing newlines and ANSI escapes, a cyclic include, a
   directory where a file is expected, a zero-byte config, CRLF line endings.

**Acceptance:**
- [ ] Offline test green
- [ ] Every hostile fixture completes: no hang, no panic, no unbounded read
- [ ] The FIFO case returns `ErrNotRegular` within milliseconds, proving the
      guard in `live.ReadFile` actually fires rather than being decorative
- [ ] The symlink-to-shadow case does not read `/etc/shadow`
- [ ] `make verify` green

---

## WP-14 — CI

**Goal:** the gates run without you.

**Build:** `.github/workflows/ci.yml`.

Jobs: build (amd64, arm64) · `make verify` · `go test -race` · schema
validation · determinism · offline · hostile corpus · integration containers
(ubuntu:24.04, debian:13, fedora:latest, alpine:3.20).

Branch protection: all required, linear history, signed commits.

**Acceptance:**
- [ ] Green on `main`
- [ ] A PR that adds a check without fixtures is blocked
- [ ] A PR that calls `os.ReadFile` outside `internal/system` is blocked
- [ ] `make verify` green locally and in CI

---

## v0.1.0 exit criteria

Tag only when all hold:

- [ ] `collect` on host A → `eval` on host B → identical findings
- [ ] Two evaluations of one bundle are byte-identical
- [ ] Full scan makes zero network syscalls, proven by test
- [ ] Hostile corpus produces no hang, panic or unbounded read
- [ ] Every check has PASS and FAIL fixtures, enforced by CI
- [ ] JSON output validates against `findings-v1.schema.json`
- [ ] Bundles and reports are `0600`
- [ ] `CLAUDE.md`, `DATA-MODEL.md`, `FIXTURES.md`, `CHECK-AUTHORING.md` accurate
      against the implementation, not against intent

Tag `v0.1.0`, marked pre-release, banner stating no stability guarantees.

---

## Then: v0.2 catalog expansion

With the skeleton proven, v0.2 is repetition of a known-good pattern. One work
package per module, each following WP-04/WP-05: collector, facts, checks,
fixtures, tests.

Order — cheapest facts first, so the pattern is well-worn before the hard
parsing arrives:

1. `KERNEL` (~15) — sysctl only, trivially fixturable
2. `USERS` (~10) — passwd, shadow, group
3. `SSHD` remainder (~19) — the collector already exists
4. `CRON` (~8) — file-based
5. `LOGGING` (~8)
6. `SERVICES` (~10) — systemd, OpenRC, sysvinit divergence
7. `NETWORK` (~12) — listeners, firewall presence
8. `FILESYS` (~14) — needs the shared walker, its own work package first
9. `AUTH` (~17) — PAM parsing; hardest, do it last with the pattern established

The walker is a work package in its own right, sized like WP-08, and blocks
`FILESYS`. Build it once, with the interest-predicate design from
`ARCHITECTURE.md` §3.2, and never let a check walk the filesystem itself.
