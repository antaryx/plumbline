# DATA MODEL — Plumbline

**Status:** normative for v1.x
**Authoritative alongside:** `schema/findings-v1.schema.json`, `schema/bundle-v1.schema.json`
**Implementations:** `internal/fact`, `internal/finding`, `internal/catalog`

If Go code and this document disagree, this document wins until it is changed
deliberately. If this document and the JSON Schema disagree, the schema wins —
it is the machine-checked one.

---

## 1. The four objects

```
System state ──collector──► FACT ──┐
                                   ├──check──► FINDING ──renderer──► output
Collection metadata ───────────────┘
                     ▼
                  BUNDLE  (facts + evidence + errors + metadata, on disk)
```

| Object | Lifetime | Stability contract |
|---|---|---|
| **Fact** | One collection | Per-fact version integer; bundles carry it |
| **FactError** | One collection | Stable kinds; new kinds are additive |
| **Finding** | Derived, recomputable | Schema major version; the public API |
| **Bundle** | Archival, indefinite | Read support is forever, write is current-only |

---

## 2. Fact

A fact is one typed observation. Facts are the entire vocabulary available to
a check: **if it is not in the FactSet, no check may assert it.**

```go
type Fact interface {
    FactID() ID       // "sshd.config" — stable forever
    FactVersion() int // bumped on incompatible shape change
}
```

### 2.1 Rules

- **Facts are data, not judgement.** `SSHDConfig` records what the files say.
  Whether that is acceptable is a check's business. A collector that decides
  something is "insecure" has taken a decision the user cannot see or override.
- **Facts are serialisable.** Everything must survive a round trip through
  JSON in a bundle. No `fs.FileInfo`, no channels, no funcs, no pointers into
  process memory.
- **Facts carry provenance.** Which file, which line, which command. A finding
  cannot cite evidence the fact did not record.
- **Facts record what was not seen.** `SSHDConfig.UnresolvedIncludes` exists
  because "this keyword is absent" and "this keyword may be in a file I could
  not read" are different observations, and conflating them produces false
  assurance.

### 2.1.1 `system.FileInfo`, the shared file descriptor

Facts that describe files embed `system.FileInfo`. It is a flattened, JSON-safe
stat result — deliberately not an `fs.FileInfo`, because everything a fact
carries must survive a round trip through a bundle.

| Field | Meaning |
|---|---|
| `path` | Absolute, as the scan saw it — beneath `--root`, not the real path |
| `mode` | Permission bits and type bits |
| `uid`, `gid` | Numeric owner; names are resolved by checks, not collectors |
| `size`, `mod_time` | As reported by the kernel |
| `is_dir`, `is_regular`, `is_symlink` | The type questions checks actually ask |
| `link_target` | Where a symlink points; the link is never followed |
| `dev`, `ino` | The inode's identity |

`dev` and `ino` exist so that the shared filesystem walker can detect
bind-mount and hardlink cycles: a tree that contains itself is infinite, and a
depth limit terminates such a walk without being able to tell it apart from a
legitimately deep one. They are integers rather than a `syscall.Stat_t` so that
no syscall type reaches a fact or a check; extraction happens inside
`internal/system`, which is the only package permitted to know that `syscall`
exists. Zero means not recorded — inode 0 is not a valid inode and device 0 is
not a real device for a file. See `docs/adr/0012-fileinfo-inode-seam.md`.

### 2.1.2 Reading a directory is bounded

`System.ReadDir(path, maxEntries)` returns a `DirResult`, not a slice, and the
difference matters:

```go
type DirResult struct {
    Path      string
    Entries   []FileInfo
    Truncated bool
}
```

`Truncated` means the listing is not the complete contents of the directory —
either the entry cap was reached, or an entry could not be stat'ed and was
omitted. Both have one consequence, which is why they share one flag:

> **Nothing may conclude that a file is absent from a truncated listing.**

A directory with ten million entries is a denial of service against a scanner
that materialises all of them, so the cap is not optional. But a bounded
listing that did not admit being bounded would be worse than no cap at all: a
check would report "no world-writable file here" about a directory it saw a
tenth of. That is the same false assurance as reporting `PASS` for something
never examined, arriving by a different route.

### 2.2 Fact versioning

`FactVersion` is bumped when the shape changes such that an old check reading a
new fact — or a new check reading an old bundle — could be wrong.

| Change | Bump? |
|---|---|
| Add an optional field | No |
| Add a field checks must consider (like `UnresolvedIncludes`) | **Yes** |
| Change a field's meaning or type | **Yes** |
| Rename or remove a field | **Yes** |
| Fix a parser bug so the same input yields different values | **Yes** |

A check declares which fact IDs it requires. When a bundle carries a fact
version the check does not understand, the runner returns
`UNKNOWN(fact_version_mismatch)`. It never attempts a best-effort read: a
best-effort read of a misunderstood structure is exactly how a false `PASS`
gets produced.

### 2.3 Registered facts (v0.1)

| Fact ID | Version | Produced by | Shape |
|---|---|---|---|
| `sshd.config` | 1 | `collect/collectors/sshd` | `Installed`, `Files`, `Directives[]`, `UnresolvedIncludes[]`, `Digests{}` |

Every fact added later is listed here with its version history.

`Digests` maps each entry of `Files` to the sha256 of the bytes read from it.
It was added after `sshd.config` v1 shipped and did **not** bump the version:
per §2.2 it is an optional field that no check is required to consider, and a
check reading a bundle written before it existed emits evidence without a
digest, which is what it did then and what the findings schema permits. See
`docs/adr/0009-evidence-digest-tracking.md`.

---

## 3. FactError

Records why a fact is absent. This type is why Plumbline can distinguish "not a
problem" from "could not tell", which the audited design could not.

```go
type Error struct {
    Fact ID
    Kind ErrorKind
    Msg  string
    Path string
}
```

| Kind | Meaning | Maps to UNKNOWN reason |
|---|---|---|
| `not_collected` | Collector did not run (profile, filter) | `fact_not_collected` |
| `permission` | Insufficient privileges | `insufficient_privileges` |
| `timeout` | Collector exceeded its budget | `ambiguous_system_state` |
| `parse` | Source found but unintelligible | `unparseable_source` |
| `truncated` | Source exceeded the read cap | `source_truncated` |
| `unsupported` | Not meaningful on this platform | `ambiguous_system_state` |
| `internal` | Collector bug — always a CI failure | `internal_error` |

Fact errors are stored in the bundle. A report six months later can still
explain the gap, which is the difference between evidence and a screenshot.

---

## 4. FactSet

The complete result of one collection: facts that succeeded, errors for those
that did not.

`fact.Get[T]` returns three values precisely because a check must handle three
situations differently:

```go
f, nil, true   // present   → evaluate
_, err, false  // failed    → UNKNOWN with err.Kind
_, nil, false  // never run → UNKNOWN(fact_not_collected)
```

Collapsing the last two into "missing" is how scanners end up reporting `PASS`
for things they never looked at. In practice the runner's required-fact gate
handles both before `Eval` is entered, so a check that declares its
dependencies honestly never sees either.

---

## 5. Finding

**This is the public API.** Serialises directly into
`schema/findings-v1.schema.json`. Changing a field is a schema change governed
by `VERSIONING.md` §4, not a refactor.

### 5.1 Result — a closed set

```
PASS · FAIL · NOT_APPLICABLE · SKIPPED · UNKNOWN
```

Adding a sixth is a **breaking schema change**. Consumers were told this set is
closed and may switch exhaustively on it.

| State | Scores? | Affects coverage? |
|---|---|---|
| `PASS` | numerator + denominator | no |
| `FAIL` | denominator | no |
| `NOT_APPLICABLE` | no | no — excluded from the population entirely |
| `SKIPPED` | no | **reduces coverage** |
| `UNKNOWN` | no | **reduces coverage** |

This table is the whole scoring fix from the audit. `SKIPPED` and `UNKNOWN`
leaving the denominator is why an unprivileged run reports
`posture 82 (coverage 44%)` instead of a punitive and meaningless `40`.

### 5.2 Severity

`CRITICAL(4) · HIGH(3) · MEDIUM(2) · LOW(1) · INFO(0)`

Every finding carries **both** `severity` (effective) and `base_severity`
(catalog default). A check may return a different severity per observed value —
`PermitRootLogin yes` is HIGH, `prohibit-password` is MEDIUM — and context
adjustment may move it by one level. Both values are always present so no
adjustment is ever hidden from the reader.

Weights change only in a MAJOR release.

### 5.3 Evidence

```go
type Evidence struct {
    Source  string // "/etc/ssh/sshd_config" or "exec: sshd -T"
    Line    int    // 1-based; 0 when not line-oriented
    Excerpt string // sanitised, length-capped
    SHA256  string // over the full source
}
```

- **Every `FAIL` and every `UNKNOWN` must carry evidence.** A finding without
  evidence is a rumour, and an auditor cannot use it.
- Excerpts are sanitised for terminal control sequences before they reach any
  renderer. Filenames containing ANSI escapes are a real attack on the operator's
  terminal.
- Excerpts are capped. Never embed a whole file; the bundle already has it,
  addressed by hash.

### 5.4 Fingerprint

```go
Fingerprint(checkID, subject) = hex(sha256(checkID ‖ "\0" ‖ trim(subject)))[:32]
```

Deliberately excludes result, severity and detail: **a finding that flips from
FAIL to PASS is the same finding.** A suppression written last quarter must
still match; GitHub's SARIF deduplication depends on it.

`subject` is the specific thing the finding is about — a path, an account, a
port — and is empty for host-wide checks. A check that can produce multiple
findings must set distinct subjects, or they will collapse into one.

Changing the derivation is a **breaking schema change**: it silently
invalidates every user's suppression baseline.

### 5.5 Invariants

Asserted in every check's test suite:

| Invariant | Rationale |
|---|---|
| `UNKNOWN` ⇒ `unknown_reason` is set | An unexplained UNKNOWN is unactionable |
| `FAIL` ⇒ `remediation` is present | Every failure ships a fix (`PROJECT-BRIEF.md` §5) |
| result ≠ `FAIL` ⇒ `remediation` is absent | Remediation on a PASS confuses readers and renderers |
| `FAIL` or `UNKNOWN` ⇒ `evidence` is non-empty | See §5.3 |
| `base_severity` is never mutated by `Eval` | Adjustment must stay visible |
| `fingerprint` is non-empty | Suppressions depend on it |

---

## 6. Bundle

The durable artifact and the reason the architecture exists. Format:
zstd-compressed tar, extension `.plb`.

```
manifest.json     schema versions, tool version, catalog version, capabilities
meta.json         hostname*, os-release, kernel, arch, scan root, timestamps
facts/<id>.json   one file per fact, each carrying its fact_version
evidence/<sha>.blob   content-addressed raw sources, deduplicated
errors.json       every FactError
integrity.json    sha256 of every member; detached signature sits alongside
```

`*` subject to `--redact`.

### 6.1 Guarantees

| Guarantee | Detail |
|---|---|
| **Read support is forever** | Any released binary reads any historical bundle. A bundle that cannot be re-evaluated breaks the core product promise. |
| **Write support is current-only** | A binary writes the current bundle schema. |
| **Findings are deterministic** | Same bundle + same catalog version ⇒ byte-identical findings JSON. Asserted in CI. |
| **Bundles are not byte-reproducible** | Two collections of the same host differ: timestamps and process lists move. Determinism is claimed for *findings*, not for bundles. Stating this precisely matters; the audited design claimed determinism it could not deliver. |
| **Evidence is deduplicated** | Ten checks citing `/etc/login.defs` store it once. |
| **Bundles are sensitive** | User lists, open ports, package inventory. Written `0600`. Redaction happens at collection time so a redacted bundle is safe to send. |

---

## 7. Worked example

Fixture `testdata/fixtures/sshd-include`:

```
/etc/ssh/sshd_config
    Include /etc/ssh/sshd_config.d/*.conf
    Port 22
    PermitRootLogin yes
/etc/ssh/sshd_config.d/50-cloud-init.conf
    PermitRootLogin no
```

**Fact** (`sshd.config`, version 1):

```json
{
  "installed": true,
  "files": ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/50-cloud-init.conf"],
  "directives": [
    {"keyword":"PermitRootLogin","value":"no","file":"/etc/ssh/sshd_config.d/50-cloud-init.conf","line":1,"in_match":false},
    {"keyword":"Port","value":"22","file":"/etc/ssh/sshd_config","line":2,"in_match":false},
    {"keyword":"PermitRootLogin","value":"yes","file":"/etc/ssh/sshd_config","line":3,"in_match":false}
  ]
}
```

The include expands *in place*, so the drop-in's directive is obtained first
and wins — sshd's documented first-value-wins precedence. A tool that reads
only `sshd_config` reports the opposite verdict.

**Finding:**

```json
{
  "check_id": "SSHD-0002",
  "module": "SSHD",
  "title": "Root login over SSH is disabled",
  "result": "PASS",
  "severity": "HIGH",
  "base_severity": "HIGH",
  "detail": "PermitRootLogin is set to no; direct root login over SSH is refused.",
  "evidence": [
    {"source":"/etc/ssh/sshd_config.d/50-cloud-init.conf","line":1,"excerpt":"PermitRootLogin no"}
  ],
  "mappings": [{"framework":"nist-800-53-r5","control":"AC-6(2)"}],
  "fingerprint": "b0f1…"
}
```

Note there is no `remediation` — the invariant in §5.5 forbids it on a `PASS`.
