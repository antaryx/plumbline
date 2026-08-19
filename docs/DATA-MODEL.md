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
| `uid`, `gid` | Numeric owner. Never a name — see below |
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

`uid` and `gid` are the CRON module's primary verdict input, and two properties
of them are load-bearing.

**They stay numbers.** Nothing outside `internal/system` may resolve a uid to
an account name: that is the seam rule, and it is also correct on the merits.
Resolving means reading `/etc/passwd` as it exists *during the scan*, which is
a different question from what it held when the file was created — and on a
bundle evaluated weeks later on another machine, it is a different host's
`/etc/passwd` entirely. A check that wants to say "owned by root" compares
against `0`. A check that wants to name the account joins against the
`users.passwd` fact, which is a recorded observation with its own provenance.
CRON's findings say `uid 1001`, not `uid 1001 (deploy)`, for exactly this
reason.

**Zero cannot mean "not recorded".** Unlike `dev` and `ino`, ownership has no
free sentinel: uid 0 is the single most important value the field takes and is
precisely what an ownership check tests for, so a missing record decoding as 0
would read as "owned by root" — turning a FAIL into a PASS. Facts that carry
ownership therefore carry an explicit state beside it (`fact.CronPath.State` is
`observed`, `absent`, `denied` or `error`), and `uid`, `gid` and `mode` mean
nothing unless the state is `observed`. A check reads the state first. See
`docs/adr/0016-fileinfo-ownership-seam.md`.

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

### 2.3 Registered facts

| Fact ID | Version | Produced by | Shape |
|---|---|---|---|
| `sshd.config` | 1 | `collect/collectors/sshd` | `Installed`, `Files`, `Directives[]`, `UnresolvedIncludes[]`, `Digests{}` |
| `fs.<interest>` | 1 | `collect/walker` (`fswalk`) | `Interest`, `Roots[]`, `Rows[]`, `Truncated`, `TruncationReasons[]`, `Overflow`, `InodesVisited` |
| `kernel.sysctl` | 1 | `collect/collectors/kernel` | `Running{}`, `Configured{}`, `Files[]`, `Digests{}`, `UnreadableFiles[]` |
| `users.passwd` | 1 | `collect/collectors/users` | `Entries[]`, `CompatEntries[]`, `Malformed[]`, `Path`, `Digest` |
| `users.shadow` | 1 | `collect/collectors/users` | `Entries[]`, `Malformed[]`, `Path` |
| `users.group` | 1 | `collect/collectors/users` | `Entries[]`, `CompatEntries[]`, `Malformed[]`, `Path`, `Digest` |
| `cron.files` | 1 | `collect/collectors/cron` | `Paths[]`, `Installed` |
| `logging.rsyslog` | 1 | `collect/collectors/logging` | `Installed`, `Files[]`, `Directives[]`, `Objects[]`, `Rules[]`, `UnresolvedIncludes[]`, `Digests{}` |
| `logging.journald` | 1 | `collect/collectors/logging` | `Installed`, `Files[]`, `Settings[]`, `PersistentDirState`, `Digests{}` |

Every fact added later is listed here with its version history.

#### `users.*` — the local account databases

Three facts rather than one, because the three files have three different
readabilities. `/etc/passwd` and `/etc/group` are world-readable; `/etc/shadow`
is not. An unprivileged scan produces two facts and one fact error, every check
over passwd returns a real verdict, and only the shadow-dependent checks
resolve to `UNKNOWN(insufficient_privileges)`. A single `users` fact would have
made one unreadable file erase two readable ones.

**`users.shadow` carries no password hash, and no digest.**

The hash is classified inside the collector — empty, locked, which crypt scheme
— and discarded. It reaches no fact, no bundle, no renderer and no log line. A
hash is not a record of what happened on a host; it is the credential itself in
a form an attacker can work on offline, and a bundle is an artifact designed to
travel.

The absent digest follows from the same decision. The bytes of `/etc/shadow`
are never stored as evidence — the exclusion is enforced at the seam, in
`collect.IsCredentialFile`, not in the collector — so a digest here would point
into an archive that deliberately does not contain what it points at. Findings
derived from shadow cite the path and the line and carry no digest, which is
the honest representation of "we read this and refused to keep it". See
`docs/adr/0015-account-data-in-bundles.md`.

`users.passwd` omits the GECOS field for a related reason: it holds a person's
real name and telephone number, no check asserts anything about it, and a field
nothing reads is a field that only creates exposure.

**`CompatEntries` and `Malformed` are what make negative assertions honest
here.** A line beginning `+` imports accounts from a directory service, so the
accounts it governs are not in the file; a line that would not parse could have
held the account a check claims is absent. Either one turns "no account has uid
0" from an observation into a guess, so the checks report `UNKNOWN` for the
negative result and leave the positive one standing — the same asymmetry
ADR-0014 records for the filesystem walk, arrived at independently because it
is a property of negative assertions rather than of filesystems.

`users.group` carries both fields for the same reason and they are not
decorative: `/etc/group` accepts the same `+` syntax as `/etc/passwd`, and a
check asserting that no gid is duplicated over a file that imports groups from
a directory service is describing a list that is explicitly not the whole list.

**`ShadowEntry.MinDays` and `MaxDays` are pointers, and the nil is
load-bearing.** An empty aging field is not a zero. An empty maximum means "no
maximum"; a maximum of 0 means "must be changed every day" — opposite ends of
the range. A parser that read the empty field as 0 would report the most
permissive setting in the file as the strictest, and USERS-0009 would return
PASS for exactly the accounts it exists to find. A field that is present but
not a number is also nil: it is not a valid aging value, and inventing one from
it would be a fabricated policy.

The four remaining shadow fields — last change, warn, inactive and expire — are
parsed and discarded. A fact field is permanent output surface (CLAUDE.md §7),
and adding one later as an optional field costs nothing, while carrying six on
the chance that something reads them is six fields that travel in every bundle.

#### `logging.*` — two daemons, two facts, and rsyslog's two languages

Separate facts because a host may run rsyslog, journald, both or neither, and a
single fact would let one absent daemon erase what is known about the other.
The same reasoning as the three account-database facts.

**`logging.rsyslog` carries three statement lists rather than one, because
rsyslog has three configuration languages and a stock host uses all of them in
the same file:**

| List | Language | Example |
|---|---|---|
| `Rules[]` | sysklogd legacy: selector, whitespace, action | `*.* @@logs.example.net:514` |
| `Directives[]` | rsyslog `$Name value` | `$FileCreateMode 0640` |
| `Objects[]` | RainerScript, rsyslog 6+ | `action(type="omfwd" target="…" protocol="tcp")` |

The syntax a statement was written in is preserved into the fact rather than
resolved away, because a finding has to quote the operator's file back in the
language it is actually written in. Telling somebody to change
`action(type="omfwd")` when their file says `*.* @@host` sends them looking for
a line that does not exist, and at that point they stop trusting the tool.

What checks read is the *normalised* view — `RemoteDestinations()` and
`FileCreateModes()` — which merges both syntaxes and carries the provenance
along. Normalising in the fact rather than in each check is deliberate: which
language produced a destination is a property of rsyslog, not a policy
question, and every check would otherwise repeat the same translation and get
it subtly different.

`FileCreateModes()` returns **every** occurrence rather than the last, because
the legacy directive is positional: it governs the file actions written after
it, so a permissive one applies to whatever follows regardless of a later line.

**`logging.journald` precedence is last-wins, the reverse of `sshd.config`.**
systemd reads `journald.conf` and then the drop-ins under `journald.conf.d/` in
lexical order, each overriding the last, so `Effective()` returns the final
match. A check that took the first would report the value the operator's
drop-in was written to replace. `Overridden()` exists so a finding can cite the
occurrences that were replaced and explain why the value in the main file is
not the value in force.

`PersistentDirState` records whether `/var/log/journal` exists. It is there
because `Storage=auto` is journald's default and its effect is a property of
the filesystem rather than of the configuration — without that one stat,
"Storage is not configured" would be UNKNOWN on the majority of hosts, which is
honest and useless.

#### `cron.files` — who may write the schedule

The fact records file *metadata* and no file contents at all. Every CRON check
asks who may write the schedule, not what the schedule says, and a crontab's
command lines are operator data — script paths, hostnames, database names and
occasionally credentials passed as arguments. Collecting them would put all of
that into a bundle designed to travel, for a set of checks that never read it.
That is ADR-0015's reasoning applied before the mistake rather than after it.

Each `CronPath` carries a `State` — `observed`, `absent`, `denied` or `error` —
and `Mode`, `UID` and `GID` are meaningful only when it is `observed`. The four
states are not decoration: "the file is not there" and "we were not allowed to
look" produce opposite verdicts, NOT_APPLICABLE or FAIL for the first and
UNKNOWN for the second, and a single boolean would have collapsed them into a
guess. See §2.1.1 and ADR-0016 for why ownership in particular cannot use a
zero sentinel.

`Installed` is derived rather than probed: there is no single file whose
presence means "cron is installed" across distributions, so it is true when any
of the eight standard paths was observed **or refused**. A refusal counts as
presence — we could not read it, but something is there — because treating it
as absence would turn an unprivileged scan into a report that the host has no
cron.

#### `kernel.sysctl` — running and configured kernel parameters

The fact carries two separate maps, and the separation is the point.
`Running` is what `/proc/sys` reports now. `Configured` is what
`/etc/sysctl.conf` and the `sysctl.d` directories will apply at the next boot.
A host with a hardened file and an unhardened kernel is a real and common
finding, and a fact that merged the two would hide it. KERNEL-0007 exists to
compare them.

`Running` holds one entry per parameter the collector **probed**, including
the ones it could not read, each with a `SysctlState`:

| State | Meaning | A check should return |
|---|---|---|
| `observed` | the value was read | a verdict on the value |
| `absent` | this kernel has no such parameter | `NOT_APPLICABLE` |
| `denied` | the parameter exists and we were refused | `UNKNOWN(insufficient_privileges)` |
| `error` | the read failed some other way | `UNKNOWN(ambiguous_system_state)` |

Keeping `absent` and `denied` apart is what stops an unprivileged scan from
reading as a clean bill of health. A key **missing from the map entirely**
means the collector never probed it, which is a wiring bug in this repository
and not an observation about the host; no check may read it as a value.

`Configured` retains **every** occurrence of a parameter across all files, in
application order, not just the winning one — a finding that reports drift has
to be able to name the file the operator should edit.
`Sysctl.ConfiguredConflict` reports when two files set one parameter to
different values, which is the case where the application order of the drop-in
directories differs between `systemd-sysctl` and procps `sysctl --system`. A
check meeting a conflict returns `UNKNOWN` rather than picking a winner; see
`docs/checks/KERNEL-0007.md` §4.

`UnreadableFiles` carries the reason a configuration file could not be read, so
a check can map the gap to the right `UNKNOWN` code rather than guessing at
one.

**The probed set is explicit, not discovered.** Walking `/proc/sys` would
collect several thousand parameters, put every one of them in the bundle on
disk — including the ones naming this host's interfaces and routes — and make
the fact's shape depend on the kernel rather than on the catalog. The collector
reads the parameters the checks need and no more.

The exception is the parameters the kernel namespaces per network interface
(`net.ipv4.conf.<interface>.rp_filter`,
`net.ipv4.conf.<interface>.accept_source_route`). Those are enumerated from
`/proc/sys/net/ipv4/conf`, because the set of interfaces is a property of the
host, and the keys are derived from the paths rather than composed from
interface names — a VLAN device is called `eth0.1` and the dotted form does not
round-trip.

For those parameters the value under `conf/all` is **not** the effective value
on its own. It combines with each interface's own setting by a rule that
differs per parameter: `max()` for `rp_filter`, logical `AND` for
`accept_source_route`. The fact records the raw per-interface values and leaves
the combining to the check that knows which rule applies, because a fact that
pre-combined them would have to pick one rule and would be wrong for the other.

#### `fs.<interest>` — the shared filesystem walk

One fact per registered walker interest: `fs.suid`, `fs.world_writable`,
`fs.unowned`, and so on. All are the same Go type, `fact.FSMatches`, whose
`FactID` is derived from `Interest`. A module gets a new fact by registering a
new interest, not by writing a new fact type.

It is one fact per interest rather than one fact holding every match for a
specific reason: a check requiring `fs.suid` must not resolve to `UNKNOWN`
because an unrelated interest overflowed its cap. Facts are the unit of
ignorance in this design, so they have to be the unit of truncation too.

**The rule that governs every check reading one of these facts is asymmetric:**

> A truncated walk can invalidate a *negative* result. It can never invalidate
> a *positive* one.

`Rows` is always trustworthy. A SUID binary the walk found is a SUID binary
that exists, so a check reporting it returns `FAIL` whether or not the walk
finished. "There are no SUID binaries outside the allowlist" is a claim about
everything that was *never examined*, so over a partial walk it is not `PASS`
but `UNKNOWN(source_truncated)`.

`FSMatches.Complete()` mechanises it. **A check asserting absence must gate on
`Complete()` before it may return `PASS`.** Returning `PASS` from a partial walk
converts "we stopped looking" into "there is nothing there", which is the single
failure mode this project exists to prevent.

`TruncationReasons` distinguishes why, because the remedies differ:

| Reason | Meaning | Scope |
|---|---|---|
| `depth_limit` | the walk refused to descend further | whole walk |
| `inode_limit` | the global inode budget was spent | whole walk |
| `wall_clock` | the walk or its context ran out of time | whole walk |
| `dir_listing` | a directory listing came back incomplete | whole walk |
| `unreadable_dir` | a directory could not be opened at all | whole walk |
| `mounts_unknown` | the mount table was unreadable while crossing was requested | whole walk |
| `max_hits` | **this interest** reached its own cap; `Overflow` counts what it dropped | one fact |

Two things that are deliberately **not** truncation: a filesystem boundary the
walk declined to cross, and a filesystem type on the skip list. Those are
*scope* — the walk states its `Roots` and never claimed to cover anything else
— and marking them would make every ordinary host report `UNKNOWN` for every
filesystem check. Breaking a cycle is not truncation either: everything inside
a directory reached twice was enumerated under its other path. See ADR-0014.

`InodesVisited` is shared by every fact one walk produced, which is what proves
the tree was traversed once rather than once per interest.

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
