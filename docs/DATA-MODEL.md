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
| `services.units` | 1 | `collect/collectors/services` | `Dirs[]`, `Units[]`, `Links[]`, `Systemd` |
| `network.firewall` | 1 | `collect/collectors/network` | `Sources[]` |
| `auth.pam` | 1 | `collect/collectors/auth` | `Installed`, `DirState`, `Services[]`, `PwQuality`, `Faillock`, `Digests{}` |
| `fs.mounts` | 1 | `collect/walker` (`fswalk`) | `Entries[]`, `Known` |
| `fs.tally.<tally>` | 1 | `collect/walker` (`fswalk`) | `Tally`, `Roots[]`, `Buckets[]`, `Truncated`, `TruncationReasons[]`, `KeysDropped`, `InodesTallied`, `InodesVisited` |
| `users.nsswitch` | 1 | `collect/collectors/users` | `Databases[]`, `State`, `Path`, `Malformed[]`, `Digest` |
| `memory.elf` | 1 | `collect/collectors/memory` | `Binaries[]`, `Truncated` |

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
parsed and discarded. A fact field is permanent output surface (CONTRIBUTING.md, "Working style"),
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

#### `fs.mounts` — the kernel's mount table

Produced by the shared walker rather than by a collector of its own, because
**the walk already reads `/proc/self/mountinfo`** to apply its filesystem-type
skip list. Two reads of the same kernel table could disagree and the
disagreement would be invisible; one read, shared, cannot. It is the
one-traversal rule applied to a file rather than to a tree.

It is published **unconditionally** — including when no module registered a
walker interest and no traversal happened at all. The mount table is not a
product of the walk, and making it conditional on some unrelated module's
wiring would have left the FILESYS mount checks resolving to UNKNOWN for a
reason that has nothing to do with the host.

`Options` and `SuperOpts` are separate because `mountinfo` reports them
separately and they are not the same thing. The per-mount options — `nodev`,
`nosuid`, `noexec`, `ro` — are properties of *this* mount and are what a bind
mount can differ in. The superblock options belong to the filesystem and are
shared by every mount of it. A check asking "is /tmp nosuid" is asking about the
first; reading the second would answer a different question and be right often
enough to look correct.

`Known` is the most important field. **An unknown table must never read as an
empty one:** "/tmp is not a separate mount" is a finding and "we could not find
out what /tmp is" is UNKNOWN, and they lead to opposite actions. A truncated
read sets `Known` false rather than returning the entries it managed to parse,
because a partial mount table is one with entries missing from the end — and
the missing one may be exactly the entry being asked about.

#### `auth.pam` — how this host decides somebody is who they claim

PAM is the only place on a Linux host where the authentication rules are
actually written down, and it is a **graph** rather than a file. Three include
directives with different scopes build it: `@include <file>` inlines a whole
file, every management group at once, and exists only in `pam.d`; `<type>
include <file>` pulls in that one type's lines; `<type> substack <file>` does
the same and scopes any die/done jump. Confusing the first two either drops
three quarters of a Debian host's rules or imports password rules into the auth
stack.

`Services[]` therefore carries each stack **fully resolved, in evaluation
order**, with every rule keeping the `File` and `Line` it was actually written
at — which is not the service file whenever an include brought it in. A finding
has to send an operator to the file they must edit.

`Unresolved[]` is the half that makes the fact honest. An include that could
not be followed leaves the stack incomplete, and while it is non-empty **nothing
may be concluded from a module's absence**. Every AUTH check that draws a
conclusion from not finding a rule resolves to UNKNOWN instead. That is
ADR-0014's asymmetry applied to a graph: an include we did not read may hold
the rule that decides the verdict, but it cannot unmake one we already read.

`ResolvedPath` records where the content came from when the service file is a
symlink. Red Hat's `/etc/pam.d/system-auth` points at `system-auth-ac`, or into
`/etc/authselect`, on every stock install — so this is the common case rather
than an oddity, and the collector resolves it through `Readlink` because the
seam's `ReadFile` refuses a symlink with `O_NOFOLLOW` (ADR-0017). Citing the
link rather than the target would send an operator to edit a file that
authselect overwrites.

**Control is kept as raw text and not parsed into a decision table.** Simulating
PAM means implementing the bracketed `[success=1 default=ignore]` jump
semantics, and a stack simulator that is subtly wrong produces confident
verdicts about which module runs. `PAMLine.Enforcing()` answers the one
question the checks need — can this rule's failure deny the operation — and
reports anything bracketed that it does not recognise as *not* enforcing, which
is the direction that produces a finding a human reads rather than a PASS drawn
from an expression nothing understood.

`PwQuality` and `Faillock` are the `/etc/security` files that hold the other
half of those modules' configuration. Both modules read their file first and let
arguments on the PAM line override it, so neither source alone is the effective
configuration — a check consulting one would be right on whichever kind of host
it was written against and wrong on the other, silently.

The fact carries no password hash, no user name and no authentication token:
these files hold policy, not credentials.

#### `network.firewall` — what filtering is configured, not what is loaded

The fact records **derived properties only**. A firewall ruleset is a map of
the network — internal ranges, which hosts reach which ports, where the
management network is — and a bundle designed to travel would carry it wherever
the bundle is filed. What is kept is the kind, the state, a statement count, the
manager's on/off switch, and the single policy line a finding has to quote.
Same reasoning as ADR-0015 and `cron.files`.

`Statements` is what distinguishes a configured firewall from an installed
package: Debian's `nftables` package writes `/etc/nftables.conf` whether or not
anybody has put a rule in it, so `FirewallSource.Active()` requires more than
zero — and, for a manager, requires that it is not switched off.

`FirewallKind.Manager()` draws the distinction the conflict check rests on. ufw
and firewalld **own** the ruleset and flush the table on start; an
iptables-save file or `nftables.conf` **is** a ruleset, loaded verbatim by its
own unit. A manager beside a saved ruleset is not redundancy — the manager
discards what the ruleset installed, and the file keeps being maintained and
stops meaning anything.

The whole module reports what is **configured**. Whether the unit that loads it
is enabled is `services.units`' half, and neither fact claims the other's.

#### `services.units` — what systemd will start at boot

The fact is a record of **symlinks**, because that is what systemd enablement
is. `systemctl enable` writes no database row and sets no flag inside the unit
file; it creates a link in `<target>.wants/`, `disable` removes it, and `mask`
replaces the unit file with a link to `/dev/null`. Reading those directories
recovers exactly the state `systemctl is-enabled` reports, with no dbus and no
privilege — which is why the collector declares `CapNone`.

`Links[]` holds the enablement symlinks, each with the target as written
(`Dest`), the same target made absolute against the link's own directory
(`Resolved`), and a `DestState` of `present`, `dangling` or `unknown`. The last
two are separate for the reason `cron.files` separates absent from denied: "the
target is not there" is a FAIL and "we were not allowed to look at it" is
UNKNOWN, and a single boolean would have collapsed them into a guess. See
ADR-0017 for why resolution happens here rather than at the seam.

`Units[]` holds the unit files, with the search directory they came from
(`Origin`: `admin`, `runtime` or `vendor`). The origin is systemd's own
precedence order and it is what makes masking legible: `/etc` outranks
`/usr/lib`, so an admin unit file pointing at `/dev/null` overrides a vendor
unit that cannot be deleted. `Services.Status` therefore tests masking **before**
enablement, because systemd does — a masked unit does not start even with a
`.wants` symlink naming it.

`Dirs[]` records every directory probed, including the absent ones, with a
`DirState` of `read`, `absent`, `denied`, `error` or `alias`. `alias` is
`/lib/systemd/system` on a usr-merged host, proved identical to
`/usr/lib/systemd/system` by inode rather than assumed from the distribution.
`Truncated` rides alongside `State` rather than replacing it: a listing that was
cut short was still read, so everything it returned is true and only conclusions
about *absence* are invalidated (ADR-0014).

The fact carries **no unit file contents**, for the reason `cron.files` carries
no crontab. A unit body is `ExecStart` command lines and `Environment=`
assignments that routinely hold credentials, and no SERVICES check reads them.

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
`fs.device_outside_dev`, and so on. All are the same Go type,
`fact.FSMatches`, whose `FactID` is derived from `Interest`. A module gets a
new fact by registering a new interest, not by writing a new fact type.

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

#### `fs.tally.<tally>` — the same walk, aggregated

One fact per registered walker **tally**: `fs.tally.owner_uid`,
`fs.tally.owner_gid`. The Go type is `fact.FSTally`, and it is a different type
from `FSMatches` because it answers a different shape of question.

An `Interest` **records**: it keeps the first `MaxHits` inodes matching a pure
predicate. A `Tally` **folds**: it maps every inode to a key, counts the keys,
and keeps one exemplar per key. The difference is memory, and it is what
decides which questions the walk can answer at all.

| | `fs.<interest>` | `fs.tally.<tally>` |
|---|---|---|
| Cost | one row per matching inode | one bucket per **distinct key** |
| Cap | `MaxHits` (default 20,000 rows) | `MaxKeys` (default 16,384 keys) |
| Coverage once the cap fires | the first N matches only | **every inode still counted**; only new keys are refused |
| Answers | "show me the setuid binaries" | "does every uid on disk resolve to an account" |

The second question cannot be answered by an interest. `Interest.Match` is pure
and is evaluated at registration time, before any fact exists, so it cannot
join against `/etc/passwd`; and deferring the join by recording every owned
inode as a row would overflow the row cap in the first populated directory of
any host that has users. The tally counts owners during the walk and the check
does the join where facts live. See `internal/collect/walker/tally.go` and
`docs/checks/FILESYS-0010.md`.

`Buckets` is sorted by key and each carries a `Count` and one `Example` row —
the first inode in walk order that fell into it. The exemplar is what makes a
tally actionable rather than merely numeric: a count says there is a problem,
an exemplar says where to look.

**The asymmetric truncation rule is unchanged**, and `FSTally.Complete()`
mechanises it exactly as `FSMatches.Complete()` does. One reason code is added:

| Reason | Meaning | Scope |
|---|---|---|
| `max_keys` | **this tally** reached its keyspace cap and refused a key it had never seen; `KeysDropped` counts them | one fact |

`max_keys` is a separate reason from `max_hits` because the two say opposite
things about how much was examined. A row cap means the walk stopped
*recording* after N matches. A key cap means the walk kept counting every inode
it met and only stopped admitting new buckets — which is why `InodesTallied`
exceeds the sum of the bucket counts on a tally that dropped keys. An operator
raising the wrong limit fixes neither.

Every whole-walk reason — `inode_limit`, `wall_clock`, `unreadable_dir` and the
rest — lands on tallies exactly as it lands on interests: it is one traversal,
so a limit that fires is a property of every fact it produced.

#### `users.nsswitch` — whether the local files are the whole account database

`/etc/passwd` is a file. The *account database* is whatever
`/etc/nsswitch.conf` routes `passwd` to, and on a host joined to LDAP, SSSD,
Active Directory or `systemd-homed` that is somewhere else, holding accounts
`/etc/passwd` has never heard of.

The distinction matters to exactly one kind of claim: a claim that an identity
does **not** exist. "This uid is not in `/etc/passwd`" is a fact about a file;
"this uid belongs to nobody" is a fact about the host, and the two are the same
statement only when the files are authoritative. `LocalFilesAuthoritative(db)`
is that predicate, and it is deliberately conservative: it is true only when
the file was read and names exactly one source, `files`, for the database. A
false negative costs an `UNKNOWN`; a false positive reports a legitimate
directory account as belonging to nobody.

`State` distinguishes `present`, `absent`, `denied` and `error`. **Absent is
not "files".** glibc falls back to a compiled-in default when the file is
missing, and that default is a property of the libc build rather than of
anything on this host, so a missing file leaves the effective policy unknown.

Action brackets — `[NOTFOUND=return]`, `[SUCCESS=merge]` — are parsed and
dropped. They govern what happens *between* two sources and no check asks about
them; carrying a field nothing reads is output surface bought for nothing.

`Digests` maps each entry of `Files` to the sha256 of the bytes read from it.
It was added after `sshd.config` v1 shipped and did **not** bump the version:
per §2.2 it is an optional field that no check is required to consider, and a
check reading a bundle written before it existed emits evidence without a
digest, which is what it did then and what the findings schema permits. See
`docs/adr/0009-evidence-digest-tracking.md`.

#### `memory.elf` — ELF hardening on the binaries worth hardening

One fact carrying an entry per probed binary, not one fact per binary. Two
constraints decide it, and neither is stylistic.

`Produces()` is read before a collector runs, so that a timeout or a panic can
be filed against the facts a check will look for. A per-path fact ID set is not
known until the collector has already stat'ed the host, so such a collector
could only ever be blamed by name. `fs.<interest>` is not a counter-example:
interests are registered at `init` and are static by the time anything asks.
And a fact ID becomes a bundle member name verbatim — `facts/<id>.json` — so an
ID carrying an absolute path would turn the flat `facts/` directory into a
mirror of the audited host's filesystem layout.

Per-binary ignorance lives in `ELFBinary.State` instead, so one unreadable
binary marks its own entry and leaves every other entry usable. The states are
`observed`, `absent`, `denied`, `not_regular`, `not_elf`, `too_large`,
`truncated` and `error`, and `PIE`, `Stack` and `RELRO` mean nothing unless the
state is `observed`. `false` is a legitimate value for both booleans, so
neither can double as "not recorded" — the rule ADR-0016 sets for uid 0.

**`Stack` is three states, not a bool.** With no `PT_GNU_STACK` header the
kernel applies its own default, which differs by architecture and by kernel
version, so the file does not answer the question. `ELFStackUnspecified`
carries that to the check, which resolves it to `UNKNOWN`. `NX()` returns the
value and whether the file said; a check that ignored the second return would
read an unspecified stack as an executable one.

**`RELRO` is partial RELRO and nothing more**, and `BindNow` is the other half.
Full RELRO is partial RELRO plus eager binding, which lives in the dynamic
section rather than in the program headers; reading `RELRO` alone as "RELRO is
on" would report a writable GOT as hardened. `FullRELRO()` combines the two and
returns whether the file answered at all — a statically linked binary has no
relocation table and neither has nor lacks the property.

Three dynamic-section encodings mean eager binding and all three are read:
`DT_BIND_NOW`, `DT_FLAGS`/`DF_BIND_NOW`, and `DT_FLAGS_1`/`DF_1_NOW`. The last
is what current toolchains emit — on a sample of stock Debian binaries not one
carried `DT_BIND_NOW`, the tag the specification names, and every one carried
`DF_1_NOW`. A reader that trusted the documented tag would report every
correctly hardened binary on a current distribution as lazily bound.

**`Symbols` exists because an absent symbol and an absent symbol *table* are
different observations.** `HasCanary` and `HasFortify` come from `.dynsym` and
`.symtab`, unioned, because a stripped image — which is every binary a
distribution installs — keeps the first and discards the second, while an
unstripped static binary has the reverse. When neither is present the state is
`stripped` and both booleans mean nothing: reading them as "unhardened" would
condemn a hardened binary for having nothing to look at. `SymbolsRead()` is the
gate, and the symbol checks resolve to `UNKNOWN` when it is false.

`FortifyCandidates` counts referenced libc functions that have a fortified
variant and were linked unfortified. It separates "compiled without
`_FORTIFY_SOURCE`" from "compiled with it and calling nothing it could
substitute", which are a finding and a non-finding that look identical from
outside.

`Resolved` is the path actually read, when the target was a symbolic link. The
seam never follows a terminal symlink, so the collector resolves the chain
itself and every hop goes back through the interface, which is what keeps
`--root` governing what is looked at (ADR-0017). Following links is not an edge
case here: on every Debian-family host `/usr/bin/sudo` is an alternatives link,
and a collector that stopped at it would examine nothing on the binary most
worth examining. Both paths are recorded because both belong in a report — one
names the command an operator types, the other names the file they have to
replace.

The fact carries no binary contents, only the parsed properties and a sha256 of
the image. A bundle is written to travel, and copying whole executables into one
would make an audit artifact the size of the binaries it audited, for checks
that never look at the bytes. Same reasoning as `cron.files` carrying no
crontab. `Truncated` means the collector stopped before probing every target; a
target absent from `Binaries` was never looked at, which no check may read as a
statement about the host.

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

### 3.1 `parse` — a file that was read and is not what it claims to be

`parse` covers two situations, and **there is deliberately no separate
"malformed" kind for the second.** A reader could not act differently on the
two, and `finding.UnknownReason` is part of `findings-v1`, so a second code
meaning the same thing would be a permanent addition to a frozen public API
that bought nothing.

**Not text at all.** Every file this project parses is a line-oriented text
configuration file, and every consumer of one on a Linux host — sshd, PAM,
glibc's passwd and group parsers, rsyslog, systemd — is C reading
NUL-terminated strings. So a NUL byte is *proof*, not a heuristic: the software
that actually acts on the file stops at that byte or refuses the file, and any
reading of ours that continued past it would describe a configuration that is
not in force. `collect.NotText` is the single test, applied at each collector's
read path, and it reports the offset because "somewhere in this file" is not
something an operator can act on.

Three things are deliberately **not** treated as malformation, because each
would reject files that real hosts have:

| Not rejected | Why |
|---|---|
| Invalid UTF-8 | A GECOS field on an older host carries a name in Latin-1. `internal/sanitize` already escapes such bytes on the way to a report, which is the correct handling; rejecting the file would report a broken account database on a host that merely has a European name in it |
| A high proportion of control characters | That is a threshold, and a threshold is a guess. The NUL test needs none: one is enough |
| An unrecognised keyword | Fatal to sshd, but the valid keyword set differs by OpenSSH release. Calling `SecurityKeyProvider` a syntax error reports a fault on a host that is merely more current than this build |

**Read, parsed, and syntactically invalid.** A file can be perfectly good text
and still not be the configuration in force. `SSHDConfig.SyntaxErrors` records
non-blank, non-comment lines that are not a keyword followed by an argument —
`sshd_config(5)` defines no keyword taking zero arguments, so each one is fatal
to `sshd -t`. This matters because sshd rejects a configuration file **as a
unit** rather than skipping the bad line: on such a host the daemon is running
whatever configuration last parsed, or is not running at all, and neither is
visible from disk. Every SSHD check therefore resolves to
`UNKNOWN(unparseable_source)` — *including* the checks whose keyword the file
does appear to set, because a correct directive two lines below a fatal error
is not in force either.

### 3.2 Present, preserved, and not interpretable

There is a third state between "the fact is here" and "the fact is missing",
and it had no representation until WP-27.

A bundle written by a newer build carries facts this one cannot decode. The
reader preserves them verbatim so that forwarding the bundle loses nothing,
which is right. But a preserved fact satisfied "the required fact is present",
so the check's `Eval` ran, its typed accessor returned the zero value, and an
`sshd.config` that could not be decoded was reported as **`NOT_APPLICABLE`: the
SSH server is not configured on this host** — a statement about the host
manufactured out of a decode failure.

`fact.Opaque` is the marker that closes it:

```go
type Opaque interface {
    Fact
    OpaqueFact() int // the version the producer declared
}
```

It is an interface rather than a concrete type because the fact carrying it is
produced by `internal/bundle`, and `internal/catalog` must not import the
serialisation layer in order to evaluate anything. The required-fact gate tests
for it and returns `UNKNOWN(fact_version_mismatch)` — a reason code that was
declared for exactly this case long before anything produced it.

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

A fourth state is handled by the gate rather than by `Get`: a fact that is
present and **opaque** — see §3.2 — resolves to
`UNKNOWN(fact_version_mismatch)` before `Eval` is entered.

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
| result ≠ `FAIL` and not suppressed ⇒ `remediation` is absent | Remediation on a PASS confuses readers and renderers. A suppressed finding is the exception: it reached `FAIL` or `UNKNOWN`, and the fix it would need is still the fix it would need |
| `suppression` present ⇒ result is `SKIPPED` | Enforced by the schema; see §5.7 |
| `skipped_by` present ⇒ result is `SKIPPED` and no suppression | Enforced by the schema; see §5.6 |
| `FAIL` or `UNKNOWN` ⇒ `evidence` is non-empty | See §5.3 |
| `base_severity` is never mutated by `Eval` | Adjustment must stay visible |
| `fingerprint` is non-empty | Suppressions depend on it |

### 5.6 SkippedBy

```go
SkippedBy string `json:"skipped_by,omitempty"`
```

Names the profile that put a check out of scope. Set only when `result` is
`SKIPPED` and there is no suppression; enforced by the schema.

It exists because the three ways a check reaches `SKIPPED` are different facts
and a consumer has to tell them apart: an accepted risk carries a
`suppression`, a check outside the declared baseline carries this, and anything
else is the runner's own doing.

**A check with `skipped_by` set leaves the posture denominator.** That is the
one place this field changes arithmetic rather than describing it: the profile
declares what applies, so `Applicable = Total − NOT_APPLICABLE − out-of-profile`.
Without a marker nothing could compute that. The file format and the rest of
the semantics are in `CLI-SPEC.md` §3a.

Added to `findings-v1` as an optional field, which `VERSIONING.md` §4.1 permits
within a schema major.

### 5.7 Suppression

```go
type Suppression struct {
    Justification  string `json:"justification"`
    ExpiresAt      string `json:"expires_at,omitempty"`
    OriginalResult Result `json:"original_result"`
}
```

Present on a finding an operator accepted, and only ever alongside
`result: SKIPPED`. Added to `findings-v1` as an optional field, which
`VERSIONING.md` §4.1 permits within a schema major; consumers written before it
existed ignore it and see a `SKIPPED` finding, which is true.

**`original_result` is the field that makes this honest.** A suppressed finding
keeps its row, its severity, its detail, its evidence and its remediation, and
states what it would have been. Without that field a suppression would be
indistinguishable from a check that never ran, and "we accepted this" would
render identically to "we never looked" — which is the failure the whole
feature exists to avoid. It is always `FAIL` or `UNKNOWN`; a `PASS` is never
suppressed.

Suppressions are applied by `internal/suppress`, **after every check has
reached its verdict and before anything is scored**. No check can observe one,
so check purity is untouched: a suppression is a statement about a finding, not
an input to producing it. The file format is specified in `CLI-SPEC.md`
§Suppressions.

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

**`meta.json` is descriptive and no check reads it.** It labels a report for a
human — which host, which distribution — and nothing in the catalog consumes it.
That is what makes silence the right answer when a field cannot be read: an
absent `os_release` costs a label, while an invented one would put a fact into
a bundle that nobody observed.

`os_release` is the `PRETTY_NAME` from `os-release(5)`, looked up in the order
that specification gives: `/etc/os-release` first, because a local override goes
there, then `/usr/lib/os-release`. **Both are read through an explicit, bounded
symlink resolution** (`collect.ResolveLinks`), because every systemd
distribution ships the `/etc` path as a link into `/usr/lib` and the seam opens
privileged reads with `O_NOFOLLOW`. `hostname` is deliberately *not* resolved
that way: no distribution ships it as a link, so one found there was put there
by somebody.

`kernel` and `arch` are reserved and not yet produced — no collector reads
them. They are absent rather than empty.

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
