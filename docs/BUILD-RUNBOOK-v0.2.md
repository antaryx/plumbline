# BUILD RUNBOOK — v0.2.0 catalog expansion

Work packages sized to roughly one Claude Code session each. Execute in order;
each one leaves the tree green.

**How to use this:** open a session, paste the work package verbatim as the
brief, let it run, then audit against the acceptance criteria before merging.
Do not batch two packages into one session — the review surface gets too large
to audit properly, which defeats the point of working this way.

---

## What is already true

**v0.1.0 is tagged.** The walking skeleton is complete and every architectural
claim it makes is a test rather than a promise. WP-00 through WP-14 are in git
history; read the commits rather than re-deriving the reasoning.

| Shipped in v0.1.0 | Where |
|---|---|
| The OS seam, `--root` prefixing, fixture-backed fake | `internal/system` |
| Typed facts, `FactSet`, typed fact errors | `internal/fact` |
| Findings: five result states, weights, evidence, fingerprints | `internal/finding` |
| Check registry and evaluation runner | `internal/catalog` |
| Collector interface, dependency DAG, budgeted runner | `internal/collect` |
| Bundle read/write, integrity, content-addressed evidence | `internal/bundle` |
| Control-character neutralisation (T-03) | `internal/sanitize` |
| Posture and coverage, both able to be undefined | `internal/score` |
| `findings/v1` renderer | `internal/render/json` |
| `collect`, `eval`, `scan`, `version`, the exit ladder | `internal/cli` |
| The fixture gate | `tools/fixturegate` |
| SSHD-0002, nine fixtures — the reference check | `internal/catalog/checks/sshd` |

**What that buys you.** A module work package is now genuinely repetitive: the
runner, the bundle, scoring, rendering, the exit codes and the invariant gates
all exist and are tested. A new module adds a collector, some facts, some
checks and their fixtures, and nothing else. If a work package below seems to
need a change to `internal/bundle`, `internal/score` or `internal/render`, stop
— either the design is wrong or the work package is.

**The gates that will block you, and should.** `make verify` runs
`check-system-seam` (no OS access outside `internal/system`),
`check-check-purity` (no clock, network or System in a check) and
`check-fixture-coverage` (no check without PASS and FAIL fixtures). Each of
these has already caught a real mistake during v0.1. Treat a gate failure as
information, not as an obstacle.

**Catalog arithmetic.** v0.1.0 ships 1 check. The modules below add ≈113, which
is the ~110 the project has always claimed. Bump `catalog.Version` in every
work package that touches the catalog — it is what makes two scores comparable,
and `plumbline diff` refuses a comparison across versions.

---

## WP-15 — The shared filesystem walker

**Goal:** one traversal per scan, no matter how many checks care about the
filesystem. This is a work package in its own right because it is the single
piece of v0.2 that can hang a production host, and because `FILESYS` (WP-23)
cannot start without it.

**Build:** `internal/collect/walker` plus an `fswalk` collector.

The design is `ARCHITECTURE.md` §3.2 and is not open for reinterpretation.
Consumers register *interest predicates* up front and the walker evaluates all
of them per inode in a single pass:

```go
type Interest struct {
    // Name is the fact suffix this interest produces: "suid" becomes fs.suid.
    Name    string
    // Match decides whether this inode is interesting. Pure, and fast — it
    // runs once per inode on a filesystem that may hold ten million of them.
    Match   func(system.FileInfo) bool
    // Row extracts what the fact should record. Called only when Match passed.
    Row     func(system.FileInfo) Row
    // MaxHits caps the rows this interest may produce. Overflow is recorded,
    // never silently dropped.
    MaxHits int
}
```

Walk rules, all non-negotiable and all tested:

- **At most one traversal per scan.** Registration happens before the walk; a
  consumer that arrives late is a programming error and panics at init, the
  same way a collector dependency cycle does.
- **Never crosses filesystem boundaries** unless `--walk-crossfs` is passed.
- **Skips by fstype:** `proc`, `sysfs`, `devtmpfs`, `cgroup*`, `tracefs`,
  `debugfs`, `fuse.*`, `nfs*`, `cifs`, `autofs`. A network filesystem is the
  classic hang, and it hangs in the kernel where no timeout of ours reaches.
- **Never follows symlinks. Never opens anything that is not a regular file or
  a directory** — no FIFOs, no character devices, no sockets. The FIFO case
  already has a test at the seam (`internal/system/live/hostile_test.go`);
  the walker needs its own, because it reaches paths nobody named.
- **Depth limit, inode-count limit and wall-clock budget.** Hitting any of them
  sets a truncation marker on every fact the walk produced.
- **Bind-mount and cycle detection** via a device+inode set.

**Two prerequisites this work package has to deal with, not around:**

1. **`system.FileInfo` carries no device or inode number.** Cycle detection
   needs both. That is a change to a seam type that facts serialise, so it
   needs an ADR and a `DATA-MODEL.md` update, and `fake` must supply them from
   the fixture tree. Do this first, in its own commit.
2. **`ReadDir` returns a slice.** A directory with ten million entries
   materialises all of them before the inode-count limit can fire, which
   defeats the limit it was supposed to respect. Either add a streaming
   variant to the seam or bound `ReadDir` explicitly — decide deliberately and
   write down which, because the wrong choice here is a memory exhaustion in a
   root process.

**Truncation and what a check may conclude from it.** This is the rule that
matters most, and it is asymmetric:

> A truncated walk can invalidate a *negative* result. It can never invalidate
> a *positive* one.

A SUID binary the walk found is a SUID binary that exists, and the check
returns `FAIL` regardless of whether the walk finished. "No SUID binaries
outside the allowlist" over a partial walk is **not** a `PASS`; it is
`UNKNOWN(source_truncated)`, using the reason code that already exists for
exactly this. A check that returns `PASS` from a partial walk has converted
"we stopped looking" into "there is nothing there", which is the single failure
mode this project exists to prevent.

**Facts.** One fact per interest (`fs.suid`, `fs.world_writable`, …) rather
than one fact holding everything. A check requiring `fs.suid` must not resolve
to `UNKNOWN` because an unrelated interest overflowed its cap. Each fact
carries the walk's truncation marker and its own overflow count.

**Cost.** `fswalk` returns `Expensive`, so the runner already serialises it
against every other expensive collector. Do not add a second mechanism.

**Acceptance:**
- [ ] Two interests over one fixture tree produce two facts from one traversal;
      a counter proves the tree was visited once
- [ ] A fixture containing a FIFO, a socket and a character device completes,
      opens none of them, and records them as non-regular
- [ ] A symlink loop and a bind-mount cycle both terminate, proven by the
      device+inode set rather than by a depth limit backstop
- [ ] Each of the depth, inode-count and wall-clock limits fires in its own
      test and sets the truncation marker on every fact produced
- [ ] `MaxHits` overflow is recorded with a count, and the fact says so
- [ ] A check over a truncated walk returns `UNKNOWN(source_truncated)` for a
      negative result and `FAIL` for a positive one; both asserted
- [ ] An fstype from the skip list is not descended into, proven against a
      fixture mountinfo rather than against the test machine's real mounts
- [ ] `make verify` green

**Do not:** let any check walk the filesystem itself; add a second walk for a
"special case"; implement `--walk-crossfs` as anything other than an explicit
opt-in; or make the truncation marker optional.

---

## The shape of a module work package

WP-16 through WP-24 are the same work package nine times, which is the point:
the pattern was proven in WP-04 and WP-05 so that the repetition is cheap.
Every one of them does exactly this.

**Build, in this order, each in its own commit:**

1. **Facts.** Typed structs in `internal/fact`, listed in `DATA-MODEL.md` §2.3
   with their version. Facts record what the host says; they never judge.
2. **Collector.** Implements `collect.Collector`: `ID`, `Produces`,
   `DependsOn`, `Requires`, `Cost`, `Timeout`, `Collect`. Registers itself at
   init. Records a typed `fact.Error` for anything it could not read, rather
   than omitting it.
3. **Fixtures.** One directory per scenario under `testdata/fixtures/`, named
   `<module>-<scenario>`. Include the ones people forget: keyword absent,
   value in a drop-in, unreadable, unparseable, CRLF, comment on the value
   line. See `FIXTURES.md` §4.1.
4. **Checks.** One file per check, IDs allocated from the next free number in
   the module and permanent thereafter. All five result states considered.
5. **Tests.** Table tests over the whole vertical slice — real collector
   against a fixture tree, then the real check — asserting result, severity,
   unknown reason, and a substring of the detail.
6. **Bump `catalog.Version`.**

**Acceptance, for every module work package:**
- [ ] Every check has PASS and FAIL fixtures; `NOT_APPLICABLE` and `UNKNOWN`
      wherever reachable
- [ ] Every `UNKNOWN` path carries a reason code
- [ ] Every `FAIL` carries evidence and remediation; `Caution` on anything that
      can lock an operator out
- [ ] Evidence is built with `finding.NewEvidence` and carries a digest where
      the fact provides one
- [ ] The module's collector declares a `Timeout` it can justify
- [ ] `catalog.Version` bumped
- [ ] `make verify` green, output pasted

**Do not,** in any module work package: add a flag, a config key or an output
field; change `internal/bundle`, `internal/score` or `internal/render`; add a
dependency; or resolve an ambiguity by choosing. Stop and ask.

---

## WP-16 — KERNEL (~15 checks)

**Goal:** the cheapest facts in the project, so the module pattern is well-worn
before the hard parsing arrives.

**Facts:** `kernel.sysctl` — the effective values, plus where each came from.

**What makes it non-trivial anyway:** the effective value and the configured
value are different observations. `/proc/sys` is what is running;
`/etc/sysctl.conf` and `/etc/sysctl.d/*.conf` are what will be running after a
reboot. A host with a hardened file and an unhardened kernel is a real and
common finding, and reporting either number alone hides it. Record both, and
make at least one check compare them.

**Hazards:** `/proc` is on the walker's skip list and must be read directly by
this collector, not walked. Some keys are unreadable even as root depending on
namespace and lockdown; that is `UNKNOWN(insufficient_privileges)`, not a
missing key.

---

## WP-17 — USERS (~10 checks)

**Facts:** `users.passwd`, `users.shadow`, `users.group`.

**Hazards:** `/etc/shadow` is unreadable unprivileged, which is the module's
main `UNKNOWN` path and must be tested as one. NIS/LDAP compat entries (`+`),
uid 0 accounts other than root, duplicate uids, and accounts whose shell is a
nologin variant that differs per distribution.

**Redaction interacts here.** `--redact` currently drops the hostname; a user
list is at least as identifying. Decide whether redaction extends to account
names and write it down — this is a `--redact` semantics decision and needs an
ADR, not a quiet choice inside a collector.

---

## WP-18 — SSHD remainder (~19 checks)

**Goal:** the collector already exists and is the project's reference
implementation. This work package is almost entirely checks, which makes it the
right place to find out whether the check-authoring pattern actually scales.

**Hazards:** the fact may need `sshd -T` cross-checking, deferred from WP-04.
That is an `Exec` through the seam and a second source of truth that can
disagree with the parsed files — a disagreement is `UNKNOWN`, never a silent
preference for one source. Match-block evaluation against a concrete user or
address is also deferred and is its own decision.

---

## WP-19 — CRON (~8 checks)

**Facts:** `cron.tabs` — system crontab, `/etc/cron.d`, per-user tabs,
`cron.allow` / `cron.deny`.

**Hazards:** per-user crontabs live in a spool directory that is unreadable
unprivileged, and its path differs by distribution. A crontab that references a
script the operator can write is the finding that matters, and it needs the
file's mode — which means this module wants facts from the walker or a targeted
stat, not a guess.

---

## WP-20 — LOGGING (~8 checks)

**Facts:** `logging.config` for rsyslog, syslog-ng and journald.

**Hazards:** three implementations with three grammars, and a host may run more
than one. "No logging configured" and "logging configured by an implementation
this build does not parse" are different observations, and only the second is
`UNKNOWN`. Remote log shipping is a positive finding; its absence is not
automatically a failure, so be careful what the check actually asserts.

---

## WP-21 — SERVICES (~10 checks)

**Facts:** `services.units` — enabled and running state.

**Hazards:** systemd, OpenRC and sysvinit divergence, and this is the first
module that genuinely needs `Exec` (`systemctl list-unit-files`). Parsing
`systemctl` output is a versioned interface; prefer the filesystem where the
answer is on the filesystem, and record the exec's argv as evidence when it is
not. A container with no init at all is `NOT_APPLICABLE`, not a failure.

---

## WP-22 — NETWORK (~12 checks)

**Facts:** `network.listeners`, `network.firewall`.

**Hazards:** listeners come from `/proc/net/*` — parse the hex address fields
carefully and test IPv6 and IPv4-mapped addresses, because getting this wrong
turns a loopback-only service into an internet-exposed one in the report.
Firewall presence spans nftables, iptables-legacy, iptables-nft, firewalld and
ufw; "no rules found" and "no firewall tool present" are different.

**This module feeds severity adjustment** (`ARCHITECTURE.md` §4.4): a service on
a non-loopback address with no host firewall is the signal that raises severity
by one level. Both severities are always reported. Build the fact; do not build
the adjustment mechanism in the same work package.

**`--redact` drops non-loopback addresses.** Until this module exists that
clause has nothing to act on. Implement it here and test it here.

---

## WP-23 — FILESYS (~14 checks)

**Blocked by WP-15.** Do not start it earlier; a temporary walk written "just
for now" is a permanent second walk.

**Facts:** whatever interests the module registers with the walker — SUID and
SGID binaries, world-writable files and directories, unowned files, sticky-bit
directories, and mount options from `fact` sources the walker already has.

**Hazards:** every check in this module is a negative assertion over a
traversal, which is precisely the shape that must return
`UNKNOWN(source_truncated)` rather than `PASS` when the walk was partial. Write
that test first. Allowlists for legitimately SUID binaries differ per
distribution and must come from facts, never from a hardcoded list that
silently excuses a real finding.

---

## WP-24 — AUTH (~17 checks)

**Goal:** the hardest module, done last, with the pattern established.

**Facts:** `auth.pam` — the PAM stack, `auth.login_defs`, `auth.pwquality`.

**Hazards:** PAM is the worst parsing job in the project. Stack order is
semantic, `include` and `substack` change control flow, control flags have both
simple and bracketed forms, and the same file means different things on
Debian-family and Red Hat-family hosts. A misparse here produces a confidently
wrong verdict about authentication, which is the most damaging thing this tool
could say.

**Rule for this module specifically:** when the stack cannot be resolved with
certainty, return `UNKNOWN`. A password policy check that guesses is worse than
no password policy check, because an operator will believe it.

---

## v0.2.0 exit criteria

Tag only when all hold:

- [ ] ≈110 checks across nine modules, every one with PASS and FAIL fixtures
- [ ] One filesystem traversal per scan, asserted by a counter
- [ ] No check reads the filesystem directly; enforced by `make verify`
- [ ] Every negative assertion over a truncated walk returns
      `UNKNOWN(source_truncated)`, never `PASS`
- [ ] `catalog.Version` incremented once per catalog change, and `plumbline
      diff` refuses to compare across versions
- [ ] A scan of a stock install of each distribution in the CI matrix completes
      with no `internal_error` fact errors
- [ ] Findings validate against `findings-v1` for every fixture in the corpus
- [ ] `DATA-MODEL.md` §2.3 lists every fact with its version, accurate against
      the implementation
- [ ] `make verify` green

---

## Then: v0.3 and beyond

`ROADMAP.md` governs. The next surfaces after the catalog are the terminal and
SARIF renderers, `diff`, suppressions, and `doctor` — none of which should
change a fact or a check, and all of which are easier because the catalog will
by then be large enough to be a real test corpus.
