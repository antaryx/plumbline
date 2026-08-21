# Performance

**Every number in this document was measured.** `docs/DOCUMENT-MAP.md` requires
that, and it is the same rule the catalog follows: a figure nobody took is a
figure nobody can act on, and a performance budget invented at a desk is how a
tool acquires a reputation for being slow in ways nobody can reproduce.

---

## 1. The short version

| Phase | Cost | Bound by |
|---|---|---|
| Evaluation — 79 checks over a collected bundle | **~10 ms** | CPU, and not measurably |
| Collection — configuration files only | **< 100 ms** | a bounded number of small reads |
| Collection — the filesystem sweep | **seconds to tens of seconds** | **disk I/O**, and nothing else |

**The engine is free and the disk is not.** Evaluating the whole catalog costs
about ten milliseconds; walking a real root filesystem costs three to thirty
seconds depending almost entirely on whether the inodes are in page cache.

If a scan feels slow, it is the sweep. Everything else is noise beside it.

---

## 2. Reference host

Measurements below are from one machine, stated so they can be discounted
appropriately rather than treated as universal:

| | |
|---|---|
| CPU | 8 logical cores |
| Memory | 9 GB |
| Kernel | 6.6.87 (WSL2) |
| Filesystem | ext4 on NVMe, **731,571 inodes** below `/` |
| Build | `v1.0.0-rc1`, `CGO_ENABLED=0`, catalog 13, 79 checks |

WSL2 is not a clean reference platform — its filesystem layer adds overhead a
bare-metal host does not have — so treat the absolute numbers as an upper bound
and the *ratios* as the finding.

---

## 3. Measured

### Evaluation is free

```
$ plumbline eval testdata/bundles/ubuntu-2404-hardened.plb -o /dev/null
0.01s   (five consecutive runs, all 0.01s)
```

79 checks, 20 facts, a full findings document rendered. This is the entire
engine — parsing a bundle, running every check, scoring, rendering — with no
collection at all, and it does not register above the process start-up cost.

**That is a design property, not luck.** Checks are pure functions from facts to
findings: no check opens a file, makes a syscall, or waits for anything. Adding
the next forty checks will not move this number meaningfully.

### Collection is bound by the disk

```
$ plumbline scan --root / -o /dev/null

  cold cache:   wall 31.86s   user 2.94s   sys 10.32s   maxrss 66 MB
  warm cache:   wall  2.79s   user 1.41s   sys  1.71s   maxrss 70 MB
```

**The same work, on the same host, eleven times faster the second time.** Nothing
about the computation changed; only whether the kernel had the inodes cached.
That ratio is the whole finding, and it is what "I/O bound" means in practice.

Note the cold run: 13.3 s of CPU against 31.9 s of wall clock. More than half
the run is the process waiting on the disk.

An operator on a different host reported ~19 s for a full scan, which sits
between these two figures — as it should, on a machine with a different inode
count and a partially warm cache.

### A fixture tree is instant

```
$ plumbline scan --root testdata/fixtures/cli-host -o /dev/null
0.00s
```

Which is why the test suite runs 79 checks against 95 fixture trees in under a
second, and why fixtures rather than virtual machines are what this project
tests against.

---

## 4. Why the sweep costs what it does

One traversal serves the whole `FILESYS` module, and several checks can only be
answered by visiting every inode:

- **`FILESYS-0010`** — every uid and gid owning a file resolves to a local
  account. An orphaned file is one owned by an identity that no longer exists,
  and there is no way to know one is absent without looking at all of them.
- **`FILESYS-0001` / `0002`** — setuid and setgid executables, wherever they are.
  A setuid binary in `/opt` is exactly the one an attacker put there.
- **`FILESYS-0004` / `0005`** — world-writable files and directories.
- **`FILESYS-0006`** — device nodes outside `/dev`.

Each is a question of the form *"is there anywhere on this host a file that…"*,
and that question has one honest implementation. A tool that answered it by
checking `/etc` and `/usr/bin` would be fast and would miss the finding that
matters.

**The traversal is shared.** All ten `FILESYS` checks are answered from a single
walk, because the design this project replaced ran twelve concurrent walks and
the runner now permits one `Expensive` collector at a time by construction.

### What it does not do

- No `find` subprocess. No subprocess at all — `Exec` takes `argv []string` and
  is used by nothing in the collection path.
- No content hashing of files it walks. Only `lstat`, so cost scales with inode
  count rather than with bytes on disk. A 4 TB media server with 50,000 files is
  faster to scan than a 40 GB build host with two million.
- No following of symlinks, and no crossing into `proc`, `sys`, `tmpfs`,
  network filesystems or bind-mount cycles — the mount table is read once and
  used to skip them.

---

## 5. What to do about it

### Scan when the cost does not matter

A full scan is a nightly or per-deploy activity, not an interactive one. The
architecture is built for that: `collect` on the host, `eval` anywhere.

```bash
plumbline collect -o host.plb     # the expensive half, once, on the host
plumbline eval host.plb           # ~10 ms, and repeatable anywhere, forever
```

Re-evaluating an existing bundle against a newer catalog costs milliseconds, so
"what would today's checks say about last month's host" is free.

### Bound it explicitly

```bash
plumbline scan --collector-timeout 60s     # per collector
plumbline scan --timeout 10m               # whole scan
```

A collector that exceeds its budget produces `UNKNOWN` with a timeout reason —
never a truncated result reported as a `PASS`. That distinction is why a budget
is safe to set.

### Narrow the question

```bash
plumbline scan --profile cis-l1
```

A profile that excludes the `FILESYS` module skips the sweep with it, and says
so: excluded checks are reported `SKIPPED` and leave the posture denominator.

### Memory is not the constraint

Peak RSS was **66–70 MB** walking 731,571 inodes, and it is bounded by
construction rather than by luck: the walker aggregates into tallies as it goes
rather than accumulating a list of every file it saw, and every read is capped
(`DefaultMaxRead`, 8 MiB) because the process may be root and the file may be
hostile.

---

## 6. Regression policy

There is **no CI performance gate**, and that is deliberate. A wall-clock
assertion on a shared runner measures the runner's neighbours, fails randomly,
and gets disabled within a month — which is worse than no gate, because the
disabling is what people remember.

What CI does assert is the property that would make a regression *matter*:
`TestGolden` re-evaluates six recorded bundles on every build, so a change that
made collection slower by doing more work would show up as changed facts and a
changed verdict, which is the visible symptom.

Re-measure and update this document when the walker changes, when a new
`Expensive` collector is added, or before a major release.
