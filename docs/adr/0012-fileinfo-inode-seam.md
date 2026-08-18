# ADR-0012 — `FileInfo` carries device and inode, flattened

**Status:** accepted · **Date:** 2026-08-18

## Context

WP-15 builds the shared filesystem walker. `ARCHITECTURE.md` §3.2 requires
"bind-mount and cycle detection via device+inode set", and it is not optional
decoration: a bind mount that points a directory at one of its own ancestors
makes the tree infinite, and a scanner that walks it never returns. `--root`
does not help — the cycle is inside the tree being scanned.

`system.FileInfo` carried mode, uid, gid, size, mtime and the three type
booleans. It carried no device or inode number, so there was nothing to build
the set from.

The tempting shortcut is to hand the walker the real `os.FileInfo` and let it
call `st.Sys().(*syscall.Stat_t)` itself. That breaks two things at once:

- **`FileInfo` is serialisable by contract.** `DATA-MODEL.md` §2.1: everything
  a fact carries must survive a round trip through JSON in a bundle — no
  `fs.FileInfo`, no pointers into process memory. A `*syscall.Stat_t` in a fact
  is a fact that cannot be written to a bundle, which means the finding derived
  from it cannot be re-evaluated later, which is the whole product.
- **It would put a syscall type on the path to a check.** Checks are pure
  functions over facts. A check reaching into `syscall` is a check that is
  platform-specific, unfakeable, and outside the seam the invariant gates
  police.

Options considered:

- **Flatten `Dev` and `Ino` onto `FileInfo` as `uint64`** — the walker gets what
  it needs, facts stay serialisable, no syscall type escapes `internal/system`
- **Give the walker a second, privileged view of the filesystem** — a parallel
  seam, which is the thing the seam exists to prevent
- **Detect cycles by path depth alone** — a depth limit is a backstop, not
  detection. It terminates the walk but reports a truncated result on a host
  that is merely misconfigured, and it cannot tell a deep tree from a loop
- **Compare `(size, mtime, mode)` as a cheap identity** — collides, and a
  collision here means silently skipping a real directory

## Decision

**`system.FileInfo` carries `Dev uint64` and `Ino uint64`.**

Extraction from `syscall.Stat_t` happens inside `internal/system`, which is the
only package allowed to know that `syscall` exists. Both are plain integers by
the time anything else sees them, so a fact holding a `FileInfo` still
round-trips through a bundle unchanged and a check still sees only data.

`fake` supplies real values from the fixture tree's own files, so two fixture
paths are genuinely distinct and cycle-detection tests are testing the set
rather than testing the fake.

Both fields are `omitempty`. Inode 0 is not a valid inode and device 0 is not a
real device for a file on any Linux filesystem, so the zero value is
unambiguously "not recorded" rather than a legitimate identity being dropped.

## Consequences

- The walker can detect bind-mount and hardlink cycles properly, and can tell
  a loop from a deep tree — which is the difference between "this host is
  misconfigured" and "we gave up"
- `FileInfo` is now wider, and it appears inside facts, so every fact that
  embeds one grows by two integers in the bundle. Acceptable: the alternative
  was a walk that cannot terminate safely
- Two more fields that a platform other than Linux would have to fill
  plausibly. There is no such platform in v1 and `PLATFORM-SUPPORT.md` will say
  so
- **Known follow-up for WP-15:** a fixture cannot yet *simulate* a cycle. Real
  values from disk make paths distinct, which is right, but a bind-mount cycle
  needs two paths reporting the same `(Dev, Ino)`. That means either a manifest
  override in `fake` — a fixture-format change, so `FIXTURES.md` and its own
  decision — or a test that constructs a real hardlinked directory, which needs
  privilege. Decide it in WP-15 rather than discovering it while writing the
  cycle test
