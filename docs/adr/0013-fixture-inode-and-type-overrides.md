# ADR-0013 — Fixtures describe inode identity and file type in the manifest

**Status:** accepted · **Date:** 2026-08-19

## Context

ADR-0012 put `Dev` and `Ino` on `system.FileInfo` so the shared walker could
detect bind-mount and hardlink cycles by identity rather than by giving up at a
depth limit. It closed with an explicit follow-up, deferred to WP-15:

> a fixture cannot yet *simulate* a cycle. Real values from disk make paths
> distinct, which is right, but a bind-mount cycle needs two paths reporting
> the same `(Dev, Ino)`. That means either a manifest override in `fake` — a
> fixture-format change, so `FIXTURES.md` and its own decision — or a test that
> constructs a real hardlinked directory, which needs privilege.

Building the walker made the same problem visible twice more. WP-15 requires a
test proving the walk never opens a FIFO, a socket or a character device, and
none of the three can be committed to git; `mknod` for the character device
needs root, so the tree cannot be generated at test time either. And the
`modes` override could not express a SUID binary at all: it masked the parsed
octal with `fs.ModePerm`, so `"4755"` silently became `0755`. Every filesystem
check in WP-23 is about exactly the bits that were being dropped.

Options considered:

- **Manifest overrides for identity and type** — the fixture states what git
  cannot carry, which is what the manifest already exists for
- **Construct the real thing at test time** — works for a FIFO and a unix
  socket, needs root for a character device, and is impossible for a bind
  mount without a mount namespace. CI that runs as root to build fixtures is a
  worse trade than a described fixture
- **Skip the cases that cannot be built** — the FIFO case is the local denial
  of service the walker exists to avoid, and the bind mount is the hang. These
  are the two cases most worth testing
- **Test the walker against a hand-written stub `System`** — precise, but it
  tests the walker against a second implementation of the seam, and the
  fixture corpus stops being the thing every layer is exercised through

## Decision

**The fixture manifest gains an `inodes` map, and `modes` gains meaning.**

`inodes` maps a path to `"dev:ino"`. Two paths given one identity is a bind
mount, which is precisely what the walker's cycle detection is for. `0:0` is
rejected at load: zero means "not recorded" on the seam, so accepting it would
silently disable cycle detection for that path — the opposite of what anyone
writing the field intends.

`modes` is translated rather than cast. Go encodes setuid, setgid, sticky and
the file type in high bits of its own choosing, so `fs.FileMode(0o4755)` is
`0o755` with a meaningless bit set. The octal a fixture author reads out of
`stat -c %a` is now converted properly, and the type bits (`0o140000` socket,
`0o020000` character device, `0o010000` FIFO, and the rest) set the
corresponding `fs.ModeType` bit.

A `modes` entry that names no type leaves the type alone. `"0644"` is a
statement about permissions and says nothing about what the inode is; clearing
the type for it would turn every directory carrying a mode override into a
regular file, and a walk would stop at it without ever saying why.

Described fixtures **complement** real ones, they do not replace them.
`internal/system/live/hostile_test.go` still builds a real FIFO against the
real seam, and the walker's own test builds a real FIFO and a real unix socket
in a temp tree and asserts the walk terminates. What the manifest covers is the
inodes that cannot be created without privilege.

## Consequences

- A bind-mount cycle, a character device, a SUID binary and a sticky directory
  are all expressible as committed fixtures, so the cases most likely to hang
  or mislead a root process are the cases with tests
- The fixture format is wider, and `inodes` is a field that can describe a
  filesystem no kernel would produce — two files with one identity and
  different contents, say. That is a sharp edge, and it is the price of being
  able to describe a bind mount at all
- `modes` now changes behaviour for strings that previously did nothing.
  Existing fixtures use plain permission strings (`"0640"`, `"0600"`) and are
  unaffected; a fixture that meant to request SUID and silently did not now
  gets what it asked for, which may turn a passing test into a failing one.
  That is the bug being fixed, not a regression
- Two ways to express a FIFO now exist — described in a manifest, or created in
  a temp tree. The rule is that the seam's own tests use real ones and
  everything above the seam may use described ones, because above the seam a
  FIFO is a `FileInfo` with a bit set and nothing more
