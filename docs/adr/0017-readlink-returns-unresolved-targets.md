# ADR-0017 — `Readlink` returns the target as written, and resolution goes back through the seam

**Status:** accepted · **Date:** 2026-08-19

## Context

`BUILD-RUNBOOK-v0.2.md` WP-21 requires evaluating systemd service state
offline. Plumbline never talks to dbus and never runs `systemctl`, so the
question "is this service enabled" has to be answered from the filesystem.

Fortunately that is where the answer lives. `systemctl enable foo.service`
writes no database row and sets no flag inside the unit file. It reads the
unit's `[Install]` section and creates a symlink:

```
/etc/systemd/system/multi-user.target.wants/foo.service
    -> /usr/lib/systemd/system/foo.service
```

`disable` removes it; `mask` replaces the unit file with a link to `/dev/null`.
**Enablement is a symlink**, and reading the `.wants` and `.requires`
directories recovers exactly the state `systemctl is-enabled` would report.

The seam could see that a path *was* a symlink — `FileInfo.IsSymlink` has been
populated since the initial slice — but not what it pointed at. Three decisions
follow from adding that, and each of them is cheap to get wrong and expensive to
discover.

## Decision

### 1. `Readlink(path string) (string, error)` joins the interface, and resolves nothing

The method returns the link's contents **verbatim**. It does not make a relative
target absolute, does not check that the target exists, and does not follow a
chain.

The alternative — a seam method returning a resolved absolute path — is the one
that must not be built. Resolving means dereferencing, and dereferencing an
absolute target such as `/usr/lib/systemd/system/sshd.service` happens against
**the real host**, not against the scan root. That is precisely what `--root`
exists to prevent, and it would have been silent: on a developer's workstation
and in CI the resolution would have succeeded, because those hosts have the file
the fixture named.

Resolution is therefore the caller's job, and it goes **back through the seam**:
the collector joins a relative target against the link's own directory and calls
`Stat` on the result, so `--root` still governs what is examined. The collector
also keeps the raw target beside the resolved one, because the raw string is
what `ls -l` shows an operator and where the two differ, the difference is
usually the bug.

That a target may not exist is not an error condition — it is the finding.
SERVICES-0004 reports enablement symlinks pointing at unit files that were
removed, a state `systemctl is-enabled` still calls `enabled`.

### 2. `ErrNotSymlink` is a sentinel, so `live` and `fake` agree

`readlink(2)` returns `EINVAL` for a path that is not a symlink. Passing that
through would have made the two implementations disagree about the same host:
`live` returning a platform errno and `fake` returning whatever `os.Readlink`
produced over a fixture tree. A collector cannot tell "not a link" from "not
there" from "not allowed" without a translation at the seam, and those three
produce different records and different verdicts.

### 3. `FileInfo.LinkTarget` is removed

The struct has carried a `LinkTarget` field since the initial slice and nothing
has ever populated it. Left beside a working `Readlink`, it is a trap of exactly
the kind ADR-0016 was written about: a future collector reads `fi.LinkTarget`,
gets `""`, and concludes the path is not a link — or that its target is empty —
in code that compiles, passes review and is wrong.

Removing it is not a schema change. `system.FileInfo` never reaches a fact or a
bundle; `fact.FSRow`, `fact.CronPath` and `fact.UnitFile` are each a trimmed
copy carrying only what a check may read, because a check may not import
`internal/system` at all (CLAUDE.md rule 2).

Populating it instead was rejected: it would put a `readlink` syscall behind
every `Stat` and every `ReadDir` entry, including the shared filesystem walker,
which stats far more paths than any caller wants link targets for.

## Consequences

- **Enablement state is recoverable with no daemon and no privilege.** The
  SERVICES collector declares `CapNone`: unit directories are world-readable on
  every distribution, because `systemd --user` and every unprivileged
  `systemctl status` reads them.
- **A dangling link is reportable, and a *refused* one is distinguishable from
  it.** "The target is not there" is a FAIL; "we were not allowed to look at the
  target" is UNKNOWN. The fact carries `DestDangling` and `DestUnknown`
  separately for the same reason `fact.CronPathState` distinguishes absent from
  denied — a single boolean would have collapsed them into a guess.
- **The fixture format needed a containment rule, not a new capability.** Git
  stores symlinks natively, so unlike ADR-0013's inode overrides this is not
  something the format could not express. It is that an *absolute* target
  committed as a real link resolves against the developer's root: a fixture
  naming `/usr/lib/systemd/system/sshd.service` points at the real unit on every
  Linux workstation, and anything that follows it reads the host. The manifest's
  `symlinks` key declares the link without creating one, so nothing can follow
  it. Relative targets stay as real links and need no entry. See
  `docs/FIXTURES.md` §2.4.
- **A mode override that sets the symlink type without a target is rejected at
  fixture load.** It would make `Stat` report a symlink whose `Readlink` says it
  is not one — two seam methods contradicting each other about one inode, which
  no real filesystem does and no check should have to defend against.
- **Callers must not treat a relative target as absolute.** It names a
  completely different file, one that almost never exists, so a working
  enablement would be reported as a broken link. `services-compliant` carries a
  real relative link for this.
