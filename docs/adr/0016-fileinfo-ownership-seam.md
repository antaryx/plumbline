# ADR-0016 — `FileInfo.UID` and `GID` are a verdict input, and a check must gate on state before reading them

**Status:** accepted · **Date:** 2026-08-19

## Context

`BUILD-RUNBOOK-v0.2.md` WP-19 anticipated that the CRON module would need the
seam extended with file ownership:

> To evaluate CRON security (e.g. verifying `/etc/crontab` is owned by root and
> `cron.allow` exists), the checks need file ownership data.

**The fields were already there.** `system.FileInfo` has carried `UID` and
`GID` as `uint32` since the initial vertical slice, and both implementations
already populate them — `live` from `syscall.Stat_t` in `infoFor`, `fake` from
the fixture manifest's `owners` map. They were added alongside `Dev` and `Ino`
(ADR-0012) for the shared filesystem walker, which needs an owner to decide
whether a world-writable file matters.

So this ADR does not record a seam change. It records the change in what those
fields are *for*, which is the part that carries obligations. Until WP-19 no
check read them: the walker recorded ownership into a fact and no check turned
it into a verdict. CRON-0001, CRON-0002 and CRON-0004 are the first checks
whose PASS or FAIL rests directly on a uid comparison, and that promotion from
recorded metadata to load-bearing input surfaces three problems that were
harmless while nothing depended on the answer.

## Decision

### 1. Ownership stays flattened integers, and no check learns what a uid means

`UID` and `GID` are numbers. Nothing outside `internal/system` may import
`syscall`, `os/user`, or anything else that resolves a number to a name — that
is the seam rule (CLAUDE.md rule 1), and it is also correct on the merits:
resolving a uid means reading `/etc/passwd` **as it exists during the scan**,
which is a different question from what it contained when the file was created,
and on a bundle evaluated later it is a different host's `/etc/passwd`
entirely.

A check that wants to say "owned by root" compares against `0`. A check that
wants to name the account joins against the `users.passwd` fact, which is a
recorded observation with its own provenance rather than a live lookup. The
CRON module does the first and not the second: its findings say "uid 1001", not
"uid 1001 (deploy)", because the mapping is a separate fact and pretending
otherwise would put an unsourced claim in a finding.

### 2. Zero is a legitimate value, so it cannot double as "not recorded"

`Dev` and `Ino` use zero as a sentinel and say so — inode 0 is not a valid
inode. **Ownership cannot do that.** uid 0 is the single most important value
the field takes, and it is exactly the value a check tests for. A missing
ownership record that decoded as 0 would read as "owned by root", which is the
answer that turns a FAIL into a PASS.

Three places could produce an unrecorded zero: a bundle written before a fact
carried ownership, a fixture whose manifest names no `owners` entry, and a
platform where `Stat().Sys()` is not a `*syscall.Stat_t`. None of them is
hypothetical over the life of a bundle format.

The decision is therefore that **ownership is only meaningful alongside an
explicit state**, and the state lives in the fact rather than in `FileInfo`.
`fact.CronPath.State` is `observed`, `absent`, `denied` or `error`, and `UID`,
`GID` and `Mode` mean nothing unless it is `observed`. A check reads the state
first; the module's helpers (`observed`, `unknownIfUnreadable`) make that the
path of least resistance rather than a discipline to remember.

This is the same shape as `fact.SysctlState` in the KERNEL module and
`fact.ShadowEntry`'s pointer-typed aging fields (WP-17): where a zero value is
indistinguishable from an absent one and the difference decides a verdict, the
fact carries the distinction explicitly instead of relying on a sentinel.

### 3. A refused stat is UNKNOWN, and it needed a new fixture mechanism

Ownership can be unobservable. A parent directory without execute permission
defeats `stat` entirely: not the mode, not the owner, not whether the path
exists. That is a real state on an unprivileged scan and it must produce
UNKNOWN, never a verdict drawn from the paths that happened to be reachable.

The `fake` could not express it. Its `unreadable` manifest key defeats
`ReadFile` and `ReadDir` only — which is *faithful*, because a file at mode
0640 that you do not own is unreadable and perfectly stat-able; `stat
/etc/shadow` succeeds for any user. Folding stat-denial into `unreadable` would
have made every unreadable-file fixture also claim its ownership was unknown,
which is not what such a host looks like.

`unstattable` was added as a separate key, modelling the real cause: a parent
directory that refuses traversal. See `docs/FIXTURES.md` §2.

## Consequences

- Ownership-based checks are testable from fixtures, including the refused
  case, without root and without a mount namespace.
- **Checks evaluated against CLI-level fixtures cannot assert root ownership.**
  `scan --root testdata/fixtures/...` runs the *live* seam, so those files
  carry the ownership of whoever checked the repository out, and git cannot
  record ownership. `cli-host` therefore fails the CRON ownership checks
  permanently and by construction. This is why `cmd/plumbline`'s offline test
  compares an offline scan against an online one rather than asserting every
  finding passes, and why `cli-host` is documented as a checkout baseline
  rather than a clean host.
- A future fact carrying ownership must carry a state beside it. Adding `UID`
  to a fact without one would reintroduce the zero-means-root ambiguity, and
  nothing mechanical prevents it — this ADR is the record that it was decided
  rather than overlooked.
- Name resolution stays out of scope. A finding that wants to say "deploy"
  rather than "uid 1001" needs the `users.passwd` fact joined in deliberately,
  with the provenance that implies.
