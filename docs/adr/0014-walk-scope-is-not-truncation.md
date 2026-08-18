# ADR-0014 — Declared scope is not truncation, and a partial walk returns facts

**Status:** accepted · **Date:** 2026-08-19

## Context

The shared filesystem walker (WP-15) governs what every filesystem check in
v0.2 may conclude. The rule it enforces is asymmetric:

> A truncated walk can invalidate a *negative* result. It can never invalidate
> a *positive* one.

Implementing it surfaced two decisions the runbook does not settle, both of
which decide whether the resulting findings are useful or noise.

**First: does declining to walk something count as truncation?** The walk
declines in two situations that are not failures. It does not cross a
filesystem boundary unless asked to, and it never descends into a filesystem
type on the skip list — `proc`, `sysfs`, `nfs*`, `fuse.*` and the rest. If
those set the truncation marker, then every ordinary host with a separate
`/home` and a mounted `/proc` reports `UNKNOWN(source_truncated)` for every
filesystem check, forever. An UNKNOWN that fires everywhere is an UNKNOWN
nobody reads, and a tool whose honest answer is indistinguishable from its
broken one has not been honest, it has been useless.

**Second: what does the collector return when it runs out of time?** The
collection runner discards the partial output of a collector it had to abandon,
and of one that returns an error under a fired deadline. That is right for a
collector that cannot describe its own incompleteness: half a parsed
`sshd_config` is a lie. But the walker *can* describe it, and the thing being
discarded is a SUID binary it actually found.

## Decision

**Scope is recorded, truncation is marked, and they are different things.**

A boundary declined and a skipped filesystem type are *scope*: the walk states
its roots in every fact and never claimed to cover anything else. They increment
a counter and do not set the truncation marker.

A depth limit, an inode budget, a wall-clock budget, an unreadable directory
and an incomplete directory listing are *truncation*: the walk intended to look
and could not. They set the marker on every fact the traversal produced, because
a limit is a property of the traversal. `MaxHits` is the one per-interest case,
and it marks only its own fact — which is the whole reason there is one fact per
interest rather than one fact holding everything.

Breaking a cycle is neither. Everything inside a directory reached twice was
enumerated under its other path, so absence is still safe to conclude; it is
deduplication that happens to also terminate the walk.

**A walk that ran out of time returns its facts with the marker set, and the
collector returns `nil`.** The walker's own wall-clock budget is deliberately
shorter than the timeout it declares to the runner. The gap is what buys the
time to write the facts out: stopping voluntarily inside our own budget means
the facts survive with a truncation marker, while being killed by the runner's
deadline means everything the walk found is thrown away.

When the mount table itself cannot be read, the fstype skip list cannot be
applied. With crossing off that is survivable — the device check alone keeps
the walk on the filesystem it started on. With crossing on it is not, so the
walk declines to cross and marks the facts `mounts_unknown` rather than
stepping blindly into what might be a dead NFS server.

## Consequences

- Filesystem checks return `PASS` on an ordinary host with an ordinary mount
  layout, and `UNKNOWN(source_truncated)` when something genuinely went
  unexamined. The distinction survives contact with real machines
- A finding's scope is only as wide as the walk's roots, and a reader has to
  consult `Roots` to know what was covered. The facts carry it, and the FILESYS
  module's findings must say so in their detail text — a `PASS` that means "no
  SUID binaries on the root filesystem" must not read as "none anywhere"
- The walker is the one collector whose partial output is trusted. That is a
  privilege earned by the truncation marker, and any future collector wanting
  the same treatment has to earn it the same way. A collector that returns
  partial facts without a marker is a bug of the worst class this project has
- `fact.FSMatches.Complete()` is the mechanised form of the rule, and a check
  asserting absence must gate on it before returning `PASS`. It is a method
  rather than a convention because conventions are what get forgotten in the
  ninth module at the end of a long afternoon
