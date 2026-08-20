# Plumbline

*Hang a line. See what's true.*

A deterministic, offline, evidence-first host security auditor for Linux.

> **Status: v0.2.0 released; v0.3.0 in progress — pre-release, no stability
> guarantees.** The catalog is the milestone: **79 checks across nine modules**
> at catalog version 12, every one with PASS and FAIL fixtures enforced in CI,
> evaluated from a single filesystem traversal and a bounded set of
> configuration reads.
>
> `findings/v1`, flag names, exit codes and check IDs are contracts from here.
> Everything in Go stays `internal/` and may change without notice (ADR-0007).
>
> Next: `docs/ROADMAP.md` v0.3 — engine maturation, then the terminal and SARIF
> renderers, `diff`, suppressions and `doctor`.

## What it checks

| Module | Checks | Reads |
|---|---|---|
| **SSHD** | 19 | `sshd_config` and its includes, `Match` block scoping |
| **KERNEL** | 16 | `/proc/sys` and the `sysctl.d` files, separately |
| **USERS** | 10 | `passwd`, `shadow`, `group`, `nsswitch.conf` — four facts, four readabilities |
| **FILESYS** | 10 | one shared traversal: setuid, world-writable, device nodes, unowned files, mount options |
| **AUTH** | 6 | the PAM stack as a graph, `pwquality.conf`, `faillock.conf` |
| **CRON** | 5 | who may write the schedule — metadata only, never a crontab |
| **LOGGING** | 5 | rsyslog in all three of its syntaxes, journald with drop-ins |
| **SERVICES** | 5 | systemd enablement recovered from symlinks |
| **NETWORK** | 3 | nftables, iptables, ufw, firewalld — configured, not loaded |

## Offline by construction

Plumbline talks to no daemon. There is no dbus connection, no `systemctl`, no
`nft list ruleset`, no `iptables -S`, and no network call of any kind — the
offline test runs a scan inside `unshare -n` and asserts it produces a
byte-identical document to an online one.

That is not asceticism; it is what makes the other properties possible:

- **Service enablement is recovered from the filesystem.** `systemctl enable`
  creates a symlink in `<target>.wants/` and nothing else — so reading those
  directories recovers exactly what `systemctl is-enabled` would report,
  without a running init system.
- **A mounted image audits like a live host.** `--root /mnt` works because
  nothing asks the kernel about itself.
- **A bundle collected months ago re-evaluates today.** There is no live state
  to have gone stale.

The cost is stated rather than hidden: this reports what is **configured**, not
what is loaded. A host with a perfect `nftables.conf` and a disabled
`nftables.service` has no firewall, and the two halves are reported by two
modules that each decline to claim the other's.

## What makes it different

Plumbline splits auditing in two. **Collectors** touch the OS and produce typed
**facts**; **checks** are pure functions from facts to **findings**. A scan
captures a portable fact bundle, and findings are derived from it.

That single decision buys things a live-evaluating scanner cannot have:

- **Re-audit the past.** Evaluate a six-month-old bundle against today's check
  catalog, offline, without touching the host.
- **Diff across time.** `plumbline diff march.plb today.plb`.
- **Separate trust domains.** Collect on a locked-down production host,
  analyse anywhere.
- **Real test coverage.** Checks run against fixture trees, so a catalog of
  hundreds of checks stays verifiable.

And it says `UNKNOWN` when it cannot tell, instead of reporting `PASS`.

Two examples of what that costs and what it buys. A filesystem walk that hits
its inode budget makes every *absence* claim resolve to `UNKNOWN` while still
reporting the setuid binary it did find — a truncated walk can invalidate a
negative result and never a positive one. And FILESYS-0010, which reports files
owned by accounts that no longer exist, reads `/etc/nsswitch.conf` first: on a
host joined to Active Directory an unresolved uid is very likely a real user
this offline scan simply cannot ask about, so the check declines rather than
accusing a correctly configured machine.

## Development

```bash
make verify      # fmt, vet, tests, architectural invariants
make test-race
```

Go 1.23+. No other tooling needed to run the tests.

## Documentation

**Start here**

| Document | Purpose |
|---|---|
| `CLAUDE.md` | Working agreement and hard rules — read before any change |
| `docs/PROJECT-BRIEF.md` | Identity, scope, non-goals, differentiation |
| `docs/ARCHITECTURE.md` | Layers, the OS seam, collection, evaluation, safety |
| `docs/GLOSSARY.md` | Vocabulary — small, disproportionately useful |

**Building**

| Document | Purpose |
|---|---|
| `docs/BUILD-RUNBOOK-v0.2.md` | Sequenced, session-sized work packages |
| `docs/DATA-MODEL.md` | Facts, findings, bundles — normative |
| `docs/CHECK-AUTHORING.md` | How to add a check |
| `docs/FIXTURES.md` | Fixture format and the test corpus |
| `docs/CLI-SPEC.md` | Commands, flags, precedence, exit codes |
| `schema/findings-v1.schema.json` | The public API |
| `schema/bundle-v1.schema.json` | Bundle manifest |

**Policy**

| Document | Purpose |
|---|---|
| `docs/THREAT-MODEL.md` | Plumbline's own attack surface — gates running as root |
| `docs/COMPLIANCE-DATA-POLICY.md` | What may and may not be shipped |
| `docs/VERSIONING.md` | Four version numbers and their contracts |
| `docs/DEPLOYMENT.md` | Build, sign, publish, install, upgrade |
| `docs/ROADMAP.md` | Three stable majors |
| `docs/adr/` | Decisions that would be expensive to reverse |
| `LEGAL-DISCLAIMER.md` | Evidence, not conclusions |

**Background**

`docs/audit/argus-design-audit.md` — the audit of the predecessor design that
produced this project. Useful context for why several things are the way they
are.

## Reference implementation

`internal/collect/collectors/sshd/sshd.go` and
`internal/catalog/checks/sshd/sshd0002.go`, with nine fixtures under
`testdata/fixtures/`. Deliberately over-commented. Copy their shape.

For a module that reads the filesystem rather than a config file, copy
`internal/catalog/checks/filesys/` instead — in particular `mustBeComplete`,
which is where the asymmetric truncation rule is applied.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
