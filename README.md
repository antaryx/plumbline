# Plumbline

*Hang a line. See what's true.*

A deterministic, offline, evidence-first host security auditor for Linux.

> **Status: v0.3.0 — pre-release, no stability guarantees.** **79 checks across
> nine modules** at catalog version 13, every one with PASS and FAIL fixtures
> enforced in CI, evaluated from a single filesystem traversal and a bounded
> set of configuration reads.
>
> `findings/v1`, flag names, exit codes and check IDs are contracts from here.
> Everything in Go stays `internal/` and may change without notice (ADR-0007).
>
> Next: `docs/ROADMAP.md` v0.4.0, which carries feature freeze — suppressions
> first, then `plumbline diff`, then the commands that make the catalog legible
> without reading Go.

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

## Using it

```bash
plumbline scan                        # audit this host, human-readable report
plumbline scan --root /mnt/image      # audit a mounted image or container filesystem
plumbline scan --save-bundle host.plb # keep the evidence this scan used
plumbline collect -o host.plb         # capture the evidence, evaluate it elsewhere
plumbline eval host.plb               # re-evaluate a bundle against today's catalog
plumbline diff march.plb today.plb    # what changed between two scans
plumbline explain FILESYS-0010        # read one catalog entry in full
plumbline profiles                    # list the built-in baselines
```

**`.plb` is an evidence bundle — the facts observed.** `eval` and `diff` take
one. A findings document (`--json > out.json`) holds verdicts already drawn
from those facts and cannot be re-evaluated or diffed; hand one to `eval` or
`diff` and it says so, and tells you which flag writes the file it wanted.

The default output is a report for a person:

```
plumbline 1.0.0-rc1   catalog 13

  host     auditbox   Debian GNU/Linux 12 (bookworm)
  root     /  (live host)
  started  2026-08-20 09:14:02 UTC   elapsed 3.1s
  euid     0  (root)
  profile  default

[+] CRON  · 5 checks, 1 failing
  - The system crontab is owned by root and writable only by root       [ OK ]
  - The cron drop-in directories are owned by root and writable o…      [ OK ]
  - Access to crontab is restricted by an allow list               [ WARNING ]
  - The cron access-control files are owned by root and writable …      [ OK ]
  - The cron schedule is not readable by unprivileged accounts          [ OK ]

[+] FILESYS  · 10 checks, 1 unknown
  - No setuid or setgid executable is writable by group or other        [ OK ]
  …
  - Every uid and gid owning a file resolves to a local account o… [ UNKNOWN ]

[=] Warnings and suggestions
──────────────────────────────────────────────────────────────────────────────

  Warnings (1)  ·  a check read the value and it does not meet the requirement

  * Access to crontab is restricted by an allow list [CRON-0003]
      - Severity  : HIGH
      - Subject   : /etc/cron.deny
      - Detail    : Access is governed by /etc/cron.deny, which fails open:
                    every account not named in it may schedule jobs, including
                    accounts created after the file was last edited.
      - Evidence  : /etc/cron.deny
                    file: mode 0644, uid 0, gid 0
      - Remedy    : Replace cron.deny with a cron.allow naming the accounts
                    that need cron.
      - Effort    : LOW

  Could not determine (1)  ·  these are not passes

  Each one is a question this scan could not answer, with the reason it
  could not. Treat them as findings until they are resolved.

  * Every uid and gid owning a file resolves to a local accoun… [FILESYS-0010]
      - Severity  : MEDIUM
      - Reason    : ambiguous_system_state
      - Subject   : /etc/nsswitch.conf
      - Detail    : 2 owners on this filesystem do not resolve in the local
                    files — uid 4242 owns 3 inodes (for example
                    /var/lib/oldapp) — but the local files are not this host's
                    whole account database: /etc/nsswitch.conf routes "passwd"
                    to files, sss. An identity absent from /etc/passwd may
                    still be a real account served from somewhere this scan
                    cannot ask, because Plumbline never opens a network socket.

[=] Scan summary
──────────────────────────────────────────────────────────────────────────────

  ╭──────────────────────────────────────────────────────────────────────────╮
  │ posture   97.2   coverage 98.7% of applicable checks                     │
  │ ████████████████████████████████████████████████████████████████████░░░░ │
  ╰──────────────────────────────────────────────────────────────────────────╯

  ╭────────────────╮ ╭────────────────╮ ╭────────────────╮ ╭────────────────╮
  │ PASS           │ │ FAIL           │ │ UNKNOWN        │ │ SKIPPED        │
  │ 73             │ │ 1              │ │ 1              │ │ 0              │
  │                │ │                │ │ not passes     │ │                │
  ╰────────────────╯ ╰────────────────╯ ╰────────────────╯ ╰────────────────╯
    NOT_APPLICABLE   4   the subject is not on this host
    UNKNOWN is not a pass; the scan could not tell

  79 checks evaluated · catalog 13
```

The bar and the boxes are drawn at a fixed 78 columns, never from `$COLUMNS`,
so two scans of an unchanged host stay byte-identical and a nightly diff shows
nothing. With colour off the boxes are still drawn and nothing is painted —
losing the colour is the degradation, losing the layout is not.

`FAIL` is red, `PASS` green, `UNKNOWN` yellow. Colour is suppressed by
`--no-color`, by `NO_COLOR` in the environment, when stdout is not a terminal,
and always when writing to `--output`.

Collection is the slow part, so while it runs there is a transient indicator on
**stderr** — never stdout, so it cannot reach a findings document:

```
⠹ Collecting host evidence (12s)
```

It erases itself before the report starts, and is drawn only when stderr is a
terminal, `TERM` is set and is not `dumb`, `PLUMBLINE_NO_PROGRESS` is unset, and
no CI marker is in the environment. The elapsed time appears after three
seconds, because "0s" answers nothing and "47s" distinguishes a large
filesystem from a wedged one.

Ctrl-C stops a scan and exits **130**. An interrupted run writes no findings
document and no bundle — not even with `--save-bundle`. A bundle assembled from
half a collection carries no mark saying so, and would re-evaluate months later
to a posture score drawn from half a host. A second Ctrl-C terminates
immediately.

**For pipelines, ask for JSON:**

```bash
plumbline scan --json | jq '.findings[] | select(.result == "FAIL")'
plumbline scan --format json -o findings.json
plumbline scan --fail-on high            # exit 2; the format does not move the exit code
```

**For GitHub Advanced Security, ask for SARIF:**

```bash
plumbline scan --format sarif -o plumbline.sarif
```

SARIF 2.1.0. `UNKNOWN` becomes a `warning` rather than an informational
`none` — a check that could not tell is not a check that passed, and a security
tab that says otherwise is worse than no security tab. Accepted risks
(`--suppress`) arrive as SARIF suppressions with their justification, so a
dismissal in GitHub carries the reason a human wrote. `PASS` and
`NOT_APPLICABLE` are counted in the run's invocation rather than emitted as
results, because seventy-four passing checks bury the three that matter. The
full mapping is `docs/adr/0018-sarif-mapping.md`.

**Scope the audit to a baseline:**

```bash
plumbline profiles                   # what this binary carries
plumbline scan --profile cis-l1      # score against that baseline only
plumbline scan --profile ./mine.json # or your own
```

A profile declares which checks apply to this class of host. Checks outside it
are reported as `SKIPPED` — never omitted — and **leave the posture
denominator**, so a thirty-check baseline reports coverage against thirty
checks rather than looking like a poorly covered scan.

`cis-l1` is a Level 1 hardening baseline and **not a CIS benchmark**: no check
here carries a CIS mapping, so the selection is this project's reading of the
themes, not a claim of correspondence. Passing it is evidence of sensible
hardening, not of compliance.

**Read the catalog from your terminal:**

```bash
plumbline explain FILESYS-0010
```

Prints what the check tests and why, which facts it reads, and the remediation
with every step and command — the procedure the scan report deliberately
summarises. No host, no bundle, no privileges. The ID is case-insensitive.

**Suppress an accepted risk, without hiding it:**

```bash
plumbline scan --suppress accepted.json
```

A suppressed finding becomes `SKIPPED`, keeps its severity, detail and
evidence, records what it *would* have said, and appears under
`[=] Accepted risks` with the justification. There is no auto-discovered
filename: an explicit path is the deterministic choice for a tool that decides
whether a host is safe.

`findings/v1` is the public API and is schema-validated in CI. **The terminal
report is not** — its layout may change in a patch release, so nothing should
parse it. That is the whole reason there are two renderers rather than one with
a flag.

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

That is load-bearing on damaged hosts, which is where scanners are least
trustworthy and least tested. Point Plumbline at a machine whose configuration
files are four kilobytes of random bytes each — a failed restore, a filesystem
that lost its journal — and it names every file it could not parse and refuses
to draw a verdict from any of them. It does not report that root login is
disabled because the corrupted `sshd_config` "does not set" the keyword.

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

Go 1.24 is the floor `go.mod` states; CI builds the release binaries with
1.25, because Go supports only its two newest majors and this binary runs as
root. No other tooling is needed to run the tests.

`make golden-diff` reports whether any of the six recorded distribution bundles
under `testdata/bundles/` has changed its verdicts — run it after touching the
catalog, and read `testdata/bundles/README.md` before regenerating anything.

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
