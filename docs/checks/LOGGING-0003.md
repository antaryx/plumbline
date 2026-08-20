# LOGGING-0003 — The systemd journal is stored persistently

| Field | Value |
|---|---|
| **ID** | `LOGGING-0003` |
| **Module** | LOGGING |
| **Base severity** | MEDIUM |
| **Tags** | logging, forensics, retention |
| **Facts required** | `logging.journald` |
| **Since catalog** | 8 |
| **Platforms** | Linux, all systemd distributions |

## 1. What is tested

The journal survives a reboot: `Storage=persistent`, or `Storage=auto` (the
default) with `/var/log/journal` present.

## 2. Why it matters

A volatile journal lives in `/run/log/journal`, a tmpfs. Every record in it is
destroyed at the next boot — and "the machine was rebooted" describes most
incidents, whether the reboot was the attacker covering their tracks, a kernel
panic they caused, or an operator restarting a host that was behaving oddly.
Investigating afterwards means investigating a host that deleted its own
evidence.

Persistence is **not** a substitute for forwarding. A persistent journal is
still a local file that root can delete; it survives a reboot, not an attacker.
LOGGING-0002 is what puts a copy beyond this host's reach.

## 3. Source of truth

| | |
|---|---|
| Source | `Storage=` under `[Journal]`, plus a stat of `/var/log/journal` |
| Daemon default when unset | **`auto`** |
| Reference | `journald.conf(5)` |

| `Storage` | Effect |
|---|---|
| `persistent` | `/var/log/journal`, created if absent; survives reboot |
| `volatile` | `/run/log/journal` only; destroyed at reboot |
| `none` | nothing is stored |
| `auto` (default) | persistent **if `/var/log/journal` already exists**, volatile otherwise |

**The stat is why this check is answerable.** `auto` is the default and its
effect is a property of the filesystem rather than of the configuration.
Without one observation of the directory, "Storage is not configured" would be
UNKNOWN on the majority of hosts — honest and useless.

**Precedence is last-wins.** systemd reads `journald.conf` first, then drop-ins
under `journald.conf.d/` in lexical order, each overriding. This is the reverse
of `sshd_config`, where the first value obtained wins, and a check that took the
first match would report the value the operator's drop-in was written to
replace. Overridden occurrences are cited as evidence so a reader who edited the
main file can see why their value is not in force.

## 4. Distribution variations

Debian and Ubuntu ship `Storage` commented out and do **not** create
`/var/log/journal`, so a stock install is volatile and fails. Fedora and RHEL
ship the directory, so `auto` resolves to persistent and a stock install passes.
The same commented-out configuration therefore produces opposite verdicts on
different distributions, which is exactly why the directory is stat'ed rather
than assumed.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | `persistent`, or `auto` with the directory present | — | how the value resolved, including the directory when `auto` |
| FAIL | `volatile` or `none` | MEDIUM | that records are destroyed at the next boot |
| FAIL | `auto` (or unset) with the directory absent | MEDIUM | that the default resolved to volatile, and why |
| NOT_APPLICABLE | no journald configuration and no journal directory | — | — |
| UNKNOWN | `auto` and the directory could not be stat'ed | `ambiguous_system_state` | that the answer depends on a directory not seen |
| UNKNOWN | an unrecognised `Storage` value | `unparseable_source` | the values journald accepts |
| UNKNOWN | the configuration could not be read | `insufficient_privileges` | which fact was unavailable |

## 6. Where this check cannot know

- **how much history the journal actually holds.** `SystemMaxUse` and
  `MaxRetentionSec` bound it, and a persistent journal capped at 10 MB on a busy
  host retains minutes. This check asserts durability across a reboot, not
  retention
- **whether `/var/log/journal` is on a filesystem that survives.** A persistent
  journal on a tmpfs mount, or on a container layer discarded at exit, is
  volatile in every way that matters
- **whether the journal has been tampered with.** FSS sealing detects that and
  requires keys this check cannot see
- **drop-ins outside `/etc`.** systemd also reads `/usr/lib/systemd/journald.conf.d`
  and `/run/systemd/journald.conf.d`; this module reads only `/etc`, so a
  vendor-supplied drop-in is not seen

## 7. Known false positives

An intentionally stateless host — an immutable image, a diskless node, a
short-lived container — where local persistence is meaningless by design. On
those, forwarding (LOGGING-0002) is the whole of the answer and this check
should be suppressed with that reasoning.

## 8. Remediation

| | |
|---|---|
| Summary | Set `Storage=persistent` and give the journal a size limit. |
| Effort | LOW |
| Steps | set it under `[Journal]`, preferably in a drop-in; **bound the size in the same change** with `SystemMaxUse=`; create the directory and restart journald; confirm with `journalctl --disk-usage` and `--list-boots` |
| Commands | `systemd-analyze cat-config systemd/journald.conf`, `journalctl --disk-usage` |
| **Caution** | **Required.** Persisting the journal starts consuming disk on a host that was not consuming any. Set `SystemMaxUse` in the same change — a full `/var` is an outage, and on many hosts it is an outage that also stops the logging you just enabled. |

## 9. Control mappings

- `nist-800-53-r5` AU-4
- `nist-800-53-r5` AU-11
- `nist-800-53-r5` AU-9

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `logging-compliant` | `Storage=persistent` | PASS |
| `logging-rsyslog-absent` | journald only, persistent | PASS |
| `logging-weak` | `Storage=volatile` | FAIL, MEDIUM |
| `logging-nodefault` | unset; `auto` with no `/var/log/journal` | FAIL, MEDIUM |
| `logging-dropin-override` | main file persistent, drop-in volatile | FAIL — the drop-in wins |
| `logging-absent` | no journald at all | NOT_APPLICABLE |
| `logging-unreadable` | configuration refused | UNKNOWN, `insufficient_privileges` |
