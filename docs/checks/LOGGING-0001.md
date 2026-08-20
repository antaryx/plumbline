# LOGGING-0001 — rsyslog creates log files unreadable by other

| Field | Value |
|---|---|
| **ID** | `LOGGING-0001` |
| **Module** | LOGGING |
| **Base severity** | MEDIUM |
| **Tags** | logging, information-disclosure, file-permissions |
| **Facts required** | `logging.rsyslog` |
| **Since catalog** | 8 |
| **Platforms** | Linux, all distributions running rsyslog |

## 1. What is tested

Every statement that sets the creation mode of rsyslog's log files leaves
`mode & 0037 == 0`: no write or execute for group, and nothing at all for
other. 0640, 0600 and 0440 pass; 0644 does not.

Both syntaxes are read — the legacy `$FileCreateMode 0640` directive and the
RainerScript `fileCreateMode="0640"` action parameter.

## 2. Why it matters

`/var/log/auth.log` and `/var/log/secure` record which accounts authenticated,
from where, and by what method. The mail and cron logs record what runs and
when. Application logs routinely carry session identifiers, tokens and query
strings that were never meant to leave the process that wrote them.

rsyslog creates these files itself with the mode its configuration specifies,
and its **built-in default is 0644** — readable by every account on the host.
An attacker with any unprivileged shell therefore starts with the
authentication history, which tells them which accounts exist, which are used,
and from which addresses a login will not look unusual.

**Group read is deliberately permitted.** Adding an operations team to an `adm`
or `systemd-journal` group is how log access is granted without root, and
failing 0640 would push hosts toward handing out root instead — a worse outcome
produced by a stricter rule.

## 3. Source of truth

| | |
|---|---|
| Source | `$FileCreateMode` directives and `fileCreateMode=` parameters across every file read |
| Daemon default when unset | **0644**, documented and stable across rsyslog 5 and later |
| Reference | rsyslog configuration documentation |

**Every occurrence is examined, not the last.** The legacy directive is
*positional*: it governs the file actions written after it. A permissive one
applies to whatever follows it regardless of what a later line sets, so a single
bad statement is a finding even where a good one appears below it.

## 4. Distribution variations

Debian and Ubuntu ship `$FileCreateMode 0640` in `/etc/rsyslog.conf`, so a stock
install of either passes. RHEL and Fedora ship no such directive, so a stock
install of either fails on the built-in default — correctly, and by vendor
default rather than by mistake.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every statement restricts group write and all access by other | — | how many statements were examined |
| FAIL | any statement grants more | MEDIUM | each statement, its file and line, its mode, and that legacy directives are positional |
| FAIL | no statement sets it | MEDIUM | that the built-in default is 0644 and other can read it |
| NOT_APPLICABLE | rsyslog is not configured on this host | — | that journald-only hosts are covered by 0003 and 0004 |
| UNKNOWN | no statement found, but an include did not resolve | `ambiguous_system_state` | which include failed |
| UNKNOWN | the configuration could not be read | `insufficient_privileges` | which fact was unavailable |

## 6. Where this check cannot know

- **the modes of files already on disk.** The setting governs files rsyslog
  creates from now on; existing files keep whatever mode they were created with
- **logrotate.** A `create` directive in `/etc/logrotate.d/` sets the mode after
  rotation and will silently reinstate 0644 at the next rotation. This module
  does not read logrotate's configuration, and it is the most common reason a
  corrected setting appears not to hold
- **per-action modes overriding a global one.** The check reports every
  statement it finds and fails on any permissive one, which is the safe
  direction, but it does not model which action each governs
- **journald's own file modes**, which are set by systemd rather than by
  configuration

## 7. Known false positives

None known. A host that deliberately publishes logs to all local users has made
a decision the finding describes correctly; suppress it with that reasoning
recorded.

## 8. Remediation

| | |
|---|---|
| Summary | Set the log file creation mode to 0640 and fix the files already on disk. |
| Effort | LOW |
| Steps | set it in whichever syntax the file already uses; **place the legacy directive above the file actions**, since it is positional; `chmod` the existing files and their rotated copies; **check logrotate's `create` directives**; restart rsyslog and confirm with `stat` |
| Commands | `grep -rEn 'FileCreateMode\|fileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/`, `stat -c '%n %a %U:%G' /var/log/*.log` |
| **Caution** | **Required.** Tightening the mode breaks anything reading logs as a non-root, non-group account: log shippers, monitoring agents and some web-facing log viewers. Add those agents to the log group rather than widening the mode back — and check logrotate, or the next rotation will undo the change without anybody noticing. |

## 9. Control mappings

- `nist-800-53-r5` AU-9
- `nist-800-53-r5` AC-6
- `nist-800-53-r5` SC-4

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `logging-compliant` | `$FileCreateMode 0640` beside RainerScript | PASS |
| `logging-legacy` | the same in legacy syntax throughout | PASS |
| `logging-weak` | `$FileCreateMode 0644` | FAIL, MEDIUM |
| `logging-nodefault` | nothing sets it; built-in 0644 applies | FAIL, MEDIUM |
| `logging-rsyslog-absent` | journald only | NOT_APPLICABLE |
| `logging-unresolved-include` | absent, include matched nothing | UNKNOWN, `ambiguous_system_state` |
| `logging-unreadable` | configuration refused | UNKNOWN, `insufficient_privileges` |
