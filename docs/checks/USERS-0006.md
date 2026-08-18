# USERS-0006 — The account database contains no legacy NIS import entries

| Field | Value |
|---|---|
| **ID** | `USERS-0006` |
| **Module** | USERS |
| **Base severity** | HIGH |
| **Tags** | users, authentication, legacy, attack-surface |
| **Facts required** | `users.passwd` |
| **Since catalog** | 4 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No line in `/etc/passwd` has a first field beginning with `+` or `-`.

## 2. Why it matters

A line whose first field begins with `+` is NIS compatibility syntax: it tells
glibc to pull accounts from a directory service and merge them into the local
database. A bare `+::::::` imports **every** account NIS offers, with whatever
uid, shell and group the directory says — including, if the directory is
compromised or spoofed, uid 0.

NIS transmits its maps without authentication or encryption and its successor,
NIS+, was withdrawn. Where a host genuinely needs directory accounts, that is
what `nsswitch.conf` and SSSD are for; a `+` line is a mechanism from an era
when the network was assumed to be trustworthy.

**The entry also changes what every other check in this module can conclude.**
Once accounts arrive from somewhere this scan cannot read, "no account has uid
0" becomes a statement about a list that is explicitly not the whole list —
which is why USERS-0001, 0002, 0003, 0004 and 0005 resolve to `UNKNOWN` when
one of these is present rather than reporting a PASS they cannot support.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/passwd`, first field |
| Daemon default when unset | Not applicable |
| Reference | `nsswitch.conf(5)`, `passwd(5)` |

Forms recognised: `+` (all accounts), `+name` (one account), `+@netgroup` (a
netgroup), and the `-` forms that exclude rather than include. All are
recorded; all indicate the compat backend is in play.

## 4. Distribution variations

The entries are only honoured when `nsswitch.conf` selects the `compat`
backend for `passwd`. Debian-family systems historically shipped `compat`;
most current distributions ship `files systemd`. **A `+` line on a host using
the `files` backend is inert** — but it is inert only until somebody changes
one word in `nsswitch.conf`, and this check does not read that file, so it
reports the entry either way. §7 covers the consequence.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | no compatibility entries | — | that every account the file defines is defined locally |
| FAIL | one or more compatibility entries | HIGH | each entry with its line number, that the protocol is unauthenticated, and that other checks over this file are limited to local accounts |
| SKIPPED | runner-decided | — | — |

This check has no `UNKNOWN` path. It reports the presence of the entries
themselves, which is a positive observation over the lines it read — a compat
entry we found is a compat entry, and an unparseable line elsewhere in the file
does not change that.

## 6. Where this check cannot know

- **whether the entries are actually honoured.** That depends on
  `nsswitch.conf`, which this module does not collect. The check reports the
  entry, not its effect
- whether the host uses a directory service through a *modern* mechanism. SSSD
  and LDAP configured through `nsswitch.conf` leave no trace in `/etc/passwd`
  and are invisible here — and they are the recommended replacement, so their
  absence from this check is correct
- `/etc/group` and `/etc/shadow` have the same compat syntax. This check reads
  only `/etc/passwd`

## 7. Known false positives

A host with `+` lines left over from a decommissioned NIS deployment, whose
`nsswitch.conf` no longer selects `compat`. The entries do nothing today. They
are still worth removing — they are one word away from doing something again —
but a host that has verified and pinned its `nsswitch.conf` may reasonably
suppress with a justification.

## 8. Remediation

| | |
|---|---|
| Summary | Remove the compatibility entries and configure directory accounts through `nsswitch.conf`. |
| Effort | MEDIUM |
| Steps | determine whether NIS is actually in use (`ypwhich`, `grep compat /etc/nsswitch.conf`); if not, remove the lines; if directory accounts are needed, migrate to SSSD or LDAP first and confirm `getent passwd` still resolves them; remove the `+` lines last |
| Commands | `grep -n '^[+-]' /etc/passwd /etc/group`, `getent passwd <name>` |
| **Caution** | **Required.** On a host really using NIS, removing the entries makes every directory account stop resolving, locking out everyone who is not a local user. Verify the replacement first and keep a local root session open. |

## 9. Control mappings

- `nist-800-53-r5` IA-2
- `nist-800-53-r5` IA-5
- `nist-800-53-r5` SC-8

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | no compat entries | PASS |
| `users-nis` | `+@engineering` and a bare `+` | FAIL, both named with line numbers |
| `users-unprivileged` | shadow unreadable, passwd readable | PASS |
