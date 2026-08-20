# USERS-0002 — System accounts have no interactive login shell

| Field | Value |
|---|---|
| **ID** | `USERS-0002` |
| **Module** | USERS |
| **Base severity** | MEDIUM |
| **Tags** | users, attack-surface, lateral-movement |
| **Facts required** | `users.passwd` |
| **Since catalog** | 4 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every account with a uid between 1 and 999 has a shell that cannot open an
interactive session.

## 2. Why it matters

A system account exists to own files and run a daemon, not to be logged into.
Leaving it with a real shell turns every one of them into a potential entry
point: an attacker who obtains its credential — from a configuration file, a
backup, a compromised service — gets a session rather than an error, and from a
session they get an environment, a shell history and somewhere to run things.

Setting the shell to `nologin` or `false` costs nothing, because nothing about
running a daemon requires the ability to log in.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/passwd`, field 7 |
| Daemon default when unset | **An empty shell field is not "no shell".** The system substitutes `/bin/sh`, so an empty field is the most permissive setting in the file, not the most restrictive |
| Reference | `passwd(5)`, `nologin(8)` |

Shells treated as non-interactive: `/usr/sbin/nologin`, `/sbin/nologin`,
`/usr/bin/nologin`, `/bin/nologin`, `/bin/false`, `/usr/bin/false`,
`/dev/null`, `/bin/sync`, `/usr/bin/sync`.

`/bin/sync` is included because it runs `sync(1)` and exits: it permits a
password prompt but cannot produce a session, and the account that traditionally
uses it exists on almost every system.

**An unrecognised shell is treated as interactive.** That is the safe
direction: a FAIL an operator suppresses costs them a minute, a PASS that
silently accepted an unfamiliar login shell costs them the finding.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu | `nologin` lives at `/usr/sbin/nologin` | Not verified on live hosts |
| RHEL, SUSE | `nologin` lives at `/sbin/nologin` | Not verified on live hosts |
| RHEL 6 and older | The system-account boundary was uid 500, not 1000 | Not verified on live hosts |

**The uid boundary is an assumption, not an observation.** The real value is
`SYS_UID_MAX` in `/etc/login.defs`, which this module does not collect — that
fact belongs to the AUTH work package (WP-24). Until then the check uses 999,
states the boundary in its detail so a reader can see immediately whether it
applies, and will be refined to read the host's own value. Refining the
boundary does not change what the ID means; it makes the determination more
accurate.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every uid 1–999 account has a non-interactive shell | — | how many were considered and the boundary used |
| FAIL | at least one has an interactive shell | MEDIUM | which accounts, and for an empty field, that the system substitutes `/bin/sh` |
| NOT_APPLICABLE | no account falls in the uid 1–999 range | — | that the host has no system accounts |
| UNKNOWN | no violation found, but the file imports accounts or has unparseable lines | — | `ambiguous_system_state` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- the same two completeness limits as USERS-0001: directory imports and
  unparseable lines turn the negative result into `UNKNOWN`
- **whether the account can actually authenticate.** A system account with
  `/bin/bash` and a locked password cannot be logged into with a password, but
  can still be reached through `su` from root, through an SSH key in its
  `authorized_keys`, or by any service that switches to it. The shell is the
  control this check asserts; it is not the only one that matters
- a host whose nologin binary lives somewhere unusual — `/usr/local/sbin/nologin`
  — is reported as interactive
- accounts supplied by a directory service are not in this file

## 7. Known false positives

- Deployment tooling that runs commands as a service account through `su -` or
  `runuser` needs a working shell.
- Red Hat-family hosts predating RHEL 7, where uid 500–999 are ordinary users.
  On such a host a real person is misread as a system account.

## 8. Remediation

| | |
|---|---|
| Summary | Set the shell of every system account to `nologin`. |
| Effort | LOW |
| Steps | confirm the account needs no shell; `usermod -s` with the path that exists on this host; verify with `getent passwd`; re-run any job that used the account |
| Commands | `awk -F: '$3 >= 1 && $3 <= 999 {print $1, $7}' /etc/passwd`, `usermod -s /usr/sbin/nologin <name>` |
| **Caution** | **Required.** Jobs using `su` or `runuser` break silently — at their next run, not immediately. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` AC-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | all system accounts on `nologin`, `sync` on `/bin/sync` | PASS |
| `users-shells` | `daemon` has bash; `games` has an empty shell field | FAIL, both named |
| `users-unprivileged` | shadow unreadable, passwd readable | PASS |
