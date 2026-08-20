# USERS-0001 — Only the root account has uid 0

| Field | Value |
|---|---|
| **ID** | `USERS-0001` |
| **Module** | USERS |
| **Base severity** | CRITICAL |
| **Tags** | users, privilege-escalation, persistence |
| **Facts required** | `users.passwd` |
| **Since catalog** | 4 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Exactly one entry in `/etc/passwd` holds uid 0, and its name is `root`.

## 2. Why it matters

The kernel grants privilege by uid, not by name. An account called `backup`
with uid 0 **is** root — it can read every file, load kernel modules and change
any password — and nothing in the shell prompt, the process list or the audit
log distinguishes it from the real thing.

A second uid 0 account is one of the quietest persistence mechanisms available
to an attacker. It survives password changes to root, it is not listed by tools
that enumerate "the root account", and on a busy host nobody reads
`/etc/passwd`. It is also occasionally created deliberately, by an
administrator who wanted a personal root login and did not realise sudo already
provided one with an audit trail.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/passwd`, field 3 |
| Daemon default when unset | Not applicable — the file always exists and always has a uid 0 entry on a working system |
| Reference | `passwd(5)` |

## 4. Distribution variations

None. The uid 0 convention predates every current distribution. Some appliance
images ship an additional uid 0 account (`toor` on BSD-derived layouts, vendor
support accounts on network appliances) and that is precisely what this check
is for.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | exactly one uid 0 entry, named `root` | — | that uid 0 is held by root alone |
| FAIL | an entry other than `root` holds uid 0 | CRITICAL | every such account by name, and that the kernel does not distinguish it from root |
| FAIL | `root` appears on several lines, all uid 0 | CRITICAL | that only the first is reachable, so the later entries' settings are not in force |
| UNKNOWN | no entry holds uid 0 | — | `ambiguous_system_state` |
| UNKNOWN | no violation found, but the file imports accounts or has unparseable lines | — | `ambiguous_system_state` |
| SKIPPED | runner-decided | — | — |

**The positive result is not weakened by an incomplete file.** An account we
read with uid 0 has uid 0, whether or not other accounts are imported from a
directory service. Only the negative claim — "no other account has uid 0" —
needs the whole list. Same asymmetry as ADR-0014.

## 6. Where this check cannot know

- **NIS/LDAP compatibility entries.** A `+` line imports accounts from a
  directory service; those accounts are not in this file and one of them may
  hold uid 0. The negative result becomes `UNKNOWN`. USERS-0006 reports the
  entries themselves
- **Unparseable lines.** A line we could not read could have held a uid 0
  account. The negative result becomes `UNKNOWN`
- accounts supplied through `nsswitch.conf` by SSSD, LDAP or systemd-homed are
  not in `/etc/passwd` at all and are invisible to this check. `getent passwd`
  would show them; reading it needs an exec and is a different design
- the check says nothing about **sudo**. An account with uid 1000 and
  unrestricted `NOPASSWD: ALL` is equivalent to root in practice, and belongs
  to a check over `/etc/sudoers` that this module does not yet have

## 7. Known false positives

Deliberate secondary root accounts, most often on appliances and in recovery
images. They are a real risk and the right response is a suppression carrying
the justification, not a softer check.

## 8. Remediation

| | |
|---|---|
| Summary | Give every account other than root a unique non-zero uid, or remove it. |
| Effort | MEDIUM |
| Steps | identify the account's purpose; replace it with sudo where it exists for human access; reallocate the uid and re-own its files; treat an unexplained one as a compromise indicator |
| Commands | `awk -F: '$3 == 0 {print $1}' /etc/passwd`, `lastlog -u <name>` |
| **Caution** | **Required.** Changing root's own uid, or removing the account a running service authenticates as, breaks the host. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` AC-2
- `nist-800-53-r5` IA-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | one uid 0, named root | PASS |
| `users-uid0` | `backup` also holds uid 0 | FAIL |
| `users-nis` | file imports accounts from NIS | UNKNOWN(`ambiguous_system_state`) |
| `users-malformed` | unparseable lines present | UNKNOWN(`ambiguous_system_state`) |
| `users-unprivileged` | shadow unreadable, passwd readable | PASS — this check does not need shadow |
