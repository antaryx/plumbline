# USERS-0005 — No uid or account name is used by more than one entry

| Field | Value |
|---|---|
| **ID** | `USERS-0005` |
| **Module** | USERS |
| **Base severity** | HIGH |
| **Tags** | users, accountability, attribution |
| **Facts required** | `users.passwd` |
| **Since catalog** | 4 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every entry in `/etc/passwd` has a uid no other entry has, and a name no other
entry has.

## 2. Why it matters

Two accounts sharing a uid are the same account as far as the kernel is
concerned. They can read each other's files, signal each other's processes and
inherit each other's group memberships, while appearing in every listing as two
separate identities — which destroys attribution: an audit log recording a uid
cannot say which of the two names was responsible.

Two entries sharing a name are worse in a different way. Name resolution returns
the first match, so the second entry is **unreachable**: its uid, its shell, its
home directory and its group are all silently ignored. An administrator who
edits the second copy makes no change at all and has no way to tell.

Both states are usually accidental — a provisioning script that allocated a uid
already in use, or a file edited by two tools at once — and both are also a tidy
way to hide an account in plain sight.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/passwd`, fields 1 and 3 |
| Daemon default when unset | Not applicable |
| Reference | `passwd(5)`, `pwck(8)` |

## 4. Distribution variations

None. `pwck` reports both conditions on every distribution.

One convention is worth knowing: uid 65534 is `nobody` on Debian-family systems
and `nfsnobody` on some Red Hat-family ones, and a host that has both packages
installed can legitimately end up with two names on that uid. It is still a
finding — attribution is still lost — but it is the most common benign cause.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every uid and every name is unique | — | how many accounts were examined |
| FAIL | a uid is shared | HIGH | which uid, and which names share it |
| FAIL | a name is repeated | HIGH | the name, the line numbers, and that only the first is reachable |
| UNKNOWN | no violation found, but the file imports accounts or has unparseable lines | — | `ambiguous_system_state` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- the same completeness limits as USERS-0001. A directory service can supply an
  account whose uid collides with a local one, and this check cannot see it
- **collisions between `/etc/passwd` and a directory service** are invisible for
  the same reason, and are the more common cause on a host using LDAP
- the check does not read `/etc/group`, so a duplicated **gid** is not reported.
  That is a separate check this module does not yet have

## 7. Known false positives

The `nobody` / `nfsnobody` overlap described in §4. Deliberate uid sharing —
occasionally used to give two service names one identity — is a genuine
attribution loss and should be suppressed with a justification rather than
excused.

## 8. Remediation

| | |
|---|---|
| Summary | Give every account a unique uid and a unique name. |
| Effort | MEDIUM |
| Steps | list collisions; **record which files the account owns before changing its uid**; `usermod -u` then re-own; for a duplicated name confirm which entry was believed to be in effect before removing the other; verify with `pwck` |
| Commands | `pwck -r`, `awk -F: '{print $3}' /etc/passwd \| sort \| uniq -d` |
| **Caution** | **Required.** Changing a uid does not change ownership of files already on disk; those files become owned by whatever account now holds the old uid. Record the file list first — afterwards the old uid no longer identifies them. |

## 9. Control mappings

- `nist-800-53-r5` IA-2
- `nist-800-53-r5` IA-4
- `nist-800-53-r5` AU-6

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | all distinct | PASS |
| `users-duplicates` | `alice`/`bob` share uid 1000; `carol` appears twice | FAIL, both conditions reported |
| `users-unprivileged` | shadow unreadable, passwd readable | PASS |
