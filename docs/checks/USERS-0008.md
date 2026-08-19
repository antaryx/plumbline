# USERS-0008 — No gid or group name is used by more than one entry

| Field | Value |
|---|---|
| **ID** | `USERS-0008` |
| **Module** | USERS |
| **Base severity** | MEDIUM |
| **Tags** | users, groups, attribution |
| **Facts required** | `users.group` |
| **Since catalog** | 5 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every entry in `/etc/group` has a gid no other entry has, and a name no other
entry has.

## 2. Why it matters

Two groups sharing a gid are one group to the kernel. Permissions are enforced
against the numeric gid and never the name, so granting somebody membership of
`developers` also grants them everything the other group holding that gid can
reach — and nothing in either group's definition says so. Read in the other
direction, a gid in an audit trail or a directory listing no longer identifies
which group was meant.

Two entries sharing a name fail differently. Group resolution returns the first
match, so the second entry is **unreachable**: its gid and its member list are
silently ignored. An administrator who adds a user to the second copy has made
no change at all, and `getent group <name>` will confirm the first entry's
contents back to them with no indication that another exists.

This is USERS-0005 for the group database, and it is one severity lower for one
reason: a duplicate gid widens file access, while a duplicate uid also merges
two authentication identities.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/group`, fields 1 and 3 |
| Daemon default when unset | Not applicable |
| Reference | `group(5)`, `grpck(8)` |

## 4. Distribution variations

None in the rule. `grpck` reports both conditions everywhere.

Two benign causes are common enough to recognise. Debian-family systems ship
`nogroup` at gid 65534 while some Red Hat-family packages create `nfsnobody` at
the same gid, and a host with both installed legitimately ends up with two names
on it. Separately, a package postinstall that hard-codes a gid can collide with
one `groupadd` allocated dynamically on an earlier install. Both are still
findings — the access merge is real either way — but they are what you will
usually find.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every gid and every name is unique | — | how many groups were examined |
| FAIL | a gid is shared | MEDIUM | which gid, and which names share it |
| FAIL | a name is repeated | MEDIUM | the name, the line numbers, and that only the first is reachable |
| UNKNOWN | no violation found, but the file imports groups or has unparseable lines | `ambiguous_system_state` / `unparseable_source` | which condition, and the line numbers |
| NOT_APPLICABLE | unreachable — every Linux host has `/etc/group` | — | — |

## 6. Where this check cannot know

- **collisions between `/etc/group` and a directory service.** A `+` line makes
  a negative verdict UNKNOWN for this reason, but a host resolving groups
  through `nsswitch.conf` and SSSD has no `+` line and no visible marker at all;
  this check sees only the local file
- **which of two colliding entries is the one in force for a given lookup.** For
  a name it is the first, deterministically; for a gid there is no answer,
  because both names resolve and both grant the same access
- **what the shared gid actually reaches.** As with USERS-0007, membership is
  asserted here and consequence is a property of the filesystem

## 7. Known false positives

The `nogroup` / `nfsnobody` overlap in §4. A deliberately shared gid — used
occasionally to let two service names address one set of files — is a real
merge of access and should be suppressed with a justification rather than
excused.

## 8. Remediation

| | |
|---|---|
| Summary | Give every group a unique gid and a unique name. |
| Effort | MEDIUM |
| Steps | list collisions with `awk`/`uniq -d`; **record which files carry the gid before changing it**; `groupmod -g` then `chgrp`; for a duplicated name check with `getent group` which entry is in force before removing the other; verify with `grpck` |
| Commands | `grpck -r`, `awk -F: '{print $3}' /etc/group \| sort \| uniq -d` |
| **Caution** | **Required.** Changing a gid does not change the group ownership of files already on disk; those files become owned by whatever group now holds the old gid, which can silently *widen* rather than narrow access. Record the file list first. |

## 9. Control mappings

- `nist-800-53-r5` AC-3
- `nist-800-53-r5` AC-6
- `nist-800-53-r5` AU-6

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | all distinct | PASS |
| `users-duplicates` | `staff`/`oldstaff` share gid 50; `dev` appears twice | FAIL, both conditions reported |
| `users-unprivileged` | shadow unreadable, group readable | PASS |
| `users-nis` | `/etc/group` ends in `+:::` | UNKNOWN, `ambiguous_system_state` |
| `users-malformed` | `/etc/group` has unparseable lines | UNKNOWN, `unparseable_source` |
