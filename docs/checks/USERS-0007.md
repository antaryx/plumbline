# USERS-0007 — Group 0 is confined to root

| Field | Value |
|---|---|
| **ID** | `USERS-0007` |
| **Module** | USERS |
| **Base severity** | HIGH |
| **Tags** | users, groups, privilege |
| **Facts required** | `users.passwd`, `users.group` |
| **Since catalog** | 5 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Three propositions, evaluated together:

1. The account named `root` has primary gid 0.
2. No account outside the system uid range has primary gid 0.
3. The gid 0 group in `/etc/group` lists no supplementary members other than
   `root`.

## 2. Why it matters

Group 0 is the group half of root's identity. Files created by root are
group-owned by gid 0 unless something says otherwise, and a great many of them
grant the group read access they deny to everyone else — `/root` itself, the
systemd unit tree, and on several distributions the parent directories of the
credential files. An ordinary account whose primary group is 0 therefore reads a
substantial part of what root reads, **without appearing in any listing of
privileged accounts and without tripping any check that looks at uid 0**. It is
the quietest of the privilege-escalation footholds in the account database.

Root's own primary group matters for the converse reason. A root account in some
other group silently changes the group ownership of everything root writes from
that moment on, which both breaks the assumption every other rule here rests on
and can widen access to files that were expected to be group-root.

The supplementary member list is the third route to the same place. A name in
the fourth field of `root:x:0:` holds gid 0 at every login, and `id` will show it
while `/etc/passwd` will not.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/passwd` field 4 (primary gid); `/etc/group` fields 3 and 4 |
| Daemon default when unset | Not applicable — both fields are mandatory |
| Reference | `passwd(5)`, `group(5)`, `usermod(8)` |

## 4. Distribution variations

**This is the reason the check is not the naive rule.** Red Hat-family
distributions ship several system accounts with primary group 0:

```
operator:x:11:0:operator:/root:/sbin/nologin
halt:x:7:0:halt:/sbin:/sbin/halt
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
sync:x:5:0:sync:/sbin:/bin/sync
```

A check phrased as "no account other than root has primary gid 0" therefore
produces four findings on a stock RHEL, CentOS, Rocky or Alma installation, none
of which an operator can act on. Plumbline reports such accounts in the PASS
detail — naming them, so the exemption is auditable — and fails only accounts
above the system uid boundary.

Debian-family systems do not ship any account in group 0 apart from root, so on
those hosts the PASS detail names nothing.

The system boundary used is uid ≤ 999 (`SystemUIDMax`). See USERS-0002 §4 for
why that constant is an assumption rather than an observation, and what it costs
on a pre-RHEL-7 host where the boundary was 500.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | all three propositions hold | — | that root holds gid 0, and any **system** accounts that also do, named, with the boundary used |
| FAIL | root's primary gid is not 0 | HIGH | the gid root actually holds |
| FAIL | an account above the system boundary has primary gid 0 | HIGH | the account name and uid |
| FAIL | the gid 0 group lists a supplementary member other than root | HIGH | the member names and the group name |
| UNKNOWN | no group in `/etc/group` holds gid 0 | `ambiguous_system_state` | that every Unix system has one |
| UNKNOWN | no account named `root` in `/etc/passwd` | `ambiguous_system_state` | that USERS-0001 reports uid 0 holders |
| UNKNOWN | no violation found, but either file imports from a directory service or has unparseable lines | `ambiguous_system_state` / `unparseable_source` | **which file** is incomplete |
| NOT_APPLICABLE | unreachable — every Linux host has both files | — | — |

Accounts holding **uid** 0 are skipped by proposition 2 deliberately: their
group is not the finding, they already are root by the only measure the kernel
applies, and USERS-0001 reports them at the severity that deserves.

## 6. Where this check cannot know

- **supplementary group memberships granted outside `/etc/group`** — SSSD, LDAP
  and `nsswitch.conf` can all place an account in gid 0, and none of them is
  visible in these two files. A `+` line in either file makes a PASS UNKNOWN for
  exactly this reason
- **what group 0 actually reaches on this host.** The check asserts membership,
  not consequence; the consequence depends on the mode bits of every root-owned
  file, which is the filesystem walker's territory, not this module's
- **`setgid` binaries owned by group 0**, which grant gid 0 for the duration of
  a process without any account being a member. That is a separate check
- whether an account with primary group 0 is *supposed* to have it. A site that
  deliberately runs a backup account in group root is making a decision this
  check cannot see the reasoning for, and should suppress it with one

## 7. Known false positives

Distribution-shipped system accounts are handled in §4 and are not failed.

Beyond those, the residual case is a site convention that puts an operations
account in group root deliberately. That is a real privilege grant and the
finding is correct about it; it should be suppressed with a justification rather
than treated as noise.

## 8. Remediation

| | |
|---|---|
| Summary | Give the account a primary group of its own and remove supplementary members from group 0. |
| Effort | MEDIUM |
| Steps | list primary members with `awk -F: '$4 == 0'` and supplementary ones with `getent group 0`; **record what the account owns before changing its group**; `groupadd` then `usermod -g`; re-own with `chgrp`; `gpasswd -d <name> root` |
| Commands | `awk -F: '$4 == 0 {print $1, $3}' /etc/passwd`, `getent group 0` |
| **Caution** | **Required.** Changing an account's primary group does not change the group ownership of files it already created; those stay gid 0 and stay readable to anything still in that group. Record the file list before the change — afterwards the account's group no longer identifies them. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` AC-3
- `nist-800-53-r5` AC-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | root in gid 0; `operator` (uid 11) also in gid 0 | PASS, `operator` named as a convention |
| `users-gid0` | root in gid 100; `eve` (uid 1001) in gid 0; `mallory` a member of the root group | FAIL, all three reported |
| `users-unprivileged` | shadow unreadable, passwd and group readable | PASS |
| `users-nis` | `/etc/group` ends in `+:::` | UNKNOWN, `ambiguous_system_state` |
| `users-malformed` | `/etc/group` has unparseable lines | UNKNOWN, `unparseable_source` |
