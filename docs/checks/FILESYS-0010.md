# FILESYS-0010 — Every uid and gid owning a file resolves to a local account or group

| Field | Value |
|---|---|
| **ID** | `FILESYS-0010` |
| **Module** | FILESYS |
| **Base severity** | MEDIUM |
| **Tags** | filesys, ownership, accounts, hygiene |
| **Facts required** | `fs.tally.owner_uid`, `fs.tally.owner_gid`, `users.passwd`, `users.group`, `users.nsswitch` |
| **Since catalog** | 12 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every uid that owns an inode on this filesystem appears in `/etc/passwd`, and
every gid that owns one appears in `/etc/group` — **provided** those files are
this host's whole account database, which `/etc/nsswitch.conf` decides.

## 2. Why an orphaned uid is a security finding and not untidiness

Ownership on a Unix filesystem is a number. The name is a lookup performed at
display time against a database that can change without the filesystem knowing.
Delete an account and its files keep the number; `ls -l` starts printing digits
because there is no longer a name to print.

The consequence is specific and entirely mundane: **uids are reused.** Every
distribution's `useradd` allocates the lowest free uid above `UID_MIN`. So the
next account created on this host inherits the number, and with it every file
the departed account left behind — its home directory, its crontabs, whatever
it wrote into shared areas, and anything restored later from a backup. Nobody
grants that access. Nobody sees it happen. An audit of "who can read this" that
consults the account database returns the wrong answer, because the filesystem
and the database disagree and only the filesystem is enforcing anything.

Groups are the same mechanism one level wider: a reused gid hands the new group
whatever the old one could reach.

Unowned inodes are also a durable trace of things that happened — a build that
ran in a container and wrote through a bind mount, a tarball unpacked with
`--same-owner` from a machine with different accounts, a service removed
without `--remove-home`, or an intrusion whose artefacts were written by a uid
that never had an account here at all.

## 3. Why this check needed a change to the walker

The shared walk records **rows**: the first `MaxHits` inodes matching a pure
predicate. That shape cannot answer this question, for two independent reasons:

1. `Interest.Match` is pure and is evaluated at registration time, before any
   fact exists. It cannot join against `/etc/passwd`.
2. Deferring the join by recording every owned inode as a row would overflow
   the 20,000-row cap in the first populated directory of any host that has
   users.

A uid threshold instead of a join — "anything above 1000 that is not in passwd"
— would be a guess, and CLAUDE.md rule 3 forbids guessing.

WP-25 added a second kind of registered question, the **`Tally`**. It maps each
inode to a key, counts the keys, and keeps one exemplar per key. Memory is
bounded by the number of *distinct owners*, not by the number of inodes: the
ten-millionth file owned by a known uid costs one increment and no allocation.
The join then happens in the check, where facts exist. See
`internal/collect/walker/tally.go`.

## 4. Why `/etc/nsswitch.conf` is a required fact

"This uid is not in `/etc/passwd`" is a fact about a file. "This uid belongs to
nobody" is a fact about the host. They are the same statement only when the
local files are the whole account database, and on a host joined to LDAP, SSSD,
Active Directory or `systemd-homed` they are not — accounts exist there that
`/etc/passwd` has never heard of, and their files are entirely legitimate.

A check that read `/etc/passwd` alone would report every AD user's home
directory as unowned. That is not a conservative failure; it is a flood of
confident false findings on a large fraction of enterprise Linux, and it would
train an operator to ignore this check and then the next one.

The local files are treated as authoritative for a database only when
`nsswitch.conf` was read and names **exactly one source, `files`**, for it.
Everything else is not authoritative, including three cases that look harmless:

| Configuration | Authoritative? | Why |
|---|---|---|
| `passwd: files` | yes | nothing else can resolve an identity |
| `passwd: files systemd` | **no** | `nss-systemd` resolves `DynamicUser=` allocations and `systemd-homed` records, neither of which is in `/etc/passwd`. This is the *default* line on current systemd distributions |
| `passwd: compat` | **no** | reads the file *and* whatever its `+` lines import |
| `passwd: files sss` / `ldap` / `winbind` | **no** | a directory service this offline scan cannot ask |
| database not mentioned | **no** | falls through to a glibc compiled-in default that is a property of the libc build, not of anything on disk |
| file absent, denied or unreadable | **no** | same — the effective policy is unknown, not "files" |

Two further conditions are checked on the same principle, because both mean the
local file is incomplete: NIS/LDAP compatibility (`+`) lines in `/etc/passwd`
or `/etc/group`, and lines in either file that could not be parsed.

## 5. The asymmetry: a PASS needs no opinion about the name service

**The nsswitch fact gates only the FAIL branch.** A name service can add
identities that resolve; it can never remove one that `/etc/passwd` already
resolves. So "every owner resolves locally" implies "every owner resolves" on
any host, whatever it is joined to.

This is why the check is useful rather than permanently UNKNOWN. On a healthy
directory-joined host every uid on disk *does* resolve locally, and the check
returns PASS without ever consulting the routing table. It degrades to UNKNOWN
only in the situation where the answer genuinely is unknown: something failed
to resolve, and there is somewhere else it might have come from.

`TestAPassNeedsNoNameServiceOpinion` pins this, and
`TestTheSameDiskWithADifferentNameServiceIsNotAFinding` pins its converse.

## 6. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every tallied uid is in `/etc/passwd` and every tallied gid is in `/etc/group` | — | the distinct owner counts and the inodes examined |
| FAIL | some identity does not resolve, **and** the local files are authoritative for its database | MEDIUM | each unresolved id, how many inodes it owns, one exemplar path, and that the next account created takes the number. It names **only the databases whose routing was actually examined** — a FAIL over a stray uid alone has said nothing about how `group` is routed |
| UNKNOWN | some identity does not resolve, and the local files are not the whole database | `ambiguous_system_state` | what failed to resolve **and** why the check declined — the routing table, the compat lines, or the unparsed lines |
| UNKNOWN | the walk did not finish, or a tally hit its keyspace cap | `source_truncated` | which limit fired, and how many inodes were folded into how many keys |
| UNKNOWN | a required fact was never collected | `fact_not_collected` | (produced by the runner's required-fact gate) |

`NOT_APPLICABLE` is unreachable. Every inode has an owner and a group, so the
subject of this check exists on every host that has a filesystem.

## 7. Where this check cannot know

- **whether an unresolved uid was ever an account here.** The number is all the
  filesystem kept. `lastlog`, `/var/log/auth.log` and the package manager's log
  usually name it during triage; none of them is collected.
- **whether a directory service would resolve it.** That requires a network
  round trip, and Plumbline opens no sockets. Where it is possible, the check
  returns UNKNOWN rather than pretending.
- **whether files on a mount the walk declined are unowned.** Network
  filesystems carry another host's account database; the walk does not cross
  filesystem boundaries by default, and the fact records its roots.
- **which unowned files matter.** A stale build artefact and an intruder's
  staging directory look identical from a `stat`.

## 8. Known false positives

- **Containers and bind mounts.** A container writing into a host bind mount
  uses its own uid space. Files owned by uid 100999 are an unmapped user
  namespace, not a deleted account. Fix the mapping, or suppress with the path
  recorded.
- **Restored archives.** `tar --same-owner` from a host with different accounts
  reproduces that host's numbers.
- **A host mid-migration** between local accounts and a directory service,
  where `nsswitch.conf` has not been switched over yet. This is the case most
  likely to produce a genuine false FAIL, and the remediation's caution says so
  explicitly: `getent passwd <uid>` resolving a name that `/etc/passwd` does
  not contain means the check should have returned UNKNOWN.

## 9. Remediation

| | |
|---|---|
| Summary | Find out what wrote them, then reassign or delete. **Do not create an account to match the number.** |
| Effort | MEDIUM |
| Steps | list with `find / -xdev \( -nouser -o -nogroup \) -ls` (the `-xdev` matters); establish what the number used to be; chown what still matters and delete what does not; never recreate the uid; fix the cause where it was a container or an archive; purge rather than remove where a package left a service account behind |
| Commands | `find / -xdev \( -nouser -o -nogroup \) -ls`, `getent passwd <uid>`, `chown <user>:<group> <path>` |
| **Caution** | **Required.** Never `chown -R` a tree without looking at it — a single recursive chown flattens every distinct owner under it and the previous ownership is not recoverable. And confirm the host is not directory-joined before treating this as a finding at all. |

## 10. Control mappings

- `nist-800-53-r5` AC-2
- `nist-800-53-r5` AC-3
- `nist-800-53-r5` CM-6

## 11. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | every inode owned by root, which `/etc/passwd` holds | PASS |
| `filesys-unowned` | `/var/lib/oldapp` owned by uid 4242, one file carrying gid 4242 alone; `nsswitch.conf` routes to `files` | FAIL, MEDIUM |
| `filesys-unowned-directory` | byte-for-byte the same ownership; `nsswitch.conf` routes `passwd` and `group` to `files sss` | UNKNOWN, `ambiguous_system_state` |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short by the inode budget | UNKNOWN, `source_truncated` |
| `cli-host` | a whole-scan fixture with no `/etc/nsswitch.conf` at all | PASS — the PASS branch never consults it |

The first two fixtures are a **matched pair, and the pair is the test.**
Identical disks, opposite verdicts, and the only difference between them is one
word in `/etc/nsswitch.conf`.
