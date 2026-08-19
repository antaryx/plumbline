# FILESYS-0003 — No file is world-writable

| Field | Value |
|---|---|
| **ID** | `FILESYS-0003` |
| **Module** | FILESYS |
| **Base severity** | HIGH |
| **Tags** | filesys, permissions, integrity |
| **Facts required** | `fs.world_writable` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No non-directory, non-symlink inode has the other-write bit (`mode & 0o002`).

## 2. Who "world" actually is

The word misleads. A world-writable file is not writable by "anyone on the
internet" — it is writable by **every account on the host**, and the accounts
that matter are the ones nobody thinks of as users.

An attacker who reaches a web server running as `www-data` has not got a shell
as a person. They have got one as a service account, and every world-writable
file on the host is now theirs to change. What that is worth depends on the
file: a world-writable shell script root runs from cron is root; a
world-writable configuration file is whatever the daemon reading it will do; a
world-writable log is an audit trail somebody else edits.

None of it needs an exploit. **The permission is the grant.**

## 3. Symlinks are excluded, and the exclusion is load-bearing

A symlink's own mode is `lrwxrwxrwx` on Linux and the kernel **ignores it
entirely** — access is decided by the target. Including symlinks would report
thousands of false findings on a stock host and bury the real ones among them.

`filesys-world-writable` carries a symlink for exactly this reason: the fixture
proves the exclusion holds rather than leaving it as a comment.

## 4. Directories are somebody else's question

A world-writable **directory** is a different exposure with a different remedy —
`/tmp` is world-writable by design and correct. FILESYS-0004 asks whether such a
directory has the sticky bit; FILESYS-0005 asks whether it should be
world-writable at all. This check covers files only.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | no world-writable file found | — | how many inodes were examined |
| FAIL | one or more found | HIGH | each path, and **that service accounts are the real audience** |
| UNKNOWN | the walk did not finish | `source_truncated` | which limit fired |

## 6. Where this check cannot know

- **whether the file has already been changed.** The mode records who may
  write, not who did
- **what the file is for.** A world-writable lock file or spool may be
  deliberate; the check reports the permission and the operator judges
- **ACLs**, which are not read
- **whether the containing directory is world-writable**, which lets anyone
  replace the file regardless of the file's own mode — that is FILESYS-0004
  and FILESYS-0005, and it means fixing the file alone can be insufficient

## 7. Known false positives

Applications that genuinely expect a shared writable file — some lock files,
spools and socket paths. Removing the permission can break them under load or
at the next restart, which is why the remediation says to identify the writer
and use a group rather than simply stripping the bit.

## 8. Remediation

| | |
|---|---|
| Summary | Remove world write, after establishing which account was supposed to be writing. |
| Effort | LOW |
| Steps | Work out who needs to write it — this mode usually stands in for a group nobody created; make the group and use `0664`; otherwise `chmod o-w`; **look at the content** if root reads it, because it may already have been changed; check the directory too |
| Commands | `find / -xdev -type f -perm -0002 -ls`, `chmod o-w <path>` |
| **Caution** | Some applications expect a shared writable file and fail only under load or at restart. Identify the writer first, and prefer a group to the world-write bit. |

## 9. Control mappings

- `nist-800-53-r5` AC-3
- `nist-800-53-r5` AC-6
- `nist-800-53-r5` SI-7

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | nothing world-writable | PASS |
| `filesys-world-writable` | a `0666` config and a `0777` script, plus a symlink | FAIL, HIGH |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short | UNKNOWN, `source_truncated` |
