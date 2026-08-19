# FILESYS-0004 — World-writable directories have the sticky bit set

| Field | Value |
|---|---|
| **ID** | `FILESYS-0004` |
| **Module** | FILESYS |
| **Base severity** | MEDIUM |
| **Tags** | filesys, permissions, sticky-bit, integrity |
| **Facts required** | `fs.world_writable_dir` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every world-writable directory carries the sticky bit (`mode & ModeSticky`).

## 2. Write on a directory means delete and replace

This is the part that is not obvious, and it is the whole check.

Write permission on a directory is permission to **unlink and rename the
entries in it, whoever owns them**. In a world-writable directory without the
sticky bit, any account can remove any other account's file and put its own
there under the same name. The victim opens the path they have always opened
and reads content somebody else wrote — and nothing about the file's own mode
prevented it, because the file was not modified. It was replaced.

The sticky bit closes exactly this. On a directory it means *only the file's
owner, the directory's owner, or root may unlink or rename an entry*.

```
/tmp  mode 1777   shared workspace   ← correct
/tmp  mode 0777   free-for-all       ← this finding
```

That is why `/tmp` being world-writable is correct rather than alarming.

## 3. Where it actually goes wrong

Almost never `/tmp` itself. It is a spool directory, an upload directory, or a
shared drop point created with `mkdir -m 777` by somebody who wanted two
services to exchange files and did not know the bit existed. Fixing the
directory without fixing the install script means it returns at the next
deployment.

## 4. The relationship to FILESYS-0005

They ask different questions about the same directories, and a directory can
pass this one and fail that one:

| | This check | FILESYS-0005 |
|---|---|---|
| Asks | is the sticky bit set? | should it be world-writable at all? |
| `/tmp` at 1777 | PASS | PASS — not a system directory |
| `/etc/cron.d` at 1777 | **PASS** | **FAIL** |

A sticky world-writable `/etc/cron.d` is still a root shell on a schedule,
because the sticky bit restricts deleting *existing* entries and says nothing
about creating new ones. `filesys-system-dir` is that fixture.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every world-writable directory is sticky | — | that FILESYS-0005 asks the other question; if none exist, **that this is unusual rather than hardened** |
| FAIL | one or more are not | MEDIUM | each path, and that write-on-a-directory means delete-and-replace |
| UNKNOWN | the walk did not finish | `source_truncated` | which limit fired |

## 6. Where this check cannot know

- **whether files in the directory have already been swapped.** A replacement
  is a new file, so its timestamps look ordinary
- **whether the directory needs to be world-writable**, which is FILESYS-0005
  for system paths and a judgement call elsewhere
- **ACLs**, which are not read

## 7. Known false positives

None known for the failing direction. A world-writable directory without the
sticky bit is a defect on every host.

## 8. Remediation

| | |
|---|---|
| Summary | Set the sticky bit, or replace world-write with a group. |
| Effort | LOW |
| Steps | Ask first whether it needs to be world-writable — a shared drop point wants a group and `2770`; otherwise `chmod +t`; **check what is already in it**, since files there may already have been replaced; fix the `mkdir -m 777` in the install script or it returns |
| Commands | `find / -xdev -type d -perm -0002 ! -perm -1000 -ls`, `chmod +t <dir>` |
| **Caution** | The sticky bit stops one account deleting another's files, which a cleanup job running as a service account may have been relying on. Check what removes files from the directory first. |

## 9. Control mappings

- `nist-800-53-r5` AC-3
- `nist-800-53-r5` SI-7

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | `/tmp` at 1777 | PASS |
| `filesys-sticky` | `/var/spool/upload` at 0777 | FAIL, MEDIUM |
| `filesys-system-dir` | `/etc/cron.d` world-writable **and** sticky | PASS — 0005's finding |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short | UNKNOWN, `source_truncated` |
