# FILESYS-0005 — No system directory is world-writable

| Field | Value |
|---|---|
| **ID** | `FILESYS-0005` |
| **Module** | FILESYS |
| **Base severity** | CRITICAL |
| **Tags** | filesys, permissions, privilege-escalation, integrity |
| **Facts required** | `fs.world_writable_dir` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No world-writable directory is at or beneath a tree the operating system
depends on: `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr`, `/etc`, `/boot`, `/opt`,
`/root`, `/var/lib`, `/var/spool/cron`, `/var/www`.

## 2. The sticky bit does not help here

This is the reason the check exists separately from FILESYS-0004.

The sticky bit restricts deleting and renaming **existing** entries. It does
nothing about **creating new ones** — and creating one is the whole attack.

A world-writable `/usr/bin` with the sticky bit set still lets any account add
a file, and adding a file to a directory on `$PATH` is sufficient on its own:
the account creates something plausible, waits for an administrator to mistype
a command or for a script to call a binary by name rather than by absolute
path, and their code runs as whoever ran it.

Under `/etc` it is worse, because so much of what lives there is read by root
at boot. A new file in `/etc/cron.d`, `/etc/sudoers.d`, `/etc/systemd/system`,
`/etc/profile.d` or `/etc/ld.so.conf.d` is root on a timer. Under `/boot` it
survives reinstalling the operating system above it.

## 3. Relationship to CRON and SERVICES

Three modules check the same escalation from different angles, and each covers
what the others cannot:

| Check | Subject |
|---|---|
| CRON-0002 | the cron drop-in directories themselves |
| SERVICES-0005 | the systemd unit directories themselves |
| **FILESYS-0005** | the trees those live in, found by traversal rather than by name |

The traversal is what catches the drop-in directory nobody thought to name.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | no system directory is world-writable | — | which trees were covered |
| FAIL | one or more are | CRITICAL | each path, **and that the sticky bit is irrelevant here** |
| UNKNOWN | the walk did not finish | `source_truncated` | which limit fired |

## 5. Where this check cannot know

- **whether something has already been placed there.** Fixing the mode stops
  new files and removes nothing already present — a cron drop-in or a systemd
  unit left behind keeps running as root afterwards. This is why the
  remediation audits before it chmods
- **whether a file in the directory is legitimate.** That needs package
  metadata this tool does not collect
- **directories outside the listed trees.** A world-writable `/srv/app` is
  FILESYS-0004's business, not this check's
- **ACLs**

## 6. Known false positives

An application deliberately given a writable subdirectory inside a system tree
— some vendored software writes into `/opt/<vendor>/var`. The correct fix is a
subdirectory the application owns rather than world-write, but where that is not
possible, suppress with the path and reasoning recorded.

## 7. Remediation

| | |
|---|---|
| Summary | Remove world write and audit everything currently in the directory. |
| Effort | MEDIUM |
| Steps | **Audit the contents before fixing the mode** — anyone could have added a file and it keeps working afterwards; `chmod o-w`; pay particular attention to drop-in directories under `/etc`; establish how it happened, since this is almost always `chmod -R 777` in an install script or container build; give applications a subdirectory they own rather than write access to the parent |
| Commands | `find /usr /etc /bin /sbin /lib /boot /opt -xdev -type d -perm -0002 -ls`, `ls -la <dir>` |
| **Caution** | **Required.** Treat this as possible compromise rather than untidiness. Fixing the permission stops new files being added and removes nothing already there. |

## 8. Control mappings

- `nist-800-53-r5` AC-3
- `nist-800-53-r5` AC-6
- `nist-800-53-r5` CM-5
- `nist-800-53-r5` SI-7

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | only `/tmp` is world-writable | PASS |
| `filesys-system-dir` | `/etc/cron.d` at 1777 — sticky, and still fatal | FAIL, CRITICAL |
| `filesys-sticky` | `/var/spool/upload` at 0777 — not a system tree | PASS — 0004's finding |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short | UNKNOWN, `source_truncated` |
