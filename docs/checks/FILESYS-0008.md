# FILESYS-0008 — /dev/shm is mounted with nodev, nosuid and noexec

| Field | Value |
|---|---|
| **ID** | `FILESYS-0008` |
| **Module** | FILESYS |
| **Base severity** | MEDIUM |
| **Tags** | filesys, mount, hardening, anti-forensics |
| **Facts required** | `fs.mounts` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

`/dev/shm` appears in the mount table carrying `nodev`, `nosuid` and `noexec`.

## 2. The writable directory nobody watches

`/dev/shm` is POSIX shared memory: a tmpfs every account on the host can write
to, present on essentially every Linux system, and invisible to the people who
think of `/tmp` as *the* writable directory.

That invisibility is the point. It is world-writable like `/tmp`, it is backed
by RAM so **nothing touches a disk**, and it is not what anybody watches. A
payload written there:

- leaves no trace on storage,
- survives until reboot,
- is missed by file-integrity monitoring and by a forensic disk image alike.

Attackers use it for exactly that reason, and it is a routine finding in
intrusions where `/tmp` was hardened and this was not.

## 3. noexec here costs almost nothing

Unlike `/tmp`, there is essentially no legitimate workload that needs to
execute from `/dev/shm`. It exists for shared memory segments, which are
**mapped rather than executed**.

On many distributions the defaults are already `nosuid` and `nodev` but **not**
`noexec` — which is why this check is worth running on a host nobody has
touched, and why `filesys-mounts-weak` models exactly that state rather than a
wholly unconfigured one.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | mounted with all three options | — | the filesystem type and the options as mounted |
| FAIL | mounted, missing one or more | MEDIUM | which are missing and what each absence permits |
| FAIL | not a separate mount | MEDIUM | which mount governs it instead |
| UNKNOWN | the mount table could not be read or was truncated | `source_truncated` | that a partial table may be missing this entry |

## 5. Where this check cannot know

- **whether anything is currently in `/dev/shm`.** The walk does not descend
  into it by default, and its contents are ephemeral
- **whether the options are in `fstab`.** The fact is what is mounted now,
  which is the more useful answer and means an unremounted `fstab` fix still
  fails
- **shared memory used through `memfd_create`**, which has no filesystem path
  at all and is a strictly better hiding place — nothing here sees it

## 6. Known false positives

A small number of database and HPC products place executable helpers in
`/dev/shm`. PostgreSQL's dynamic shared memory uses it heavily but does not
execute from it. Check the workload before making the change permanent; expect
no impact on an ordinary host.

## 7. Remediation

| | |
|---|---|
| Summary | Add an fstab entry for `/dev/shm` with `nodev,nosuid,noexec` and remount. |
| Effort | LOW |
| Steps | **Add the entry** — the default mount is made by the kernel or systemd and there is usually no fstab line to edit; `mount -o remount /dev/shm`; verify with `findmnt`, because an fstab entry for an already-mounted filesystem does nothing until the remount; on systemd check `systemctl show -p Options dev-shm.mount` |
| Commands | `findmnt /dev/shm`, `mount -o remount,nodev,nosuid,noexec /dev/shm` |
| **Caution** | A few database and HPC products place executable helpers here. Check the workload before making it permanent, but expect no impact on an ordinary host. |

## 8. Control mappings

- `nist-800-53-r5` CM-7
- `nist-800-53-r5` SC-2

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | tmpfs with all three options | PASS |
| `filesys-mounts-weak` | `nosuid,nodev` but **no** `noexec` — the common default | FAIL, MEDIUM |
| `filesys-mounts-unknown` | mount table unreadable | UNKNOWN, `source_truncated` |
