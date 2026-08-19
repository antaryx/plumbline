# FILESYS-0006 — No device node exists outside /dev

| Field | Value |
|---|---|
| **ID** | `FILESYS-0006` |
| **Module** | FILESYS |
| **Base severity** | HIGH |
| **Tags** | filesys, device, privilege-escalation, persistence |
| **Facts required** | `fs.device_outside_dev` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No block or character device node exists at a path outside `/dev`.

## 2. The kernel does not care where the doorway is

`/dev/sda` is not special because of its path. It is a block device node with a
major and minor number, and an identical node created in `/tmp` or in a home
directory reaches **the same disk**.

That is what makes one outside `/dev` worth reporting:

- Reading a raw block device **bypasses every file permission on the filesystem
  stored on it**. An account that cannot read `/etc/shadow` through the
  filesystem can read the bytes of `/etc/shadow` straight off the disk.
- A character device node for `/dev/mem` or `/dev/kmem` bypasses the kernel's
  own memory protection.

## 3. Creating one needs root; using one does not

`mknod` requires `CAP_MKNOD`. So a node outside `/dev` is either a mistake made
by root or an artifact left by somebody who had root — and in the second case it
is a way back in that survives the patch which closed the original hole.

**Using** it requires only the permissions on the node itself, which is why a
node an attacker leaves world-readable is usable by any account afterwards. The
`filesys-device` fixture makes it mode 0444 for that reason.

The mistakes are real too: extracting an archive as root with `tar -p`, or
restoring a backup of `/dev` into the wrong place, produces exactly this.
Neither is an attack and both are the same doorway.

## 4. Why the walker stats non-regular files

This check is one of the reasons the shared walker's `Match` sees every inode
including devices, FIFOs and sockets, rather than only regular files. It is
safe because the walker **only ever stats them and never opens one** — opening
an unprivileged user's FIFO as root hangs the scanner forever, which is what
`internal/system/live`'s hostile corpus tests.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | no device node outside `/dev` | — | how many inodes were examined |
| FAIL | one or more found | HIGH | each path, **and that creating one required root** |
| UNKNOWN | the walk did not finish | `source_truncated` | which limit fired |

## 6. Where this check cannot know

- **which device the node points at.** The major and minor numbers are not
  carried in the fact; `stat` during triage answers it, and the answer decides
  urgency — 8,x is a disk, 1,1 is `/dev/mem`
- **when it appeared.** `stat -c %z` bounds it
- **whether the filesystem is mounted `nodev`**, which makes the node inert.
  FILESYS-0007 through 0009 check that separately
- **device nodes inside `/dev`** that should not be there

## 7. Known false positives

Container runtimes and chroot trees that legitimately contain a `dev`
directory at a nested path — for example `/var/lib/containers/…/dev/null`.
These are real device nodes outside the host's `/dev` and they are intended.
Suppress with the path prefix recorded.

## 8. Remediation

| | |
|---|---|
| Summary | Record the node and establish where it came from before removing it. |
| Effort | MEDIUM |
| Steps | Record it first — `ls -l` shows major and minor in place of a size; work out whether anything explains it (`tar -p`, a restored backup); **if nothing does, treat the host as compromised** rather than misconfigured; `rm` it once recorded; mount `/home`, `/tmp` and `/var/tmp` `nodev` so nodes there are inert |
| Commands | `find / -xdev \( -type b -o -type c \) ! -path '/dev/*' -ls`, `stat <path>` |
| **Caution** | **Required.** If this is an attacker's artifact, deleting it destroys evidence and does not remove their access. Record it and treat the finding as an incident before cleaning up. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` SC-4
- `nist-800-53-r5` SI-4

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | `/dev/null` only | PASS |
| `filesys-device` | a block node in `/var/tmp` with `/dev/sda`'s numbers | FAIL, HIGH |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short | UNKNOWN, `source_truncated` |
