# FILESYS-0007 — /tmp is a separate mount with nodev, nosuid and noexec

| Field | Value |
|---|---|
| **ID** | `FILESYS-0007` |
| **Module** | FILESYS |
| **Base severity** | MEDIUM |
| **Tags** | filesys, mount, hardening, attack-surface |
| **Facts required** | `fs.mounts` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

`/tmp` appears in the kernel's mount table as its own mount point, carrying
`nodev`, `nosuid` and `noexec`.

## 2. Why /tmp specifically

It is the one directory every account can write to, which makes it the first
place anything an attacker brings with them lands. A downloaded payload, an
extracted archive, a compiled exploit — all of it arrives in `/tmp` because
`/tmp` is where an unprivileged account is *allowed* to put things.

| Option | What it removes |
|---|---|
| `noexec` | nothing written here can be executed directly — this breaks the step immediately after "download the payload" |
| `nosuid` | a setuid binary here does not run with its owner's privileges, so `/tmp` stops being a place to park a setuid root shell |
| `nodev` | a device node here reaches nothing, closing the raw-disk path FILESYS-0006 reports |

## 3. Being a separate filesystem is the precondition

These are **per-mount** properties. A `/tmp` that is merely a directory on the
root filesystem cannot carry them no matter what `fstab` says — which is why
"not a separate mount" is a FAIL in its own right rather than a technicality.

It is also an availability control: a runaway process filling `/tmp` fills the
root filesystem, and a host with no space on `/` stops being able to log, to
rotate, and in some cases to boot.

## 4. noexec is not a boundary, and the check does not claim it is

`noexec` is bypassable by invoking the interpreter directly — `sh /tmp/x`
rather than `/tmp/x`, or `ld.so /tmp/binary` — and anyone who says otherwise
has not tried it.

What these options do is remove the **easy** path, which is the path automated
tooling and most opportunistic attacks actually take. That is worth having and
it is not a boundary, and the check's description says so rather than
overselling it.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | separate mount with all three options | — | the filesystem type and the options as mounted |
| FAIL | not a separate mount | MEDIUM | **which mount governs it instead**, and that per-mount options cannot apply |
| FAIL | separate mount missing one or more options | MEDIUM | which are missing and **what each absence permits** |
| UNKNOWN | the mount table could not be read or was truncated | `source_truncated` | that a partial table may be missing this very entry |

The UNKNOWN branch is the mount-table half of the same asymmetry the truncated-
walk rule enforces for the traversal: a table we could not read is not a table
with nothing in it, and the two conclusions lead to opposite actions.

## 6. Where this check cannot know

- **whether the options are in force versus merely written in `fstab`.** The
  fact comes from `/proc/self/mountinfo`, which is what is actually mounted —
  so this is a strength, but it means an `fstab` fixed and not remounted still
  fails, correctly
- **whether anything on the host needs to execute from `/tmp`.** Some
  installers and JVM native libraries do; the remediation says to set `TMPDIR`
  for them rather than drop the option
- **the size of the filesystem**, so the availability argument is not verified
- **bind mounts of `/tmp` elsewhere**, which could reintroduce the capability

## 7. Known false positives

A container, where `/tmp` is usually part of the image's root filesystem by
design and the isolation comes from the container boundary instead. Suppress
with that reasoning recorded.

## 8. Remediation

| | |
|---|---|
| Summary | Make `/tmp` a separate filesystem — tmpfs is simplest — and mount it `nodev,nosuid,noexec`. |
| Effort | MEDIUM |
| Steps | On systemd, `systemctl unmask tmp.mount` then `systemctl enable --now tmp.mount`; or an fstab line with `size=`; **check what is in `/tmp` first**, because a tmpfs starts empty and does not survive reboot; `mount -o remount /tmp` then `findmnt /tmp` to confirm the options are in force; test that `noexec` breaks nothing you depend on |
| Commands | `findmnt /tmp`, `systemctl enable --now tmp.mount` |
| **Caution** | **Required.** `noexec` breaks software that extracts and runs helpers in `/tmp` — some installers, some JVM native libraries, some Node modules — and the failure is usually an obscure permission error. Test the workloads first, and set `TMPDIR` for offenders rather than dropping the option. |

## 9. Control mappings

- `nist-800-53-r5` CM-7
- `nist-800-53-r5` SC-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | separate tmpfs with all three options | PASS |
| `filesys-mounts-weak` | `/tmp` is a directory on `/` | FAIL, MEDIUM |
| `filesys-mounts-unknown` | mount table unreadable | UNKNOWN, `source_truncated` |
