# KERNEL-0012 — Opening another user's file in a shared directory is restricted

| Field | Value |
|---|---|
| **ID** | `KERNEL-0012` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, filesystem, toctou, information-disclosure |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 3 |
| **Platforms** | Linux 4.19 and later |

## 1. What is tested

The running value of `fs.protected_regular` is `1` or greater.

## 2. Why it matters

This is the same weakness KERNEL-0011 covers, for ordinary files rather than FIFOs. A privileged program creating a predictably named file in `/tmp` with `O_CREAT` will happily open a file an attacker created there first, then write its output into a file the attacker owns and can read afterwards — or read the attacker's content believing it to be its own.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/fs/protected_regular` |
| Daemon default when unset | The parameter arrived in Linux 4.19 and **does not exist on older kernels**. Kernel default is `1` where it exists. |
| Reference | `Documentation/admin-guide/sysctl/fs.rst` |

`0` off. `1` restricts O_CREAT opens in world-writable sticky directories.
`2` extends the restriction to group-writable sticky directories.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Any distribution on Linux ≥ 4.19 | Ship `1` | Not verified on live hosts |
| Any distribution on Linux < 4.19 | Parameter does not exist | Covered by the `kernel-absent` fixture |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value ≥ 1 | — | whether the restriction covers world-writable only, or group-writable too |
| FAIL | running value is 0 | MEDIUM | the concrete substitution attack the setting prevents |
| NOT_APPLICABLE | the parameter does not exist — a kernel older than 4.19 | — | that this kernel does not expose it |
| UNKNOWN | the parameter exists and could not be read | — | `insufficient_privileges` |
| UNKNOWN | the value is not a single integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

Where the running value fails and a configuration file sets a different value,
the detail names the file and line and points at KERNEL-0007.

## 6. Where this check cannot know

- **the parameter is absent, meaning a kernel older than 4.19 → `NOT_APPLICABLE`.**
  This is not a PASS. Such a kernel has no protection against this attack at
  all; the check reports that there is no parameter to assert about, and the
  protection must come from somewhere else. Reporting PASS here would tell an
  operator their oldest hosts were their safest
- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`

The check asserts the kernel-wide policy only. Whether any particular directory
on this host is world-writable and sticky is the FILESYS module's question.

## 7. Known false positives

Software that deliberately shares a predictably named path in `/tmp` between
users — some older lock-file and IPC conventions do — will break. The correct
fix is a private directory under `/run` or an abstract socket, not lowering the
parameter.

## 8. Remediation

| | |
|---|---|
| Summary | Set `fs.protected_regular` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, verify; consider `2` if nothing relies on group-writable shared directories |
| Commands | `sysctl -w fs.protected_regular=1` |
| **Caution** | Not required. Cannot remove the operator's access. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` SC-4

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | protection enabled | PASS |
| `kernel-weak` | value 0 | FAIL |
| `kernel-partial` | value 1 | PASS |
| `kernel-absent` | kernel older than 4.19 | NOT_APPLICABLE |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
