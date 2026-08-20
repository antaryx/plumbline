# KERNEL-0010 — Hardlink creation is restricted to files the user can already read

| Field | Value |
|---|---|
| **ID** | `KERNEL-0010` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, filesystem, privilege-escalation |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 3 |
| **Platforms** | Linux 3.6 and later |

## 1. What is tested

The running value of `fs.protected_hardlinks` is `1`.

## 2. Why it matters

Without this restriction, any user may create a hardlink to any file whose directory they can write, including files they cannot read. That turns two harmless-looking permissions into an attack: link a shadow file or a setuid binary into a directory you control, wait for a privileged process or a package upgrade to act on it, and inherit the result. It also defeats quota and retention controls, because the original file cannot be freed while the attacker's link exists.

Setting this to `1` permits a hardlink only when the user owns the source file, or can both read and write it.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/fs/protected_hardlinks` |
| Daemon default when unset | The parameter exists on Linux 3.6+. Kernel default is `1`. |
| Reference | `Documentation/admin-guide/sysctl/fs.rst` |

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu, RHEL, SUSE | Ship `1`; the value is the kernel default | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value ≥ 1 | — | which directories the restriction covers |
| FAIL | running value is 0 | MEDIUM | the concrete attack the setting prevents |
| NOT_APPLICABLE | the parameter does not exist in this kernel | — | that the kernel does not expose it |
| UNKNOWN | the parameter exists and could not be read | — | `insufficient_privileges` |
| UNKNOWN | the value is not a single integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

Where the running value fails and a configuration file sets a different value,
the detail names the file and line and points at KERNEL-0007.

## 6. Where this check cannot know

- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`
- the parameter is absent, which means a kernel older than 3.6 → `NOT_APPLICABLE`

The check asserts the kernel-wide policy only. It cannot tell whether any
particular directory on this host is world-writable and sticky — that is the
FILESYS module's question, answered from the shared filesystem walk.

## 7. Known false positives

None commonly. Software that relied on the unrestricted behaviour is relying on
a race, and the correct fix is in that software.

## 8. Remediation

| | |
|---|---|
| Summary | Set `fs.protected_hardlinks` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, verify |
| Commands | `sysctl -w fs.protected_hardlinks=1` |
| **Caution** | Not required. Cannot remove the operator's access. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` AC-3

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | protection enabled | PASS |
| `kernel-weak` | value 0 | FAIL |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
