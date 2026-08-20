# KERNEL-0004 — The kernel ring buffer is not readable by unprivileged users

| Field | Value |
|---|---|
| **ID** | `KERNEL-0004` |
| **Module** | KERNEL |
| **Base severity** | LOW |
| **Tags** | kernel, information-disclosure |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

The running value of `kernel.dmesg_restrict` is `1` or greater.

## 2. Why it matters

`dmesg` output routinely contains kernel addresses, module load addresses,
hardware identifiers, filesystem paths and the register dumps left by earlier
crashes. An unprivileged process that can read it gets a running commentary on
the kernel's internal state, which is the raw material for defeating
address-space randomisation.

Severity is LOW rather than higher because the disclosure is indirect: it
assists an attack rather than being one, and an attacker who can read `dmesg`
already has local execution.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/dmesg_restrict` |
| Daemon default when unset | The parameter always exists. Kernel default is `0`; `CONFIG_SECURITY_DMESG_RESTRICT` makes it `1`. |
| Reference | `Documentation/admin-guide/sysctl/kernel.rst` — `dmesg_restrict` |

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu | Ship `1` | Not verified on live hosts |
| RHEL family | Ship `1` | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value ≥ 1 | — | that reading requires `CAP_SYSLOG` |
| FAIL | running value is 0 | LOW | that any user may read the ring buffer |
| NOT_APPLICABLE | parameter absent | — | that the kernel does not expose it |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`

The check does not assert anything about `/var/log/kern.log` or the journal,
which may expose the same content to a different set of readers through
filesystem permissions. That is a LOGGING-module concern.

## 7. Known false positives

Monitoring agents that read `dmesg` without `CAP_SYSLOG` break. The fix is to
grant the capability to the agent, not to lower the parameter.

## 8. Remediation

| | |
|---|---|
| Summary | Set `kernel.dmesg_restrict` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, verify |
| Commands | `sysctl -w kernel.dmesg_restrict=1` |
| **Caution** | Not required. |

## 9. Control mappings

- `nist-800-53-r5` SC-4

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 1 | PASS |
| `kernel-weak` | value 0 | FAIL |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
