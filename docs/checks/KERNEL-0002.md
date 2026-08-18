# KERNEL-0002 — Kernel pointers are not exposed to unprivileged users

| Field | Value |
|---|---|
| **ID** | `KERNEL-0002` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, information-disclosure, exploit-mitigation |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

The running value of `kernel.kptr_restrict` is `1` or greater.

## 2. Why it matters

Kernel virtual addresses printed in `/proc/kallsyms`, `/proc/modules` and
various other interfaces tell an attacker where the kernel actually is in
memory. That is precisely the information kernel address-space layout
randomisation exists to withhold, and leaking it turns a local privilege
escalation that would have needed an information leak into one that does not.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/kptr_restrict` |
| Daemon default when unset | The parameter always exists. Kernel default is `0` unless the distribution sets otherwise. |
| Reference | `Documentation/admin-guide/sysctl/kernel.rst` — `kptr_restrict` |

`0` prints addresses to everyone. `1` replaces them with zeros for processes
without `CAP_SYSLOG`. `2` replaces them for everyone including root.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu | Ship `1` via a `procps` drop-in | Not verified on live hosts |
| RHEL family | Ship `1` | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value ≥ 1 | — | which restriction applies (CAP_SYSLOG, or all users at 2) |
| FAIL | running value is 0 | MEDIUM | that addresses are printed in full to any user |
| NOT_APPLICABLE | parameter absent | — | that the kernel does not expose it |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`

The check does not verify that individual interfaces actually honour the
setting. A kernel module that prints pointers with `%px` bypasses
`kptr_restrict` entirely, and no sysctl reports that.

## 7. Known false positives

Profiling and tracing tools (`perf`, some eBPF front-ends) need symbol
addresses. The correct response is to grant those tools `CAP_SYSLOG` rather
than to lower the parameter host-wide; a host that genuinely cannot do so
should suppress with a justification.

## 8. Remediation

| | |
|---|---|
| Summary | Set `kernel.kptr_restrict` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, verify |
| Commands | `sysctl -w kernel.kptr_restrict=1` |
| **Caution** | Not required. Cannot remove the operator's access. |

## 9. Control mappings

- `nist-800-53-r5` SC-4
- `nist-800-53-r5` SI-16

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 1 | PASS |
| `kernel-weak` | value 0 | FAIL |
| `kernel-partial` | value 2 | PASS |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
