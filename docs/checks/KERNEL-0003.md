# KERNEL-0003 — Debugging other processes with ptrace is restricted

| Field | Value |
|---|---|
| **ID** | `KERNEL-0003` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, lsm, credential-theft, lateral-movement |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux with the Yama LSM built in |

## 1. What is tested

The running value of `kernel.yama.ptrace_scope` is `1` or greater.

## 2. Why it matters

`ptrace` lets one process read and write another's memory. With the default
permissive policy, any process may attach to any other process running as the
same user — so a single compromised program can read the credentials, session
tokens and private keys held by every other program that user is running,
without needing a privilege escalation at all.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/yama/ptrace_scope` |
| Daemon default when unset | The parameter exists only when Yama is built into the kernel. When Yama is absent there is no restriction and no parameter. Yama's own default is `1` on Debian-family kernels and `0` on several others. |
| Reference | `Documentation/admin-guide/LSM/Yama.rst` |

`0` classic permissive. `1` descendants only. `2` requires `CAP_SYS_PTRACE`.
`3` disables ptrace entirely and **cannot be lowered without a reboot**.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu | Yama built in, ships `1` | Not verified on live hosts |
| RHEL family | Yama built in, ships `0` in some releases | Not verified on live hosts |
| Minimal/embedded kernels | Yama not built in; the parameter does not exist | Covered by the `kernel-absent` fixture |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value ≥ 1 | — | which restriction is in force, naming the irreversibility at 3 |
| FAIL | running value is 0 | MEDIUM | that any process may read another's memory including credentials |
| NOT_APPLICABLE | the parameter does not exist | — | that this kernel does not expose it and why that may be |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- Yama absent → `NOT_APPLICABLE`. **This is not a PASS.** A kernel without Yama
  has no ptrace restriction at all; the check reports that there is no
  parameter to assert about, and a different control has to provide the
  restriction. Reporting PASS here would be the module's worst possible bug.
- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`

The check cannot see whether another LSM (SELinux, AppArmor) already restricts
`ptrace`. A host confined by one of those may be adequately protected with
`ptrace_scope` at 0, and that is a suppression with a justification.

## 7. Known false positives

Hosts that attach debuggers or crash reporters to already-running processes
need scope `0`, or need the attaching process to hold `CAP_SYS_PTRACE`.
Container hosts running debug tooling in a sidecar are the common case.

## 8. Remediation

| | |
|---|---|
| Summary | Set `kernel.yama.ptrace_scope` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | check what relies on cross-process attachment, apply with `sysctl -w`, persist, verify |
| Commands | `sysctl -w kernel.yama.ptrace_scope=1` |
| **Caution** | **Required.** Value `3` is irreversible until reboot. Do not set 3 unless nothing on the host needs ptrace, including crash handlers of services that are not currently running. |

## 9. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` SC-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 1 | PASS |
| `kernel-weak` | value 0 | FAIL |
| `kernel-partial` | value 3 | PASS, detail names the irreversibility |
| `kernel-absent` | Yama not in this kernel | NOT_APPLICABLE |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
