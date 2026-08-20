# KERNEL-0006 — Unprivileged users cannot load BPF programs

| Field | Value |
|---|---|
| **ID** | `KERNEL-0006` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, bpf, privilege-escalation, attack-surface |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux with BPF built in |

## 1. What is tested

The running value of `kernel.unprivileged_bpf_disabled` is `1` or `2`.

## 2. Why it matters

The `bpf()` system call compiles user-supplied bytecode and runs it inside the
kernel. The verifier that is supposed to prove such a program safe is one of
the most complex pieces of the kernel and has been a recurring source of local
privilege escalations; leaving it reachable by unprivileged users gives every
local account a large, intricate attack surface for no benefit on a server.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/unprivileged_bpf_disabled` |
| Daemon default when unset | The parameter exists only on kernels with BPF. Its default depends on `CONFIG_BPF_UNPRIV_DEFAULT_OFF`: `2` where that is set, `0` otherwise. |
| Reference | `Documentation/admin-guide/sysctl/kernel.rst` — `unprivileged_bpf_disabled` |

`0` unprivileged loading permitted. `1` refused, and **locked until reboot**.
`2` refused, and may still be raised to `1`.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Ubuntu 22.04+ | Ships `2` via `CONFIG_BPF_UNPRIV_DEFAULT_OFF` | Not verified on live hosts |
| Older kernels (pre-4.4) | Parameter does not exist | Covered by the `kernel-absent` fixture |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value is 1 | — | that unprivileged `bpf()` is refused and locked |
| PASS | running value is 2 | — | that it is refused and may still be locked by raising to 1 |
| FAIL | running value is 0 | MEDIUM | that any local user may load BPF programs |
| FAIL | any other integer | MEDIUM | the observed value and that it is undocumented |
| NOT_APPLICABLE | parameter absent | — | that this kernel does not expose it |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- BPF absent → `NOT_APPLICABLE`. A kernel without BPF has no `bpf()` attack
  surface, so unlike KERNEL-0003 this genuinely is the absence of the subject.
- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`

The check makes no claim about privileged BPF use. An observability agent
running as root loads BPF programs regardless of this parameter, and that is
both normal and outside what this setting governs.

## 7. Known false positives

Unprivileged BPF is genuinely required by some sandboxing and observability
tooling. A host that needs it should suppress with a justification rather than
have the check soften.

## 8. Remediation

| | |
|---|---|
| Summary | Set `kernel.unprivileged_bpf_disabled` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | confirm nothing unprivileged loads BPF, apply with `sysctl -w`, persist, verify |
| Commands | `sysctl -w kernel.unprivileged_bpf_disabled=1` |
| **Caution** | **Required.** Value 1 cannot be lowered again without rebooting. |

## 9. Control mappings

- `nist-800-53-r5` CM-7
- `nist-800-53-r5` AC-6

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 1 | PASS |
| `kernel-weak` | value 0 | FAIL |
| `kernel-partial` | value 2 | PASS |
| `kernel-absent` | parameter absent | NOT_APPLICABLE |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
