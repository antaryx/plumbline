# KERNEL-0013 — Unprivileged access to performance counters is restricted

| Field | Value |
|---|---|
| **ID** | `KERNEL-0013` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, side-channel, information-disclosure, attack-surface |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 3 |
| **Platforms** | Linux with `CONFIG_PERF_EVENTS` |

## 1. What is tested

The running value of `kernel.perf_event_paranoid` is `2` or greater.

## 2. Why it matters

`perf_event_open()` is the entry point to the kernel's performance-monitoring
subsystem. Left open to unprivileged users it is two problems at once. It is a
side channel: hardware performance counters and instruction sampling leak the
behaviour of other processes precisely enough to recover cryptographic keys,
and every speculative-execution attack of the last decade has used it as a
measurement device. It is also a large and historically fragile piece of kernel
code, and has produced its own local privilege escalations.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/perf_event_paranoid` |
| Daemon default when unset | The parameter exists wherever `CONFIG_PERF_EVENTS` is set. Mainline default is `2`; Debian and Ubuntu ship `3` or `4`. |
| Reference | `perf_event_open(2)` |

| Value | Meaning |
|---|---|
| `-1` | no restriction whatsoever |
| `0` | raw tracepoint access requires `CAP_PERFMON` |
| `1` | additionally, CPU-wide events require `CAP_PERFMON` |
| `2` | additionally, kernel profiling requires `CAP_PERFMON` |
| `3` | `perf_event_open()` refused entirely without `CAP_PERFMON` |

## 4. Distribution variations

**Value `3` is not mainline.** It comes from a patch carried by Debian, Ubuntu
and Android. A mainline kernel clamps to `2` and cannot express `3`.

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu | Carry the `perf_event_paranoid=3` patch and ship `3` or `4` | Not verified on live hosts |
| RHEL family, mainline | Maximum meaningful value is `2` | Not verified on live hosts |

**This is why the check requires `≥ 2` rather than `3`.** Demanding a value a
mainline kernel cannot express would fail hosts that are already configured as
strictly as they are able to be, and a check that cannot be satisfied is a
check operators learn to ignore. A host at `3` passes and the detail says so.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value ≥ 3 | — | that `perf_event_open()` is refused outright, and that the value is a downstream patch |
| PASS | running value is 2 | — | that kernel profiling, CPU-wide events and raw tracepoints all require `CAP_PERFMON` |
| FAIL | running value is 1 | MEDIUM | that unprivileged users may still profile the kernel |
| FAIL | running value is 0 | MEDIUM | that CPU-wide measurement and kernel profiling are open |
| FAIL | running value is `-1` | HIGH | that the subsystem is entirely unrestricted |
| NOT_APPLICABLE | the parameter does not exist | — | that this kernel does not expose it |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

`-1` carries a higher severity than `0` or `1` because it is not merely a
looser setting: it is the documented value for *no restriction at all*,
including raw tracepoint access.

## 6. Where this check cannot know

- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`
- parameter absent (kernel built without `CONFIG_PERF_EVENTS`) →
  `NOT_APPLICABLE`. Here that genuinely is the absence of the subject: there is
  no `perf_event_open()` to restrict
- the check cannot see whether a process holds `CAP_PERFMON`. A host at `2`
  with a monitoring agent granted the capability is correctly configured and
  looks identical to one with no agent at all

## 7. Known false positives

Hosts whose purpose is performance analysis, and hosts running APM agents that
call `perf_event_open()` without holding `CAP_PERFMON`. The correct fix is to
grant the capability to the agent; where that is not possible, suppress with a
justification.

## 8. Remediation

| | |
|---|---|
| Summary | Set `kernel.perf_event_paranoid` to 2 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | identify what profiles on this host; apply with `sysctl -w`; persist; verify; consider `3` only on Debian-family kernels where nothing profiles |
| Commands | `sysctl -w kernel.perf_event_paranoid=2` |
| **Caution** | Not required for the operator's access. Profiling and APM tooling will stop working and should be granted `CAP_PERFMON`. |

## 9. Control mappings

- `nist-800-53-r5` SC-4
- `nist-800-53-r5` AC-6

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 2 | PASS |
| `kernel-weak` | value -1 | FAIL / HIGH |
| `kernel-partial` | value 1 | FAIL / MEDIUM |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
| `kernel-unparseable` | holds `notanumber` | UNKNOWN(`unparseable_source`) |
