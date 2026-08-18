# KERNEL-0001 — Address-space layout randomisation is fully enabled

| Field | Value |
|---|---|
| **ID** | `KERNEL-0001` |
| **Module** | KERNEL |
| **Base severity** | HIGH |
| **Tags** | kernel, memory-protection, exploit-mitigation |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

The running value of `kernel.randomize_va_space` is `2`.

## 2. Why it matters

Address-space layout randomisation places the stack, the heap, shared libraries
and — for position-independent executables — the program image itself at
addresses that differ on every execution. Without it, an attacker who finds a
memory-corruption bug knows in advance where everything is, and a crash-only
bug becomes reliable code execution.

`kernel.randomize_va_space` takes three values. `0` disables randomisation
entirely. `1` randomises the stack, the shared libraries and the mmap base but
leaves the heap where the linker put it, which leaves heap-grooming attacks
intact. `2` additionally randomises the brk-managed heap and is the value every
current distribution ships.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/randomize_va_space` |
| Daemon default when unset | Not applicable — the parameter always exists on Linux and always holds a value. The kernel's compiled-in default is `2`. |
| Reference | `proc(5)`, `Documentation/admin-guide/sysctl/kernel.rst` |

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu, RHEL, SUSE | Ship `2`; no drop-in sets it | Not verified on live hosts — the value is the kernel default and no distribution package in the fixture corpus overrides it |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value is `2` | — | that stack, heap, libraries and mmap base are all randomised |
| FAIL | running value is `1` | MEDIUM | that the heap is not randomised and heap layout is predictable |
| FAIL | running value is `0` | HIGH | that ASLR is disabled entirely |
| FAIL | running value is any other integer | HIGH | the observed value and that it is undocumented |
| NOT_APPLICABLE | the parameter does not exist in this kernel | — | that the kernel does not expose it |
| UNKNOWN | the parameter exists and could not be read | — | `insufficient_privileges` |
| UNKNOWN | the value is not a single integer | — | `unparseable_source` |
| SKIPPED | runner-decided (profile, filter) | — | — |

Where the running value fails *and* a configuration file sets a different
value, the detail additionally names the file and line and points at
KERNEL-0007. An operator whose file already holds `2` needs to know that a
reboot — not another edit — is the fix.

## 6. Where this check cannot know

- `/proc/sys/kernel/randomize_va_space` unreadable (namespaced or lockdown) →
  `UNKNOWN(insufficient_privileges)`
- the value is not an integer, which happens when something is mounted over
  `/proc/sys` in a container → `UNKNOWN(unparseable_source)`
- the parameter absent, which should not occur on Linux but is handled rather
  than assumed → `NOT_APPLICABLE`

This check makes no claim about *per-binary* randomisation. A binary that is
not position-independent has a fixed image base whatever this parameter says,
and that is a property of the binary, not the kernel.

## 7. Known false positives

None known. A host deliberately running with ASLR disabled is doing so for a
debugging or performance reason and should suppress the check with a
justification rather than have the check soften.

## 8. Remediation

| | |
|---|---|
| Summary | Set `kernel.randomize_va_space` to 2 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, confirm with `sysctl --system`, verify the running value |
| Commands | `sysctl -w kernel.randomize_va_space=2`, `sysctl kernel.randomize_va_space` |
| **Caution** | Not required. The change takes effect for newly executed processes and cannot remove the operator's access. |

## 9. Control mappings

- `nist-800-53-r5` SI-16

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 2 | PASS |
| `kernel-weak` | value 0 | FAIL / HIGH |
| `kernel-partial` | value 1 | FAIL / MEDIUM |
| `kernel-drift` | running 0, configured 2 | FAIL / HIGH, detail names the configuration |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
| `kernel-unparseable` | holds `enabled` | UNKNOWN(`unparseable_source`) |
