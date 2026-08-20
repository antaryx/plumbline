# KERNEL-0014 — Core dumps are not written to an attacker-influenced location

| Field | Value |
|---|---|
| **ID** | `KERNEL-0014` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, credential-theft, information-disclosure |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 3 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

`kernel.core_pattern` either pipes dumps to a handler, or names an absolute
path that is not inside a world-writable directory.

## 2. Why it matters

A core dump is a copy of a process's memory. Where it lands is decided entirely
by `kernel.core_pattern`, and the kernel's own default is the bare word `core`
— a relative path, which means the dump is written into the crashing process's
current working directory.

That is the dangerous case. A daemon's working directory is not always a place
the operator has thought about, and a process that can be induced to `chdir`
somewhere writable will drop its memory — session tokens, decrypted
configuration, private keys — into a directory an attacker is watching. Writing
cores into `/tmp` is the same failure stated explicitly.

KERNEL-0005 covers the related and separate question of whether *setuid*
programs dump at all. Both are needed: KERNEL-0005 protects privileged memory,
this one protects everything else.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/kernel/core_pattern` |
| Daemon default when unset | The parameter always exists. **The kernel's compiled-in default is `core`**, which this check fails. Distributions override it. |
| Reference | `core(5)` |

A pattern beginning with `|` pipes the dump to the program named immediately
after the pipe; the kernel requires that program's path to be **absolute** and
silently discards the dump otherwise. Any other pattern is a filename, subject
to `%` expansion, resolved relative to the crashing process's working directory
unless it begins with `/`.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| systemd hosts | `/usr/lib/sysctl.d/50-coredump.conf` sets `\|/usr/lib/systemd/systemd-coredump …` | Not verified on live hosts |
| Ubuntu | `apport` sets its own piped handler while installed | Not verified on live hosts |
| Container images, minimal installs | Often left at the kernel default `core` | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | pattern begins with `\|` and the handler path is absolute | — | which handler receives dumps |
| PASS | pattern begins with `\|` and the handler path is relative | — | that dumps are being **discarded**, because the kernel requires an absolute handler path |
| PASS | pattern is an absolute path outside the known world-writable directories | — | the path, and that this check cannot inspect its permissions |
| FAIL | pattern is a relative path | MEDIUM | that dumps land in the crashing process's working directory |
| FAIL | pattern is an absolute path under `/tmp`, `/var/tmp` or `/dev/shm` | MEDIUM | which world-writable directory receives process memory |
| UNKNOWN | pattern is empty | — | `ambiguous_system_state` |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| SKIPPED | runner-decided | — | — |

**The relative-handler case is a PASS, deliberately.** No memory reaches the
filesystem, so the exposure this check is about does not occur. The detail says
the dumps are being discarded, because an operator relying on crash collection
has a broken configuration and nothing else on the host will tell them.

Where the running value fails and a configuration file sets a different value,
the detail names the file and line and points at KERNEL-0007.

## 6. Where this check cannot know

- **the permissions of the destination directory.** A check is a pure function
  over facts and cannot stat anything. An absolute path outside the known
  world-writable directories passes with the detail telling the reader to
  verify the directory themselves. The alternative — reasoning about arbitrary
  paths — would be guessing
- an empty pattern → `UNKNOWN(ambiguous_system_state)`. What the kernel does in
  that state is not documented and has varied
- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- whether core dumps are reachable at all. `RLIMIT_CORE` of 0, a systemd
  `LimitCORE=0`, or a filesystem that is full all prevent a dump regardless of
  this pattern, and none of them is visible here
- **the `%` expansions are not evaluated.** `/var/crash/%h/core` may land
  anywhere the hostname says. The check judges the literal prefix

## 7. Known false positives

A host writing cores to an absolute path in a directory that is in fact
world-readable passes this check. That is stated in the detail rather than
hidden, but it is a PASS this check cannot convert into a FAIL without the
filesystem facts that the FILESYS module will provide.

## 8. Remediation

| | |
|---|---|
| Summary | Pipe core dumps to an absolute-path handler, or write them to a directory only root can read. |
| Effort | LOW |
| Steps | prefer the distribution's crash handler; otherwise `\|/bin/false` to discard; otherwise an absolute path in a root-owned `0700` directory with a retention policy |
| Commands | `sysctl kernel.core_pattern`, `sysctl -w kernel.core_pattern='\|/bin/false'` |
| **Caution** | **Required.** Switching to a discarding handler removes the crash reports an operator may be relying on to diagnose production failures. |

## 9. Control mappings

- `nist-800-53-r5` SC-4
- `nist-800-53-r5` SI-11

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | piped to `systemd-coredump` | PASS |
| `kernel-weak` | the kernel default `core` | FAIL |
| `kernel-partial` | `/var/crash/core.%e.%p` | PASS, detail asks the reader to verify permissions |
| `kernel-drift` | `/tmp/core.%e.%p` running, systemd handler configured | FAIL, detail names both `/tmp` and the drift |
| `kernel-unparseable` | empty pattern | UNKNOWN(`ambiguous_system_state`) |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
