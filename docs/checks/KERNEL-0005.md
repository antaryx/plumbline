# KERNEL-0005 — Setuid programs do not write core dumps

| Field | Value |
|---|---|
| **ID** | `KERNEL-0005` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, credential-theft, information-disclosure |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

The running value of `fs.suid_dumpable` is `0`.

## 2. Why it matters

A core dump is a copy of a process's memory written to disk. When a setuid
program dumps core, that memory belongs to the privileged identity the program
assumed — it can hold password hashes, private keys, decrypted secrets and the
contents of files the invoking user cannot read — and the dump lands somewhere
the invoking user often can.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/fs/suid_dumpable` |
| Daemon default when unset | The parameter always exists. Kernel default is `0`. |
| Reference | `proc(5)`, `Documentation/admin-guide/sysctl/fs.rst` |

`0` setuid programs never dump. `1` they dump like any other program. `2` they
dump but only root may read the result.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| All mainstream | Ship `0`; `2` appears on hosts configured for crash collection | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value is 0 | — | that setuid and setgid programs do not dump |
| FAIL | running value is 1 | MEDIUM | that an unprivileged user can obtain privileged memory by crashing a setuid program |
| FAIL | running value is 2 | LOW | that privileged memory still reaches the disk and may be captured by backups |
| FAIL | any other integer | MEDIUM | the observed value and that it is undocumented |
| NOT_APPLICABLE | parameter absent | — | that the kernel does not expose it |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

The two FAIL severities are deliberate. `2` is a real exposure and a materially
smaller one than `1`, and an operator triaging a list of findings needs that
difference visible rather than buried in the detail text.

## 6. Where this check cannot know

- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`

The check does not inspect `kernel.core_pattern`. A host may pipe cores to a
handler that discards them, or to one that ships them off the machine, and
neither is visible here. That is a separate check and is not in this batch.

## 7. Known false positives

Hosts running a crash-collection service (`systemd-coredump`, `abrt`,
`apport`) legitimately set `2`. Where the collector stores dumps with
appropriate permissions and retention, this is a considered choice and a
candidate for suppression with a justification.

## 8. Remediation

| | |
|---|---|
| Summary | Set `fs.suid_dumpable` to 0 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, verify; collect crash dumps in a controlled directory rather than lowering this globally |
| Commands | `sysctl -w fs.suid_dumpable=0` |
| **Caution** | Not required. |

## 9. Control mappings

- `nist-800-53-r5` SC-4
- `nist-800-53-r5` SI-11

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 0 | PASS |
| `kernel-weak` | value 1 | FAIL / MEDIUM |
| `kernel-partial` | value 2 | FAIL / LOW |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
