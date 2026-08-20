# KERNEL-0007 — The running kernel parameters match the configured ones

| Field | Value |
|---|---|
| **ID** | `KERNEL-0007` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, configuration-drift, persistence |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

For every kernel parameter this module probes, the value in `/proc/sys` equals
the value the sysctl configuration files set.

## 2. Why it matters

`/proc/sys` is what the kernel is doing now. `/etc/sysctl.conf` and the
`sysctl.d` directories are what it will do after the next reboot. They are
different observations and they disagree more often than operators expect.

The disagreement runs in both directions and both matter. A parameter hardened
in a file but not applied means the host is unprotected today and someone
believes otherwise. A parameter hardened at runtime but absent from any file
means the protection disappears at the next reboot, silently, possibly months
later during an unrelated maintenance window.

This is the check the runbook requires the module to carry
(`BUILD-RUNBOOK-v0.2.md`, WP-16: "Record both, and make at least one check
compare them"). Reporting either number alone hides the state that is actually
dangerous.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/*` for running values; `/etc/sysctl.conf` and `*.conf` under `/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`, `/lib/sysctl.d` for configured values |
| Daemon default when unset | Not applicable — the check compares two observations and reports NOT_APPLICABLE when there is no configured value to compare against |
| Reference | `sysctl.conf(5)`, `sysctl.d(5)` |

**Application order implemented:** the drop-in directories in the order listed
above, files within a directory sorted by name, then `/etc/sysctl.conf` last.
Later settings override earlier ones.

## 4. Distribution variations

This is the check's one genuine ambiguity and it is handled rather than
resolved.

| Implementation | Order | Verified? |
|---|---|---|
| procps `sysctl --system` | `/run/sysctl.d`, `/etc/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`, `/lib/sysctl.d`, then `/etc/sysctl.conf` | From `sysctl(8)`; not verified against a live host |
| `systemd-sysctl` | merges all `sysctl.d` directories by **basename**, higher-precedence directory wins for an identical name, applied in basename order; Debian-family symlinks `/etc/sysctl.d/99-sysctl.conf` → `/etc/sysctl.conf` so it sorts last | From `sysctl.d(5)`; not verified against a live host |

The two agree that `/etc/sysctl.conf` effectively wins, and agree in every case
where a parameter is set in exactly one file. They can disagree when one
parameter is set in two different directories with two different values.

**Where they can disagree, this check returns `UNKNOWN` rather than picking a
winner.** A guess here is a confident claim about what the host will do after a
reboot, which is exactly the kind of statement an operator acts on. See §6.

> **Open question for a future work package.** Whether Plumbline should detect
> which implementation a host uses — and report a definite answer accordingly —
> is a design decision that needs an ADR, not a quiet choice inside a check.
> Until then the conservative `UNKNOWN` stands.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every comparable parameter agrees | — | how many were compared and that the settings survive a reboot |
| FAIL | at least one parameter differs | MEDIUM | how many differ, which ones, with both values in the evidence |
| NOT_APPLICABLE | no configuration file sets any probed parameter | — | that there is no configured value to compare against |
| NOT_APPLICABLE | the only configured parameters are ones this kernel does not implement | — | which ones, and that they have no effect |
| UNKNOWN | no drift found, but a configuration file could not be read | — | `insufficient_privileges` / `source_truncated`, per the read failure |
| UNKNOWN | no drift found, but a parameter is set in two files with different values | — | `ambiguous_system_state` |
| SKIPPED | runner-decided | — | — |

A drift that **was** found is reported as FAIL even when part of the
configuration is unreadable or ambiguous. A disagreement we observed is a
disagreement that exists; only the negative claim — "nothing drifts" — needs a
complete view. This is the same asymmetry the shared walker enforces
(ADR-0014).

## 6. Where this check cannot know

- a configuration file exists and cannot be read → the negative result becomes
  `UNKNOWN`, because the setting that disagrees may be in the file we could not
  open
- a parameter is set in two files with different values → `UNKNOWN(ambiguous_system_state)`;
  see §4
- a parameter that could not be read from `/proc/sys` is skipped entirely. Its
  own check already reports the `UNKNOWN`; repeating it here would count one
  gap as two findings
- a configured parameter this module does not probe is invisible to the check.
  It has no running value to compare and no way to know whether the kernel
  implements it, so it says nothing rather than guessing
- **something applied after boot** — a container runtime, a network manager
  hook, a configuration-management run — is indistinguishable from a file that
  was never applied. The check reports that they differ, not why

## 7. Known false positives

Hosts where a parameter is deliberately set at runtime for the current
workload and deliberately left out of the persistent configuration. This is
uncommon and usually accidental, but it is legitimate on ephemeral instances
whose configuration is applied by an image build rather than by `sysctl.d`.

## 8. Remediation

| | |
|---|---|
| Summary | Reconcile `/proc/sys` with the sysctl configuration, then apply the files. |
| Effort | LOW |
| Steps | decide which value is correct per parameter; apply the files where the configuration is right; add a drop-in where the running value is right; re-run the audit |
| Commands | `sysctl --system`, `sysctl --all` |
| **Caution** | **Required.** `sysctl --system` applies every setting in every file at once, not only the drifted ones. On a host whose files have not been applied in a long time this can change networking behaviour immediately, including on the interface carrying the operator's session. |

## 9. Control mappings

- `nist-800-53-r5` CM-6
- `nist-800-53-r5` CM-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | running and configured agree | PASS |
| `kernel-drift` | file hardened, host never rebooted | FAIL |
| `kernel-weak` | nothing configured at all | NOT_APPLICABLE |
| `kernel-absent` | configures Yama on a kernel without Yama | NOT_APPLICABLE, detail names the inert setting |
| `kernel-conflict` | two drop-ins set one parameter differently | UNKNOWN(`ambiguous_system_state`) |
| `kernel-denied` | a configuration file is unreadable | UNKNOWN(`insufficient_privileges`) |
