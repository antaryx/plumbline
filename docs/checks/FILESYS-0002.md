# FILESYS-0002 — No setuid or setgid executable outside the system binary directories

| Field | Value |
|---|---|
| **ID** | `FILESYS-0002` |
| **Module** | FILESYS |
| **Base severity** | HIGH |
| **Tags** | filesys, suid, persistence, privilege-escalation |
| **Facts required** | `fs.suid`, `fs.sgid` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every setuid and setgid executable is at or beneath one of the directories a
package manager installs into.

## 2. The classic persistence artifact

An attacker who gains root once copies a shell, sets the setuid bit and owns it
to root. From then on they regain root by running a file in their own home
directory — no exploit, nothing unusual in a log. **The technique survives
password changes, key rotation and the patch that closed the original hole.**

It is also, occasionally, an accident: a backup of `/usr/bin` restored into
`/var/tmp`, a build tree that preserved modes, an archive extracted as root
with `tar -p`. Neither is an attack and both are the same escalation path.

## 3. Location, not names — and why that matters

| Directories treated as legitimate |
|---|
| `/bin` `/sbin` `/usr/bin` `/usr/sbin` `/usr/libexec` `/usr/lib` `/usr/lib64` |
| `/usr/local/bin` `/usr/local/sbin` `/usr/local/libexec` `/usr/local/lib` `/opt` |
| `/snap` `/var/lib/snapd` `/var/lib/flatpak` |

The runbook is explicit: *"Allowlists for legitimately SUID binaries differ per
distribution and must come from facts, never from a hardcoded list that
silently excuses a real finding."*

A list of blessed **names** does exactly that — name the implant `pkexec` and
it is excused. A list of **directories** cannot, because writing into those
directories already requires the privilege the setuid bit would grant. A setuid
file there therefore tells you far less than one outside them, which is why the
rule is drawn here.

The snap and flatpak entries are included because both ship setuid helpers
under their own roots. Omitting them would fail every Ubuntu desktop for doing
something its vendor designed.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | all setuid/setgid files are in the listed directories | — | **that whether each should carry the bit is not answered here** |
| FAIL | one or more are outside them | HIGH | each path, and that this survives the fix for whatever granted root |
| UNKNOWN | the walk did not finish | `source_truncated` | which limit fired |

## 5. Where this check cannot know

- **whether a setuid binary inside those directories is legitimate.** That
  needs package metadata — `rpm -Va`, `dpkg --verify` — which this tool does not
  collect. FILESYS-0001 covers the property that *is* decidable without it
- **when the file appeared**, which is what distinguishes an attacker's artifact
  from a restored backup. `stat -c %z` bounds it during triage
- **whether the filesystem is mounted `nosuid`**, which makes the bit inert

## 6. Known false positives

A vendored application shipping a setuid helper outside `/opt` — some
commercial software installs under `/usr/local/<vendor>` (covered) or under a
bespoke root such as `/srv/app` (not covered). Suppress with the path and the
reasoning recorded.

## 7. Remediation

| | |
|---|---|
| Summary | Establish what the file is before removing it; if unaccounted for, treat the host as compromised. |
| Effort | MEDIUM |
| Steps | **Do not delete it first** — record path, `stat`, `sha256sum`; establish when it appeared from the inode change time; if nothing explains it, treat this as an incident rather than a misconfiguration; if a backup explains it, `chmod u-s,g-s`; mount `/home`, `/tmp` and `/var/tmp` `nosuid` so the bit is inert there |
| Commands | `find / -xdev -type f -perm /6000 -ls`, `stat <path>`, `sha256sum <path>` |
| **Caution** | **Required.** If this is an attacker's artifact, deleting it destroys the evidence and does not remove their access — they had root to create it. Preserve it and treat the finding as an incident before cleaning up. |

## 8. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` SI-4
- `nist-800-53-r5` SI-7

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | setuid binaries in `/usr/bin` and `/usr/sbin` | PASS |
| `filesys-suid-outside` | setuid shells in `/home/alice` and `/var/tmp`, both 4755 | FAIL, HIGH |
| `filesys-suid-writable` | a setuid helper under `/opt` | PASS — `/opt` is a package directory |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short | UNKNOWN, `source_truncated` |
