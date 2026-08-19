# FILESYS-0001 — No setuid or setgid executable is writable by group or other

| Field | Value |
|---|---|
| **ID** | `FILESYS-0001` |
| **Module** | FILESYS |
| **Base severity** | CRITICAL |
| **Tags** | filesys, suid, privilege-escalation, permissions |
| **Facts required** | `fs.suid`, `fs.sgid` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No file carrying the setuid or setgid bit has a group- or other-write bit set
(`mode & 0o022`).

## 2. Why this is a root shell, not a permissions problem

A setuid executable runs with its **owner's** privileges rather than the
caller's — usually root's. That is the entire point of the mechanism and it is
why `passwd`, `sudo` and `mount` work.

It also means the file's *contents* are executed as root by anybody who runs
it. So a setuid binary a non-root account can write is a root shell with a
waiting period: the account overwrites the file with anything it likes, waits
for the next person to run it — or runs it themselves — and the code executes
as the owner. No exploit, no vulnerability, no authentication step.

setgid is the same mechanism one privilege level down.

## 3. Why this check needs no allowlist

This is what makes it trustworthy, and it is the distinction from FILESYS-0002.

The check does not ask whether a particular binary *should* be setuid. It
asserts a property that **no legitimate setuid executable has on any
distribution**: being writable by someone other than its owner. A finding here
is wrong only if the file is not really setuid or not really writable, and both
came from the same `stat`.

The runbook forbids a hardcoded list of blessed binaries precisely because such
a list silently excuses whatever an attacker names their implant after. Nothing
here is excused.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every setuid/setgid file is owner-writable only | — | the count; if zero, **that the host has none at all** rather than "all 0 are fine" |
| FAIL | one or more are group- or other-writable | CRITICAL | each path, and that this is a root shell rather than untidiness |
| UNKNOWN | the walk did not finish | `source_truncated` | which limit fired and how much was examined |

The FAIL is never gated on walk completeness. A setuid binary the walk found is
one that exists; stopping the traversal afterwards cannot unmake it. Only the
PASS — a claim about everything never examined — is converted to UNKNOWN.

## 5. Where this check cannot know

- **whether the binary should be setuid at all.** That needs package metadata
  this tool does not collect
- **whether it has already been modified.** The mode says who *can* write it,
  not who did. The remediation's second step is `rpm -Vf` / `dpkg --verify`
- **ACLs.** Only the classic mode bits are read; a POSIX ACL granting write is
  invisible here
- **filesystems mounted `nosuid`**, where the bit is inert. FILESYS-0007 and
  FILESYS-0009 check that separately, and a `nosuid` mount does not make this
  finding wrong — remounting is one command

## 6. Known false positives

None known. Every legitimate setuid binary on every mainstream distribution is
writable by root alone.

## 7. Remediation

| | |
|---|---|
| Summary | Remove group and other write, then establish whether the file was already modified. |
| Effort | LOW |
| Steps | **Treat it as possibly already replaced**; compare against the package's copy with `rpm -Vf` or `dpkg --verify`; `chmod go-w`; ask whether it needs the setuid bit at all; find out how the mode drifted, because `chmod -R` on a bin directory will do it again |
| Commands | `find / -xdev -type f -perm /6000 -perm /022 -ls`, `rpm -Vf <path>` |
| **Caution** | Removing the setuid bit from a binary that needs it breaks whatever depends on it, sometimes only for non-root users. Remove the *write* bits first — that closes the escalation immediately and changes nothing else. |

## 8. Control mappings

- `nist-800-53-r5` AC-6
- `nist-800-53-r5` CM-5
- `nist-800-53-r5` SI-7

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | three setuid binaries, all mode 4755 | PASS |
| `filesys-suid-writable` | a vendor helper at mode 4775 | FAIL, CRITICAL |
| `filesys-suid-outside` | setuid binaries in odd places, all 4755 | PASS — 0002's finding, not this one's |
| `filesys-truncated` (capped walk) | nothing wrong, walk cut short | UNKNOWN, `source_truncated` |
