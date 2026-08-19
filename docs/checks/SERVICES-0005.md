# SERVICES-0005 — Unit directories and unit files are writable by root alone

| Field | Value |
|---|---|
| **ID** | `SERVICES-0005` |
| **Module** | SERVICES |
| **Base severity** | HIGH |
| **Tags** | services, systemd, permissions, privilege-escalation |
| **Facts required** | `services.units` |
| **Since catalog** | 9 |
| **Platforms** | Linux, systemd hosts only |

## 1. What is tested

Every unit directory that was listed, and every regular unit file in one, is
owned by `root:root` and has no group or other write bit.

## 2. Why this is root, not hygiene

A systemd unit file is a list of commands run as whatever user it names, at
boot, before anybody logs in. Write access to a unit file — or to the directory
holding one — is therefore **arbitrary code execution as root at the next
reboot**, with no exploit, no authentication step and nothing to detect, because
the resulting process is exactly the sort of thing that is supposed to start at
boot.

**Write access to the directory is as good as write access to the file.** A
non-root account that can write `/etc/systemd/system` can:

- create a unit file there, and `/etc` is the **highest-precedence** unit
  directory, so the file it places shadows the vendor's version of that unit
  outright;
- create a symlink in `<target>.wants/` and enable something the administrator
  never approved.

This is the same failure the CRON module checks, reached by a different
mechanism, and it is produced by the same ordinary accidents: a deployment
script that chowns a directory to its service account so the account can drop a
unit file in, an installer that leaves a package directory group-writable, an
administrator who ran `chmod -R` on the wrong path. None of those looks like an
attack while it is happening.

## 3. Ownership and writability are one exposure

They are reported together because they are the same thing reached two ways. A
file owned by an unprivileged account is one that account can `chmod` at will,
so "root-owned but group-writable" and "owned by `deploy`" mean the same thing
in the end: somebody other than root decides what the machine runs at boot.

## 4. Symlinks are excluded, deliberately

A symlink's own mode and owner govern nothing — the kernel ignores a symlink's
permission bits, and what matters is the file at the other end, which is
recorded separately when it lives in a unit directory. Judging the link would
report every mask (`lrwxrwxrwx` by construction) as world-writable, which is a
FAIL about the one configuration that guarantees a unit cannot run.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every listed directory and every regular unit file is root-owned and not group/other writable | — | how many directories and files were examined |
| FAIL | one or more are not | HIGH | each offending path and **which of the two faults** it has |
| NOT_APPLICABLE | no systemd unit directory on this host | — | that another init system governs services here |
| UNKNOWN | a unit directory could not be listed completely | `insufficient_privileges` | that the PASS rests on absence |

The FAIL is unguarded: we read those modes and owners, and nothing we failed to
read elsewhere can unmake them.

## 6. Where this check cannot know

- **whether the unit has already been modified.** A writable unit file should be
  treated as possibly *already written*, not merely as misconfigured. Comparing
  it against the package's version (`rpm -V`, `dpkg --verify`) is the follow-up,
  and this module does not read package metadata
- **what the unit runs.** No unit body is collected — see the module note in
  §7 — so a unit file that is root-owned and correct-moded passes regardless of
  what its `ExecStart` says
- **ACLs and capabilities.** Only the classic mode bits and the numeric owner
  are observed. A POSIX ACL granting write to a group is invisible here
- **the meaning of a uid.** Findings say `uid 1001`, not `uid 1001 (deploy)`.
  Resolving a number to a name means reading `/etc/passwd` as it exists during
  the scan, which is a different question and, on a bundle evaluated later, a
  different host's file entirely. See ADR-0016

## 7. A note on what is collected

The SERVICES collector reads **no unit file contents**. A unit body is operator
data — `ExecStart` command lines and `Environment=` assignments that routinely
carry credentials — and collecting it would put all of that into a bundle
designed to travel, for a set of checks that never look at it. The same
reasoning as ADR-0015 and the CRON collector, applied before the mistake rather
than after it.

## 8. Known false positives

**Fixtures evaluated through the live seam.** `scan --root testdata/fixtures/…`
reads real files carrying the ownership of whoever checked the repository out,
and git cannot record ownership. `cli-host` therefore fails this check
permanently and by construction, exactly as it fails the CRON ownership checks —
which is why it is documented as a *checkout baseline* rather than a clean host.
See ADR-0016.

## 9. Remediation

| | |
|---|---|
| Summary | Restore root ownership and remove group and other write on the paths named in the finding. |
| Effort | LOW |
| Steps | **Read the unit before changing its mode** (`systemctl cat <unit>`) — a unit a non-root account could write may already have been written; `chown root:root`; `chmod go-w` (conventionally 0644 for a file, 0755 for a directory); find out *why* it was wrong, because ownership by a service account almost always comes from a deployment step that wanted to drop a unit file in; where a service genuinely needs to manage units, give it a narrow `sudo` rule for specific units rather than write access to the directory; `systemctl daemon-reload` |
| Commands | `ls -la /etc/systemd/system /usr/lib/systemd/system`, `find /etc/systemd/system /usr/lib/systemd/system \( ! -user root -o -perm /022 \) -print` |
| **Caution** | **Required.** Treat a writable unit path as possibly already modified. Fix the mode, but also compare the unit against the package's version before concluding nothing happened. |

## 10. Control mappings

- `nist-800-53-r5` AC-3
- `nist-800-53-r5` AC-6
- `nist-800-53-r5` CM-5

## 11. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `services-compliant` | everything root-owned, 0755 / 0644 | PASS |
| `services-writable` | `/etc/systemd/system` at 0775, and a unit file owned by uid 1001 | FAIL, HIGH |
| `services-absent` | no systemd on this host | NOT_APPLICABLE |
| `services-denied` | `/etc/systemd/system` refuses traversal | UNKNOWN, `insufficient_privileges` |
