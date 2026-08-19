# SERVICES-0004 — Every enabled unit resolves to a unit file that exists

| Field | Value |
|---|---|
| **ID** | `SERVICES-0004` |
| **Module** | SERVICES |
| **Base severity** | MEDIUM |
| **Tags** | services, systemd, integrity, symlink |
| **Facts required** | `services.units` |
| **Since catalog** | 9 |
| **Platforms** | Linux, systemd hosts only |

## 1. What is tested

Every enablement symlink in every `.wants` and `.requires` directory resolves to
a path that exists.

This is the check the `Readlink` seam was added for (WP-21), and it is only
answerable *because* enablement is a symlink: the link records what an
administrator turned on, and the target records whether the software is still
there.

## 2. How the two come apart

An enablement symlink and the unit file it points at are separate objects, and
ordinary operations separate them:

- a package removed without disabling its units first
- a unit file deleted by hand
- a vendor path that moved between distribution releases
- a configuration-management run that wrote the link before the payload

Each leaves `/etc/systemd/system/<target>.wants/<unit>` pointing at nothing.

**systemd's response is to log `Unit <name> not found` once during boot and
carry on.** Nothing else marks it. `systemctl is-enabled` still answers
`enabled`, because the symlink is what that command reads. The operator's belief
that the service is enabled is *correct*; their belief that it runs is not, and
there is no routine moment at which those two diverge visibly.

## 3. Why it is a security finding and not tidiness

**What dangled decides the impact.** A dangling link to `auditd`, to a firewall
unit, to a log shipper or to an EDR agent is a control everybody believes is in
place and which has not run since the package was removed. That is the most
expensive way for a control to fail, because it also suppresses the alarm that
would have reported its own absence.

**There is a sharper reading.** A symlink is a name that resolves at use. A
dangling one names a path that does not exist *yet*, and whoever can create a
file there decides what systemd loads at the next boot. Where the target's
parent directory is writable by a non-root account, the dangling link is not
inert — it is a scheduled execution slot waiting to be filled.

## 4. Relative targets

`systemctl` always writes an absolute target. An administrator running `ln -s`
does not, and **a relative target read as absolute names a completely different
file** — one that almost never exists, which would report a working enablement
as a dangling link.

The collector resolves relative targets against the link's own directory and
hands the result back **through the seam**, so `--root` still governs what is
examined. That is why the seam's `Readlink` returns the target as written and
resolves nothing itself: a seam that resolved would have dereferenced an
absolute link against the real host, which is what `--root` exists to prevent.

The raw target is preserved in the evidence rather than normalised away. It is
the string in the operator's filesystem and what `ls -l` will show them, and
where the raw and resolved forms differ, the difference is usually the bug.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every link resolves to an existing path | — | how many links, and that each has something for systemd to start |
| PASS | no enablement symlink exists at all | — | that a booting host's services are then static or started by something else |
| FAIL | one or more links resolve to nothing | MEDIUM | which units, **and that `systemctl` still reports them enabled** |
| UNKNOWN | a link's target could not be stat'ed | `insufficient_privileges` | that a link which cannot be followed may be the broken one |
| NOT_APPLICABLE | no systemd unit directory on this host | — | that another init system governs services here |
| UNKNOWN | a unit directory could not be listed completely | `insufficient_privileges` | that the PASS rests on absence |

**Dangling and unresolved are different states.** "The target is not there" and
"we were not allowed to look" produce opposite verdicts — FAIL and UNKNOWN — and
a single boolean would have collapsed them into a guess. This is the same
distinction `fact.CronPathState` draws, for the same reason.

The FAIL is not guarded by the incomplete-listing rule: we followed those links
and found nothing at the other end, and a directory we failed to list elsewhere
cannot unmake that.

## 6. Where this check cannot know

- **whether the unit *should* be enabled.** A dangling link may mean the package
  was removed on purpose and the link was forgotten, or that the package was
  removed by accident. Only the operator knows which
- **whether the target is writable by somebody.** The check reports the dangling
  link; whether its parent directory is a placement primitive needs a stat of a
  path outside the unit directories, which this module does not walk
- **units enabled in `/run`**, which is transient and empty in an image scan
- **`Alias=` links** between unit files, which are not enablement and are not
  examined here

## 7. Known false positives

A scan of a mounted image (`--root /mnt`) whose `/usr` is a separate filesystem
that was not mounted. Every vendor unit is then genuinely absent from the tree
being read, and every enablement link dangles. The finding is correct about what
was examined; the examination was incomplete.

## 8. Remediation

| | |
|---|---|
| Summary | Decide per link whether the service should return or the link should go, then remove the dangling links. |
| Effort | LOW |
| Steps | Ask systemd for its own account (`journalctl -b \| grep "Unit .* not found"`); for each broken link decide which half is wrong — reinstall the package, or remove the link; **use `systemctl disable` rather than `rm`**, because disable removes every link for that unit across all targets and deleting the one you found leaves the others; where disable refuses because the unit file is gone, `rm` the link and `systemctl daemon-reload`; treat a dangling link under a writable directory as urgent rather than untidy |
| Commands | `find /etc/systemd/system /usr/lib/systemd/system -xtype l -print`, `systemctl list-unit-files --state=enabled`, `journalctl -b -p warning \| grep -i 'not found'` |
| **Caution** | **Required.** `find -xtype l` follows the link to decide, so run it as a user who can read the target directories or it reports links as broken that are merely unreadable — the same distinction this check draws between FAIL and UNKNOWN. |

## 9. Control mappings

- `nist-800-53-r5` CM-6
- `nist-800-53-r5` SI-7

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `services-compliant` | four links, one of them **relative**, all resolving | PASS |
| `services-dangling` | `auditd.service` enabled, unit file removed | FAIL, MEDIUM |
| `services-unresolved` | link into `/opt` whose parent refuses traversal | UNKNOWN, `insufficient_privileges` |
| `services-absent` | no systemd on this host | NOT_APPLICABLE |
| `services-denied` | `/etc/systemd/system` refuses traversal | UNKNOWN, `insufficient_privileges` |
