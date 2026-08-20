# FILESYS-0009 — /home is a separate mount with nodev and nosuid

| Field | Value |
|---|---|
| **ID** | `FILESYS-0009` |
| **Module** | FILESYS |
| **Base severity** | LOW |
| **Tags** | filesys, mount, hardening |
| **Facts required** | `fs.mounts` |
| **Since catalog** | 11 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

`/home` appears in the mount table as its own mount point carrying `nodev` and
`nosuid`.

`noexec` is **reported and not required**. See §3 — it is the substance of this
check.

## 2. Why nodev and nosuid belong there without argument

Home directories are writable by the people who own them, which makes `/home`
the second place — after `/tmp` — that anything a user brings to the host ends
up.

| Option | What it removes | Cost to users |
|---|---|---|
| `nosuid` | a setuid binary in a home directory is inert — the persistence artifact FILESYS-0002 reports stops working | none |
| `nodev` | a device node there reaches nothing, closing FILESYS-0006's raw-disk path | none |

Nobody's workflow depends on setting the setuid bit in their own home
directory, and nobody's depends on creating a device node there. These two are
free.

## 3. noexec is observed, not required — and that is deliberate

Enforcing `noexec` on `/home` breaks:

- Python virtual environments
- local Go, Rust and C builds
- `node_modules` with native binaries
- every `~/.local/bin` on the host

Which is to say **most of what a developer workstation exists to do**. CIS
treats it as a separate, stricter item for exactly this reason.

On a server where nobody builds or runs anything from a home directory it is
worth setting, and the finding's detail says so. On a workstation, requiring it
would produce a failure whose right answer is to ignore it — and **a check whose
right answer is to ignore it teaches people to ignore the next one.** That is
the reasoning, and it is the same judgement the module applies to allowlists:
prefer fewer assertions that are always right to more that are sometimes noise.

The detail reports whether `noexec` is present either way, so an operator
hardening a server can see the gap without the check failing a laptop for it.

## 4. Separate filesystem, again

As with `/tmp`, `nodev` and `nosuid` are per-mount properties: a `/home` that is
a directory on the root filesystem cannot carry them. It also bounds the damage
a user filling their home directory can do — without it, `/home` fills `/` and
the host stops being able to log.

A host with **no `/home` at all** — a single-purpose appliance, a container —
has no subject here. The check reports the governing mount rather than
inventing a failure.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | separate mount with `nodev` and `nosuid` | — | the options as mounted, **and whether `noexec` is present**, with the workstation caveat |
| FAIL | not a separate mount | LOW | which mount governs it instead |
| FAIL | separate mount missing `nodev` or `nosuid` | LOW | which is missing and what its absence permits |
| UNKNOWN | the mount table could not be read or was truncated | `source_truncated` | that a partial table may be missing this entry |

Severity is LOW rather than MEDIUM because the two required options close paths
that other checks already report directly — FILESYS-0002 finds the setuid
binary, FILESYS-0006 finds the device node. This is defence in depth, and it is
scored as such.

## 6. Where this check cannot know

- **whether anyone actually uses home directories on this host.** A server with
  `/home` empty gets the same verdict as a workstation with fifty users
- **whether `noexec` would break anything**, which is why it is observed rather
  than required
- **home directories outside `/home`** — `/var/home`, `/export/home`, or a
  directory service placing them elsewhere. Only `/home` is examined
- **per-user quotas**, which are the other half of the availability argument

## 7. Known false positives

A container or an appliance with no real `/home`, and hosts using an
unconventional home directory root. Both are legitimate; suppress with the
reasoning recorded.

## 8. Remediation

| | |
|---|---|
| Summary | Mount `/home` as its own filesystem with `nodev` and `nosuid`; consider `noexec` only where nobody builds. |
| Effort | MEDIUM |
| Steps | If already separate, this is an fstab edit and `mount -o remount /home`; if not, it needs a filesystem, and moving an existing `/home` means `rsync -aHAX` with nobody logged in; verify with `findmnt`; **decide about `noexec` separately and on evidence**; if you add it, tell the people who use the host beforehand, because the failure mode is a permission-denied error on a binary that plainly exists |
| Commands | `findmnt /home`, `mount -o remount,nodev,nosuid /home`, `lsblk -f` |
| **Caution** | **Required.** Moving `/home` onto a new filesystem copies data while people may be using it. Do it with nobody logged in, use `rsync -aHAX` so ownership, ACLs and xattrs survive, and keep the old copy until the new mount is verified — a botched migration locks every non-root account out of its own files. |

## 9. Control mappings

- `nist-800-53-r5` CM-7
- `nist-800-53-r5` SC-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `filesys-clean` | separate ext4 with `nodev,nosuid` and **no** `noexec` | PASS — with `noexec` reported in the detail |
| `filesys-mounts-weak` | separate mount with neither option | FAIL, LOW |
| `filesys-mounts-unknown` | mount table unreadable | UNKNOWN, `source_truncated` |
