# SERVICES-0001 — No cleartext-credential network service is enabled

| Field | Value |
|---|---|
| **ID** | `SERVICES-0001` |
| **Module** | SERVICES |
| **Base severity** | HIGH |
| **Tags** | services, systemd, cleartext, network, legacy |
| **Facts required** | `services.units` |
| **Since catalog** | 9 |
| **Platforms** | Linux, systemd hosts only |

## 1. What is tested

No unit in the cleartext set has an enablement symlink that survives masking.

That is the whole proposition, and both halves of it are load-bearing. See §3
for why "enabled" is a symlink and §4 for why a mask outranks one.

## 2. Why these protocols

| Protocol | What crosses the wire |
|---|---|
| telnet | The whole session, password included, as plaintext |
| rsh / rlogin / rexec | Plaintext, and authenticated on `.rhosts` — which is to say on the client's own claim about who it is |
| FTP | Password in the clear on the control channel |
| TFTP | No authentication at all |

A password captured this way needs no cryptanalysis and no vulnerability.
Anyone on the path — a switch, a router, a compromised host on the same
segment, a cloud provider's virtual network — reads it as it goes past, along
with everything typed afterwards.

The r-commands are worse than merely cleartext. There is no secret involved at
all: the trust relationship *is* the credential, and it is forgeable by anyone
who can spoof a source address or take over a trusted host.

Every one of these has had a drop-in replacement for a quarter of a century.
The reason they survive is never that somebody chose them — it is a package
installed for its client tools, an image nobody has rebuilt, a migration that
finished years ago. That is precisely why it is worth checking rather than
assuming.

## 3. Source of truth: enablement is a symlink

`systemctl enable foo.service` writes no database row and sets no flag inside
the unit file. It reads the unit's `[Install]` section and creates

```
/etc/systemd/system/<target>.wants/foo.service -> /usr/lib/systemd/system/foo.service
```

`disable` removes that link. The link **is** the enablement, which is what
makes this answerable with no dbus, no `systemctl` and no privilege.

**Socket units are checked alongside service units.** These daemons are shipped
socket-activated now: `telnet.socket` is enabled and `telnet@.service` is
started per connection, so the `.service` is never enabled at all. A check
looking only for `telnet.service` finds nothing on a host running telnet.

## 4. Masking outranks enablement

`systemctl mask foo.service` replaces the unit file with a symlink to
`/dev/null` in `/etc/systemd/system`, which is the highest-precedence unit
directory. A masked unit **cannot be started by anything** — not by an
enablement symlink, not by another unit that `Requires=` it, not by an
administrator typing `systemctl start`.

So a unit with both a `.wants` symlink and a mask is **not** enabled, and this
check passes over it. Getting that backwards produces a FAIL about a service
that cannot run, which is a wrong verdict in the direction that matters most:
it sends somebody to disable something already off while the real findings go
unread. `services-masked` exists for this case alone.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | no unit in the set resolves to `enabled` | — | which of them are installed-but-off and how many are absent |
| FAIL | one or more resolve to `enabled` | HIGH | which units, and that credentials cross the wire in plaintext |
| NOT_APPLICABLE | no systemd unit directory on this host | — | that another init system governs services here and may be running the service |
| UNKNOWN | a unit directory could not be listed completely | `insufficient_privileges` | that the PASS rests on absence and the directory holding the answer was not read |

### Why the PASS is guarded and the FAIL is not

A PASS here is a **negative** conclusion: no enablement symlink was found. A
directory that could not be listed might hold exactly the symlink that decides
it, so the PASS is converted to UNKNOWN. The FAIL is a **positive** conclusion —
a symlink we read — and no directory we missed can unmake it. That asymmetry is
ADR-0014.

## 6. Where this check cannot know

- **whether the daemon is running.** Nothing on disk records that. `enabled`
  means "systemd will start it at boot", which is the durable property an audit
  is actually about; a daemon started by hand and never enabled does not appear
- **inetd and xinetd**, which are separate mechanisms this module does not read.
  A host serving telnet from `/etc/inetd.conf` passes this check
- **whether the port is reachable.** A firewall may make an enabled daemon
  unreachable. That is a mitigation, not a fix, and it is not visible here
- **static units.** A unit with no `[Install]` section cannot be enabled and has
  no symlink; it runs because another unit names it in `Wants=`. None of the
  units in this set is normally static

## 7. Known false positives

A lab or provisioning network that genuinely requires TFTP to serve boot images
to devices with no room for a TLS stack. The finding is still correct — the
protocol has no authentication — and the right response is a suppression with
that reasoning recorded, plus network isolation.

## 8. Remediation

| | |
|---|---|
| Summary | Disable and mask the cleartext service, and remove the package that ships it. |
| Effort | MEDIUM |
| Steps | Establish who still uses it (`ss -tnp`, `journalctl -u`); `systemctl disable --now`; **also `systemctl mask`**, because a package upgrade re-runs its preset and a merely disabled unit can come back enabled; purge the server package (the *client* package is separate and usually worth keeping); migrate callers to ssh / scp / sftp |
| Commands | `systemctl list-unit-files --state=enabled \| grep -Ei 'telnet\|rsh\|rlogin\|rexec\|ftp'`, `systemctl disable --now telnet.socket`, `systemctl mask telnet.socket` |
| **Caution** | **Required.** Masking a unit that something else `Requires=` makes that dependency fail, which on a hard dependency takes the depending unit down with it. Check `systemctl list-dependencies --reverse <unit>` first. |

## 9. Control mappings

- `nist-800-53-r5` AC-17
- `nist-800-53-r5` CM-7
- `nist-800-53-r5` IA-5
- `nist-800-53-r5` SC-8

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `services-compliant` | nothing in the set installed | PASS |
| `services-cleartext` | `telnet.socket` and `rsh.socket` enabled through socket activation | FAIL, HIGH |
| `services-masked` | `telnet.socket` both enabled **and** masked | PASS |
| `services-absent` | no systemd on this host | NOT_APPLICABLE |
| `services-denied` | `/etc/systemd/system` refuses traversal | UNKNOWN, `insufficient_privileges` |
