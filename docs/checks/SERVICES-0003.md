# SERVICES-0003 — Exactly one time synchronisation daemon is enabled

| Field | Value |
|---|---|
| **ID** | `SERVICES-0003` |
| **Module** | SERVICES |
| **Base severity** | MEDIUM |
| **Tags** | services, systemd, time, logging, authentication |
| **Facts required** | `services.units` |
| **Since catalog** | 9 |
| **Platforms** | Linux, systemd hosts only |

## 1. What is tested

Exactly one unit from the time-synchronisation set resolves to `enabled`.

Both bounds are asserted, and they fail differently. **None** means the clock
drifts. **More than one** means two daemons fight over it, which is a distinct
and considerably more confusing failure than having neither.

## 2. Why an accurate clock is a security control

Three things break without it, and each breaks quietly.

**Log correlation.** An incident is reconstructed by ordering events across
hosts. A host whose clock is minutes out contributes events that appear in the
wrong place in the sequence — or appear to have happened *before* the intrusion
that caused them. The investigation does not fail loudly; it produces a timeline
that is wrong.

**Authentication.** Kerberos rejects tickets outside a five-minute skew by
design, because the timestamp is the replay defence. TLS certificates, signed
tokens, TOTP codes and short-lived cloud credentials all fail closed against a
drifted clock — and the operator debugging that will find nothing wrong with the
certificate.

**Scheduled work.** Certificate renewal, log rotation and credential rotation
run on timers. A clock that jumps can skip a window entirely.

## 3. Why two daemons is its own failure

They compete for the same UDP port and the same clock. The second to start fails
to bind and exits, and **which one that is depends on start order rather than on
configuration**. The host then synchronises through whichever daemon won, using
whichever server list that one was given — very often not the list the
administrator edited.

This is the ordinary outcome of installing chrony on a system already running
`systemd-timesyncd`: installing it does not disable the other.

## 4. Unit names differ per distribution for the same software

| Software | Red Hat family | Debian family |
|---|---|---|
| chrony | `chronyd.service` | `chrony.service` |
| ntpsec / ntp | `ntpd.service` | `ntp.service`, `ntpsec.service` |

A check written against one name reports "no time synchronisation" on the other,
which is a wrong verdict produced entirely by packaging. Every name is in the
set.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | exactly one enabled | — | which one, and that nothing competes with it |
| FAIL | none enabled | MEDIUM | that the clock will drift, and the consequences for logs, Kerberos and expiring credentials |
| FAIL | two or more enabled | MEDIUM | which ones, **and that the winner depends on start order rather than configuration** |
| NOT_APPLICABLE | no systemd unit directory on this host | — | that another init system governs services here |
| UNKNOWN | a unit directory could not be listed completely, and the outcome rested on absence | `insufficient_privileges` | that the conclusion rests on not having found a symlink |

### The polarity here is the reverse of SERVICES-0001, and it matters

In SERVICES-0001 the PASS is the conclusion drawn from absence. **Here the FAIL
is** — "no time daemon is enabled" is a claim about what is *not* on disk, so an
unreadable directory invalidates it exactly as it would invalidate a PASS.

The PASS is guarded too, for a different reason: it rests on the absence of a
*second* daemon.

The only unguarded branch is the two-or-more FAIL, which is purely positive: we
found them, and no directory we missed can unmake that. A helper that guarded
PASS alone would have left this check reporting "no time synchronisation is
configured" about a host whose configuration it never saw.

## 6. Where this check cannot know

- **whether the daemon is actually disciplining the clock.** Enabled is not
  running, and running is not synchronised. `timedatectl` and `chronyc tracking`
  answer that live; nothing on disk does
- **which servers it uses.** The configuration file is not read
- **the current offset.** A host with a correctly enabled daemon and a clock an
  hour out passes this check
- **VM guest agents.** A hypervisor may discipline the guest clock without any
  unit being enabled, which makes this a false positive on some virtualised
  fleets

## 7. Known false positives

A virtual machine whose clock is disciplined by a hypervisor guest agent
(`vmtoolsd`, `qemu-guest-agent` with a time provider), and containers, which
inherit the host's clock and have nothing to synchronise. Both are legitimate;
suppress with the reason recorded.

## 8. Remediation

| | |
|---|---|
| Summary | Enable exactly one time synchronisation daemon and mask the rest. |
| Effort | LOW |
| Steps | Choose one — chrony is the right default on almost anything; establish what is enabled now **including the one you did not install**; `systemctl enable --now` the chosen one; **mask** every other one (disable is not enough: installing an NTP package re-runs its preset and a merely disabled unit can come back enabled); point it at servers you control; verify with `chronyc tracking` and `timedatectl` that it is disciplining the clock rather than merely running |
| Commands | `timedatectl`, `systemctl list-unit-files --state=enabled \| grep -E 'chrony\|ntp\|timesync'`, `chronyc tracking` |
| **Caution** | **Required.** A host that has drifted for months will have its clock stepped when synchronisation starts, and a large backward step makes log timestamps go backwards. Expect it to be visible in the logs and note when it happened. |

## 9. Control mappings

- `nist-800-53-r5` AU-8
- `nist-800-53-r5` SC-45

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `services-compliant` | `chronyd.service` enabled, `systemd-timesyncd` installed but off | PASS |
| `services-notime` | both installed, neither enabled | FAIL, MEDIUM |
| `services-twoclocks` | `chronyd.service` **and** `systemd-timesyncd.service` both enabled | FAIL, MEDIUM |
| `services-absent` | no systemd on this host | NOT_APPLICABLE |
| `services-denied` | `/etc/systemd/system` refuses traversal | UNKNOWN, `insufficient_privileges` |
