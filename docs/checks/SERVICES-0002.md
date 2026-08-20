# SERVICES-0002 — Network discovery and RPC portmapping services are not enabled

| Field | Value |
|---|---|
| **ID** | `SERVICES-0002` |
| **Module** | SERVICES |
| **Base severity** | MEDIUM |
| **Tags** | services, systemd, attack-surface, network |
| **Facts required** | `services.units` |
| **Since catalog** | 9 |
| **Platforms** | Linux, systemd hosts only |

## 1. What is tested

None of `avahi-daemon`, `cups-browsed` or `rpcbind` is enabled, under any of the
unit names the major distributions ship them as.

## 2. Why exactly these three, and no more

"Unnecessary services" is a category that invites an ever-growing list, and a
check that fails on a print server for running a print server is noise. Noise is
how a catalog trains people to ignore it, and an ignored catalog is worse than a
smaller one.

These three were selected because they share one specific property: they open a
listening socket to the local network **by default**, they arrive enabled as
part of a desktop-oriented package set rather than by anybody's decision, and
the workload that needs them is narrow and known to whoever runs it.

| Unit | What it costs |
|---|---|
| `avahi-daemon` | mDNS/DNS-SD. Announces the host's name, addresses and services to every machine in the broadcast domain, and answers queries about them. An attacker landing on any host on the segment gets an inventory of the others without sending a scan |
| `rpcbind` | The portmapper. Publishes which RPC service is on which port to anyone who asks, and has spent years on abuse lists as a UDP amplification reflector — a small query returns a large answer to a spoofed source |
| `cups-browsed` | Discovers and configures printers announced over the network. It acts on unauthenticated broadcast input, and its history of remote code execution follows directly from that design |

## 3. The judgement is a policy one, and the check says so

A print server should run CUPS. An NFS server needs `rpcbind`. A desktop fleet
may want mDNS. What this check asserts is that these services should be present
because somebody **decided** they should be — and the common case, a server
image that inherited them from a desktop package set, is not that.

Where the service is intentional, the right response is a suppression with the
reason recorded. A recorded decision is worth more than a silent exception: it
survives the next audit, and it survives the person who made it leaving.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | none of the set resolves to `enabled` | — | which are installed-but-off and how many are absent |
| FAIL | one or more resolve to `enabled` | MEDIUM | which units, what they advertise, **and that a suppression is the right answer if the role is intentional** |
| NOT_APPLICABLE | no systemd unit directory on this host | — | that another init system governs services here |
| UNKNOWN | a unit directory could not be listed completely | `insufficient_privileges` | that the PASS rests on absence |

The PASS is guarded and the FAIL is not, for the reason set out in
SERVICES-0001 §5: a directory we could not read might hold the symlink that
decides a negative conclusion, and cannot unmake a positive one.

## 5. Where this check cannot know

- **whether the host serves the role.** Nothing on disk says "this is a print
  server". That judgement is the operator's, and the finding is written to be
  suppressible rather than to be argued with
- **whether the daemon is running**, or reachable, or firewalled
- **the NFS version in use.** NFSv3 needs `rpcbind`; NFSv4 does not. Telling
  them apart needs mount state this module does not collect
- **`inetd`-style equivalents** of the same functions

## 6. Known false positives

A print server, an NFSv3 server or client, and a desktop fleet using `.local`
name resolution. All three are legitimate, all three should be suppressed with
the reason recorded, and none of them makes the observation wrong.

## 7. Remediation

| | |
|---|---|
| Summary | Disable the service, or record the decision to keep it as a suppression. |
| Effort | LOW |
| Steps | Decide whether the host serves the role (`nfsstat -m` names the NFS version per mount); `systemctl disable --now` **both** the `.socket` and the `.service` for socket-activated units, or the socket starts the service on the next connection; purge the package where the role is settled; where it is needed, bound it with a listen-address and a firewall rule rather than removing it |
| Commands | `systemctl is-enabled avahi-daemon.service cups-browsed.service rpcbind.service`, `ss -lnp \| grep -E ':(111\|631\|5353)\b'` |
| **Caution** | **Required.** Disabling `rpcbind` on a host that mounts NFSv3 shares breaks those mounts at the next boot, and the failure looks like a network problem rather than a configuration one. |

## 8. Control mappings

- `nist-800-53-r5` CM-7
- `nist-800-53-r5` SC-7

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `services-compliant` | none of the set installed | PASS |
| `services-discovery` | `avahi-daemon.service` and `rpcbind.socket` enabled, `cups-browsed` installed but off | FAIL, MEDIUM |
| `services-absent` | no systemd on this host | NOT_APPLICABLE |
| `services-denied` | `/etc/systemd/system` refuses traversal | UNKNOWN, `insufficient_privileges` |
