# KERNEL-0008 — Reverse-path filtering is enabled on every network interface

| Field | Value |
|---|---|
| **ID** | `KERNEL-0008` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, network, spoofing |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 2 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

For every non-loopback network interface, the effective reverse-path filter —
`max(net.ipv4.conf.all.rp_filter, net.ipv4.conf.<interface>.rp_filter)` — is
`1` or `2`.

## 2. Why it matters

Reverse-path filtering makes the kernel drop an incoming packet whose source
address it would not route back out of the interface the packet arrived on.
Without it, a host accepts packets claiming to come from anywhere, which is
what makes source-address spoofing useful: an attacker on one network segment
can impersonate an address on another, defeating any control that trusts a
source address and hiding the true origin of an attack.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/net/ipv4/conf/<interface>/rp_filter`, enumerated from the directory |
| Daemon default when unset | The parameter always exists per interface. A new interface inherits `net.ipv4.conf.default.rp_filter` **at creation time**; changing `default` afterwards does not alter existing interfaces. |
| Reference | `Documentation/networking/ip-sysctl.rst`, RFC 3704 |

**The combining rule is the part that is easy to get wrong.** The effective
value for an interface is the *maximum* of `conf.all.rp_filter` and that
interface's own setting — not `all` alone, and not the interface alone. A check
that read `conf.all` by itself would report a host as unfiltered while every
interface on it was in fact filtering, which is a confidently wrong verdict on
a large fraction of real hosts.

`0` no filtering. `1` strict: the reverse path must be the same interface.
`2` loose: the source must be routable via some interface.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Ubuntu | Ships `all` and `default` at `2` (loose) | Not verified on live hosts |
| RHEL family | Ships `all` at `1` (strict) | Not verified on live hosts |
| Debian | Ships `0` in some releases, relying on per-interface values | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every non-loopback interface has effective value ≥ 1 | — | how many interfaces, and which are in loose mode |
| FAIL | at least one non-loopback interface has effective value 0 | MEDIUM | which interfaces, and the value of `conf.all` |
| NOT_APPLICABLE | the host has no non-loopback interface | — | that no path exists on which a spoofed source could arrive |
| UNKNOWN | the interface list could not be enumerated | — | `fact_not_collected` |
| UNKNOWN | no interface's value could be read | — | `insufficient_privileges` |
| SKIPPED | runner-decided | — | — |

**Loose mode (2) passes.** It is a deliberate and correct choice on a
multi-homed host with asymmetric routing, and failing it would produce a
finding that a large class of legitimate hosts would suppress en masse — which
trains operators to suppress findings. The detail names the interfaces in loose
mode so a reader can judge for themselves.

**Loopback is excluded.** Loopback traffic never crosses a network boundary and
its reverse path is always `lo`. Distributions leave `lo` at 0 as a matter of
course, so judging it would fail on almost every host in the world for
something no operator can sensibly act on.

## 6. Where this check cannot know

- the interface directory could not be listed, or the listing was incomplete →
  `UNKNOWN(fact_not_collected)`. Reporting on a partial interface list would
  let "no unfiltered interfaces found" mean "we did not look at the unfiltered
  one"
- per-interface values unreadable → `UNKNOWN(insufficient_privileges)`
- an interface whose value alone is unreadable is named in the detail and
  excluded from the count, so a PASS never silently covers it
- **this check says nothing about IPv6.** There is no `rp_filter` for IPv6;
  the equivalent protection comes from firewall rules, and asserting IPv6
  safety from an IPv4 parameter would be a false assurance
- interfaces that appear after the scan are not covered. `conf.default` governs
  those and is deliberately not judged here, because it governs no traffic
  today

## 7. Known false positives

Routers, firewalls and multi-homed hosts with policy routing legitimately run
with reverse-path filtering off on transit interfaces, because the reverse path
genuinely differs from the forward path. These hosts should suppress with a
justification. This is the most likely source of false positives in the module.

## 8. Remediation

| | |
|---|---|
| Summary | Set `net.ipv4.conf.all.rp_filter` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | confirm the host does not rely on asymmetric routing; apply to `all` and `default`; persist; verify per interface |
| Commands | `sysctl -w net.ipv4.conf.all.rp_filter=1`, `sysctl -w net.ipv4.conf.default.rp_filter=1` |
| **Caution** | **Required.** Strict mode drops traffic on a host with asymmetric routing and can remove the operator's own access if they are connected over the interface that stops accepting replies. Verify from a second session before persisting. |

## 9. Control mappings

- `nist-800-53-r5` SC-7
- `nist-800-53-r5` SC-5

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | `all`=1, `eth0`=1, `lo`=0 | PASS — loopback is not judged |
| `kernel-weak` | every value 0 | FAIL |
| `kernel-partial` | `all`=0, `eth0`=2 — the maximum rule decides | PASS, detail names loose mode |
| `kernel-loopback-only` | no non-loopback interface | NOT_APPLICABLE |
| `kernel-denied` | per-interface values unreadable | UNKNOWN(`insufficient_privileges`) |
