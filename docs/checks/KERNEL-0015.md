# KERNEL-0015 — Source-routed packets are refused on every network interface

| Field | Value |
|---|---|
| **ID** | `KERNEL-0015` |
| **Module** | KERNEL |
| **Base severity** | MEDIUM |
| **Tags** | kernel, network, spoofing, routing |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 3 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No non-loopback interface accepts source-routed packets — that is, for every
such interface, `net.ipv4.conf.all.accept_source_route` **and** that
interface's own `accept_source_route` are not both non-zero.

## 2. Why it matters

A source-routed packet carries its own return path. The sender dictates which
hops the reply traverses, which lets an attacker steer traffic through a
machine they control, reach addresses that are not routable from where they
are, and receive replies to a source address they have spoofed — because the
reply follows the attached route rather than the routing table.

There is no legitimate modern use. IP source routing was deprecated for exactly
these reasons and RFC 7126 records that the correct handling on a host is to
drop such packets.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/net/ipv4/conf/<interface>/accept_source_route`, enumerated from the directory |
| Daemon default when unset | The parameter always exists per interface. Kernel default is TRUE on a router, FALSE on a host. A new interface inherits `conf.default` **at creation time**. |
| Reference | `Documentation/networking/ip-sysctl.rst`, RFC 7126 |

### The combining rule — and why it is not KERNEL-0008's

The kernel takes the **logical AND** of `conf/all` and the interface's own
value: an interface accepts source routing only when both are non-zero
(`IN_DEV_ANDCONF`). For `rp_filter`, KERNEL-0008's parameter, it takes the
**maximum** (`IN_DEV_MAXCONF`).

The two rules point in opposite directions and copying one to the other
produces a confidently wrong verdict:

| | `rp_filter` (KERNEL-0008) | `accept_source_route` (this check) |
|---|---|---|
| Combining | `max(all, iface)` | `all AND iface` |
| `all = 0`, `iface = 1` | filtering **on** for that interface | source routing **off** everywhere |
| Safe when | either is ≥ 1 | either is 0 |

`conf.all = 0` is therefore decisive on its own here: no interface can accept,
whatever its own value says. The `kernel-partial` fixture encodes exactly this
case, and `TestSourceRouteCombiningRuleIsAndNotMax` asserts it.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian, Ubuntu, RHEL | Ship `0` for `all` and `default` | Not verified on live hosts |
| Hosts with `net.ipv4.ip_forward=1` | Kernel default for the parameter is TRUE on a router | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | `conf.all` is 0 | — | that the AND can never be true, plus any interfaces carrying a non-zero value that would take effect if `conf.all` were raised |
| PASS | every non-loopback interface is 0 | — | how many interfaces were considered |
| FAIL | `conf.all` is non-zero and at least one non-loopback interface is non-zero | MEDIUM | which interfaces, and the value of `conf.all` |
| NOT_APPLICABLE | no non-loopback interface exists | — | that no path exists on which a source-routed packet could arrive |
| UNKNOWN | the interface list could not be enumerated | — | `fact_not_collected` |
| UNKNOWN | no interface was observed accepting, but some value could not be resolved | — | `insufficient_privileges` |
| SKIPPED | runner-decided | — | — |

**Loopback is excluded**, as in KERNEL-0008: a source-routed packet cannot
arrive over `lo`. **`conf.default` is not judged** — it is the template copied
into interfaces created later and governs no traffic today.

## 6. Where this check cannot know

- the interface directory could not be listed, or the listing was incomplete →
  `UNKNOWN(fact_not_collected)`. Reporting on a partial interface list would
  let "none accepting" mean "we did not look at the one that does"
- an interface is non-zero and `conf.all` could not be read → that interface's
  verdict depends on a value we do not have, so it counts as unresolved
- **the negative result requires a complete view; the positive one does not.**
  An interface observed accepting source routing is reported as FAIL even when
  other values are unreadable, because a disagreement we watched happen is a
  disagreement that exists. Only "nothing accepts" needs everything read. This
  is the same asymmetry the shared filesystem walker enforces (ADR-0014)
- **this check says nothing about IPv6.** There is no `accept_source_route` for
  IPv6; routing headers are governed elsewhere, and asserting IPv6 safety from
  an IPv4 parameter would be a false assurance
- a firewall may already drop source-routed packets regardless of this
  parameter, and no sysctl reports that

## 7. Known false positives

Essentially none. Source routing has no modern legitimate use on a host. A
router that genuinely needs it should suppress with a justification.

## 8. Remediation

| | |
|---|---|
| Summary | Set `net.ipv4.conf.all.accept_source_route` to 0 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply to `all` and `default`; persist; verify per interface. Setting `conf.all` to 0 is sufficient on its own because of the AND; setting the per-interface values too keeps the host safe if `conf.all` is later raised |
| Commands | `sysctl -w net.ipv4.conf.all.accept_source_route=0` |
| **Caution** | Not required. No legitimate traffic depends on source routing. |

## 9. Control mappings

- `nist-800-53-r5` SC-7
- `nist-800-53-r5` SC-8

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | every value 0 | PASS |
| `kernel-weak` | `all`=1, `eth0`=1 | FAIL |
| `kernel-partial` | `all`=0, `eth0`=1 — the AND rule decides | PASS, detail names `eth0` as latent |
| `kernel-loopback-only` | no non-loopback interface | NOT_APPLICABLE |
| `kernel-denied` | values unreadable | UNKNOWN(`insufficient_privileges`) |
