# NETWORK-0001 — A host-based firewall is configured

| Field | Value |
|---|---|
| **ID** | `NETWORK-0001` |
| **Module** | NETWORK |
| **Base severity** | HIGH |
| **Tags** | network, firewall, attack-surface |
| **Facts required** | `network.firewall` |
| **Since catalog** | 10 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

At least one firewall configuration exists **and holds statements**.

Both halves matter. See §3 for why a file's existence is not enough.

## 2. Why a host firewall and not the perimeter

A perimeter is a statement about where an attacker is, and it stops being true
the moment one is inside it: a compromised workstation on the same VLAN, a
container escaping onto the host network, a cloud security group edited to
unblock a deployment and never edited back. The host firewall is the only
ruleset that does not depend on that assumption.

What it defends against specifically is **the service nobody decided to run**.
A package installs a daemon listening on all interfaces; a development build
ships with a debug port; an operator binds a database to `0.0.0.0` to test
something. None of those is visible until somebody scans for it, and every one
is closed by a default-deny host firewall without anybody having to notice.

## 3. An empty configuration file is not a firewall

Debian's `nftables` package installs `/etc/nftables.conf` whether or not
anybody has written a rule in it — the shipped file is entirely comments. A
check that treated the file's existence as protection would report every host
with that package installed as firewalled, which is a false PASS produced by a
dependency somebody else chose.

The fact therefore counts non-blank, non-comment lines, and
`FirewallSource.Active()` requires more than zero.

A **manager** has a second condition: `ufw disable` leaves every rule in the
file and applies none of them. `ENABLED=no` in `ufw.conf` is not a firewall,
and it is the state that most reliably survives an audit of the ruleset itself
— the file reads correctly and the host is open. The finding distinguishes that
case from an empty file, because they are different mistakes.

## 4. What is read

| Kind | Paths | Role |
|---|---|---|
| nftables | `/etc/nftables.conf`, `/etc/sysconfig/nftables.conf` | saved ruleset |
| iptables | `/etc/sysconfig/iptables`, `/etc/sysconfig/ip6tables`, `/etc/iptables/rules.v4`, `/etc/iptables/rules.v6` | saved ruleset |
| ufw | `/etc/ufw/ufw.conf`, `/etc/default/ufw` | manager |
| firewalld | `/etc/firewalld/firewalld.conf` | manager |

**No ruleset contents reach the fact.** A firewall configuration is a map of
the network — internal ranges, which hosts reach which ports, where the
management network is — and a bundle designed to travel would carry it wherever
the bundle is filed. Only the derived properties the checks read are kept, plus
the single policy line a finding has to quote. Same reasoning as ADR-0015 and
the CRON collector.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | at least one active configuration | — | which kind, which file, and that the loading unit is a separate question |
| FAIL | no configuration file at all | HIGH | that every listening port is reachable from anywhere that can route to it |
| FAIL | a file exists with no statements | HIGH | **that an empty ruleset is not a firewall**, and why the file exists anyway |
| FAIL | a manager is configured with `ENABLED=no` | HIGH | that every rule is present and none applies |
| UNKNOWN | a candidate file could not be read | `insufficient_privileges` | that the file we were refused could be the firewall |

The PASS is unguarded — we read a configuration, and nothing unread can unmake
it. The FAIL rests on absence and is wrapped (ADR-0014).

## 6. Where this check cannot know

- **whether the ruleset is loaded.** This is the module's central limit and it
  is stated in the PASS detail. A host with a perfect `nftables.conf` and a
  disabled `nftables.service` has no firewall. That half is visible to the
  SERVICES module, and neither module claims the other's
- **whether the rules are any good.** A default-deny ruleset that allows every
  port passes this check. NETWORK-0002 tests the default; nothing tests the
  allow list, because what should be allowed is a property of the workload
- **rules applied by something else.** A cloud security group, a hypervisor
  filter, or an orchestrator's network policy may be doing the work. The host
  is still unprotected against anything inside that boundary
- **`iptables-nft` versus legacy.** Both write the same saved-rule files

## 7. Known false positives

A container, which usually inherits the host's netfilter rules and is not
expected to carry its own; and a host whose filtering is genuinely done
upstream by a hypervisor or a cloud security group. Both are legitimate
architectures and both should be suppressed with the reasoning recorded — the
observation stays correct in each case.

## 8. Remediation

| | |
|---|---|
| Summary | Configure a default-deny host firewall permitting only what this host is meant to offer. |
| Effort | MEDIUM |
| Steps | Enumerate listeners with `ss -tulpn` first — every entry is either intended or a finding of its own; pick the tool the distribution manages; **set the default before adding rules**; allow ssh first, from a session you can afford to lose; enable it and make it survive a reboot; verify from another host |
| Commands | `ss -tulpn`, `ufw status verbose`, `nft list ruleset` |
| **Caution** | **Required.** Enabling default-deny over ssh disconnects you if the ssh rule is wrong, and the host keeps running with no way in. Keep a second session open; on a host you cannot physically reach, schedule a job that disables the firewall in ten minutes unless you cancel it. |

## 9. Control mappings

- `nist-800-53-r5` SC-7
- `nist-800-53-r5` CM-7
- `nist-800-53-r5` AC-4

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `network-nftables` | default-deny nftables ruleset | PASS |
| `network-ufw` | ufw enabled, policy in a second file | PASS |
| `network-accept` | a default-accept ruleset — still a firewall | PASS |
| `network-none` | no configuration of any kind | FAIL, HIGH |
| `network-empty` | Debian's stock comments-only `nftables.conf` | FAIL, HIGH |
| `network-denied` | the one file present is unreadable | UNKNOWN, `insufficient_privileges` |
