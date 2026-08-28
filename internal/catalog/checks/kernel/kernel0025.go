package kernel

import (
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0025 tests whether source routing and ICMP redirect acceptance are
// refused in the sysctl configuration, rather than merely at runtime.
var Check0025 = catalog.Check{
	ID:     "KERNEL-0025",
	Module: "KERNEL",
	Title:  "Source routing and ICMP redirects are refused in the sysctl configuration",

	Description: `Two ways a remote party can tell this host how to route, both
of them obsolete and both still enabled somewhere:

**Source routing.** A source-routed packet carries its own return path. Accept
one and an attacker chooses the route their reply takes, which lets them reach
a host they have no route to, bypass a firewall that filters on path, and
receive replies to a source address they have spoofed. RFC 7126 records that
the correct handling on a host is to drop these, and there is no modern
legitimate use.

**ICMP redirects.** A redirect is an unauthenticated packet that rewrites this
host's routing table. Accept one from an attacker on the same segment and
traffic to a chosen destination goes through them instead — a
man-in-the-middle that needs no ARP spoofing and leaves nothing on disk. A host
that does not route has no reason to take routing advice from the network.

All four keys must be 0: conf.all and conf.default for each. **default is not
redundant with all** — it is the template copied into interfaces created after
the files are applied, which is every container veth, VPN tunnel and hot-plugged
NIC on a modern host, and nothing else covers them.

The two parameters combine differently, which is why they are worth stating
separately even though the fix is the same line twice:

  - accept_source_route is the logical AND of conf.all and the interface's own,
    so conf.all at 0 refuses it everywhere.
  - accept_redirects on a host that does not forward is the logical OR, so
    conf.all at 0 refuses nothing on its own; the interface's own value has to
    be 0 too. It also **defaults to 1**, unlike accept_source_route, so the
    absence of any configuration is materially worse here.

A key set by a glob counts as set: a file writing net.ipv4.conf.*.accept_source_route
has configured every interface it matched, and a bare -net.ipv4.conf.all.…
line withholds that one key from the pattern deliberately.

This is a check about files. KERNEL-0015 computes the effective source-routing
value for each interface that exists right now; redirect acceptance has no
runtime counterpart yet.`,

	// Medium. Both give a network-adjacent attacker a way to redirect or
	// observe traffic without touching this host, which is more than the
	// spoofing findings offer and less than a local privilege escalation.
	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "sysctl", "persistence", "routing"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 29,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, requirementKeys(routingPersistent), persistRoutingCaveat); out != nil {
			return *out
		}

		failed, evidence := checkRequirements(sc, routingPersistent)
		if len(failed) > 0 {
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  "sysctl configuration",
				Detail:   capitaliseFirst(strings.Join(failed, "; ")) + ". Both parameters let a party on the network decide where this host sends packets, which is a position to read and rewrite traffic from rather than a weakness in it." + persistRoutingCaveat,
				Evidence: searchedEvidence(sc, evidence),
			}
		}

		return catalog.Outcome{
			Result:  finding.Pass,
			Subject: "sysctl configuration",
			Detail: "Source routing and ICMP redirect acceptance are both refused in the sysctl configuration, for the host-wide keys and for the template every interface created later inherits. A packet carrying its own return path is dropped and an unauthenticated redirect will not rewrite this host's routing table, after the next reboot and on interfaces that do not exist yet." +
				runningContradiction(sc, routingPersistent) + persistRoutingCaveat,
			Evidence: searchedEvidence(sc, evidence),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write all four keys as 0 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets them, patterns included: grep -rn 'accept_source_route\\|accept_redirects' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d.",
			"Create or extend a drop-in with all four lines: net.ipv4.conf.all.accept_source_route = 0, net.ipv4.conf.default.accept_source_route = 0, net.ipv4.conf.all.accept_redirects = 0, net.ipv4.conf.default.accept_redirects = 0.",
			"Set the default keys even though the all keys look sufficient. default is the template for interfaces created after the files are applied — container veths, VPN tunnels, hot-plugged NICs — and nothing else reaches them.",
			"Add the IPv6 equivalents where IPv6 is in use: net.ipv6.conf.all.accept_ra, net.ipv6.conf.all.accept_redirects and net.ipv6.conf.default.accept_redirects. IPv6 has no source-routing key to set, having removed the header, but router advertisements are the larger equivalent exposure.",
			"Apply without rebooting: sysctl --system, then confirm per interface with sysctl -a | grep -E 'accept_(source_route|redirects)'.",
			"Set net.ipv4.conf.all.secure_redirects = 0 as well if nothing needs redirects at all; on its own it only narrows acceptance to the current default gateways rather than refusing them.",
		},
		Commands: []string{
			"sysctl -a 2>/dev/null | grep -E 'accept_(source_route|redirects)'",
			"grep -rn 'accept_source_route\\|accept_redirects' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Refusing redirects is safe on a host with a single default gateway and changes routing behaviour on one that depends on being redirected — an unusual arrangement, but check the routing table on a router or a multi-homed host first. Refusing source routing breaks nothing in modern use; the feature has been deprecated for two decades.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — ip-sysctl accept_source_route and accept_redirects", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
		{Title: "RFC 7126 — Filtering of IP-Optioned Packets", URL: "https://www.rfc-editor.org/rfc/rfc7126"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

// routingPersistent are the four keys, with what their absence and their
// presence mean.
//
// The wording differs per parameter on purpose. accept_source_route defaults
// to 0, so an unset key is an undocumented default; accept_redirects defaults
// to 1, so an unset key is a host that will accept them. A shared sentence
// would have to be vague enough to be true of both, which would make it useless
// for the one that matters more.
var routingPersistent = []requirement{
	{
		accept:  refused,
		key:     "net.ipv4.conf.all.accept_source_route",
		absence: "nothing on this host records that source-routed packets should be dropped; the kernel's own default is 0, which is correct and is not a decision anybody made",
		wrong:   "a packet may carry its own return path and this host will honour it",
	},
	{
		accept:  refused,
		key:     "net.ipv4.conf.default.accept_source_route",
		absence: "an interface created after boot — a container veth, a VPN tunnel, a hot-plugged NIC — inherits whatever the kernel defaults to rather than a value this host chose",
		wrong:   "every interface created after boot will accept source-routed packets",
	},
	{
		accept:  refused,
		key:     "net.ipv4.conf.all.accept_redirects",
		absence: "this host will accept ICMP redirects, because unlike source routing the kernel defaults this one to 1: any party on the segment can rewrite its routing table with an unauthenticated packet",
		wrong:   "any party on the segment can rewrite this host's routing table with an unauthenticated packet",
	},
	{
		accept:  refused,
		key:     "net.ipv4.conf.default.accept_redirects",
		absence: "every interface created after boot will accept ICMP redirects, since the kernel defaults this one to 1 and nothing here overrides it",
		wrong:   "every interface created after boot will accept ICMP redirects",
	},
}

// persistRoutingCaveat names the check that reads the running values.
//
// Only half of this check has a runtime counterpart, and saying so is more
// useful than naming KERNEL-0015 alone would be: a reader who goes looking for
// the redirect equivalent should find out it does not exist rather than
// conclude they misread the report.
var persistRoutingCaveat = " This reads the sysctl configuration files, which describe what the kernel will do after the next reboot. What it is doing now is KERNEL-0015's subject for source routing and nothing's yet for redirect acceptance, and a disagreement between file and kernel is KERNEL-0007's."
