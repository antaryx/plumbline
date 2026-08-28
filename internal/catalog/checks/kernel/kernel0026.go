package kernel

import (
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0026 tests whether IPv6 router advertisements are refused in the sysctl
// configuration.
var Check0026 = catalog.Check{
	ID:     "KERNEL-0026",
	Module: "KERNEL",
	Title:  "IPv6 router advertisements are refused in the sysctl configuration",

	Description: `A router advertisement is an unauthenticated multicast packet
that tells every listening host on the segment what the prefix is and who the
default gateway is. It is how IPv6 stateless autoconfiguration is designed to
work, and it is the whole attack.

Anyone who can put a frame on the segment can send one. There is no race to win
and no cache to poison — a host that accepts RAs installs the attacker as its
default gateway because that is what the protocol says to do. Two things make
it worse than the IPv4 equivalent:

  - **It works on a network that is not using IPv6.** The stack is enabled by
    default on every modern distribution, so an attacker can introduce IPv6 to
    a v4-only segment and be the only router on it.
  - **The host will prefer the new route.** RFC 6724 puts IPv6 above IPv4 in
    destination address selection, so traffic that was working over IPv4 moves
    to the attacker's path without anything appearing to change.

net.ipv6.conf.*.accept_ra takes three values: 0 refuses, 1 accepts unless this
host forwards, and 2 accepts even when it does. **1 is the default**, so a host
that has never been configured accepts them.

Both keys are checked. conf.default is the template every interface created
after boot inherits — a container veth, a VPN tunnel, a hot-plugged NIC — and
nothing else reaches them.

This check is for a host that gets its addresses statically or by DHCPv6. On a
host that uses SLAAC, refusing RAs removes its IPv6 address, its default route
and its DNS servers, which is the deliberate trade rather than a side effect.
See the remediation.

This is a check about files. Nothing reads the running value yet.`,

	// High. A successful rogue RA is a complete man-in-the-middle position over
	// every IPv6 flow on the segment, obtained without any privilege on this
	// host and without exploiting anything — the protocol is working as
	// designed. It sits above the redirect and source-routing findings because
	// those redirect chosen destinations and this one redirects everything, and
	// above rp_filter because spoofing defeats a control while this defeats
	// confidentiality.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "ipv6"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 30,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, requirementKeys(acceptRAPersistent), persistAcceptRACaveat); out != nil {
			return *out
		}

		failed, evidence := checkRequirements(sc, acceptRAPersistent)
		if len(failed) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "sysctl configuration",
				Detail: capitaliseFirst(strings.Join(failed, "; ")) +
					". Anyone able to put a frame on this segment can advertise themselves as the default gateway and read and rewrite every IPv6 flow leaving this host, without exploiting anything — router advertisements are unauthenticated by design." +
					persistAcceptRACaveat,
				Evidence: searchedEvidence(sc, evidence),
			}
		}

		return catalog.Outcome{
			Result:  finding.Pass,
			Subject: "sysctl configuration",
			Detail: "IPv6 router advertisements are refused in the sysctl configuration, for the host-wide key and for the template every interface created later inherits. A rogue advertisement will not install a default route on this host after the next reboot, and this host is therefore configured for static or DHCPv6 addressing rather than SLAAC." +
				runningContradiction(sc, acceptRAPersistent) + persistAcceptRACaveat,
			Evidence: searchedEvidence(sc, evidence),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write net.ipv6.conf.all.accept_ra = 0 and net.ipv6.conf.default.accept_ra = 0 to a file in /etc/sysctl.d/ — but confirm this host does not use SLAAC first.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out how this host gets its IPv6 address before changing anything. `ip -6 addr show` marking an address `dynamic mngtmpaddr` means it came from a router advertisement, and refusing RAs will remove it along with the default route. An address from DHCPv6 or from a static configuration is unaffected.",
			"Check what already sets it, patterns included: grep -rn accept_ra /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d.",
			"Create or extend a drop-in containing net.ipv6.conf.all.accept_ra = 0 and net.ipv6.conf.default.accept_ra = 0. Set both: default is the template for interfaces that do not exist yet, and nothing else reaches them.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl -a | grep accept_ra, and confirm the host still has the route it needs with ip -6 route.",
			"Where the host genuinely needs SLAAC, this is a network control rather than a host one: RA Guard on the access switch drops advertisements from ports that are not the router, which is the only thing that stops the attack while leaving autoconfiguration working.",
			"Disabling IPv6 outright is a different and usually worse answer. A stack that is down cannot be attacked, but applications fall back in ways that are hard to predict, and a kernel parameter is easier to reverse than an addressing decision.",
		},
		Commands: []string{
			"ip -6 addr show",
			"ip -6 route show",
			"sysctl -a 2>/dev/null | grep accept_ra",
			"grep -rn accept_ra /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
		},
		Caution: "On a host that autoconfigures over IPv6 this removes its address, its default route and any DNS server learned from the advertisement — IPv6 connectivity stops. That is the trade, not a mistake. Verify the addressing method before applying it, and be aware that a cloud provider's network may hand out IPv6 by RA even where IPv4 comes from DHCP.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — ip-sysctl accept_ra", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
		{Title: "RFC 6104 — Rogue IPv6 Router Advertisement Problem Statement", URL: "https://www.rfc-editor.org/rfc/rfc6104"},
		{Title: "RFC 6105 — IPv6 Router Advertisement Guard", URL: "https://www.rfc-editor.org/rfc/rfc6105"},
	},
}

// acceptRAPersistent are the two keys the configuration has to carry.
//
// The absence wording differs between them because the consequence does. An
// unset conf.all leaves the interfaces that exist now accepting
// advertisements; an unset conf.default leaves every interface created later
// accepting them, which on a host running containers is a new one every few
// seconds.
var acceptRAPersistent = []requirement{
	{
		key:     "net.ipv6.conf.all.accept_ra",
		accept:  refused,
		absence: "this host accepts IPv6 router advertisements, because the kernel defaults this to 1: anyone on the segment can become its default gateway by announcing that they are",
		wrong:   "anyone on the segment can become this host's default gateway by announcing that they are",
	},
	{
		key:     "net.ipv6.conf.default.accept_ra",
		accept:  refused,
		absence: "every interface created after boot accepts IPv6 router advertisements, since the kernel defaults this to 1 and nothing here overrides it",
		wrong:   "every interface created after boot will accept IPv6 router advertisements",
	},
}

// persistAcceptRACaveat names the absent runtime counterpart.
var persistAcceptRACaveat = persistCaveatUnpaired()
