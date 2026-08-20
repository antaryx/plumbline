package services

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// DiscoveryUnits are network-facing services that a server does not need and
// that arrive enabled on desktop-oriented installations.
//
// The list is short on purpose. "Unnecessary services" is a category that
// invites an ever-growing list of things somebody somewhere legitimately runs,
// and a check that fails on a print server for running a print server is
// noise, which is how a catalog trains people to ignore it. These three share
// one specific property: they open a listening socket to the local network by
// default, they are enabled by a desktop package set rather than by a
// decision, and the workload that needs them is narrow and known to whoever
// runs it.
var DiscoveryUnits = []string{
	// avahi: mDNS/DNS-SD. Announces the host's name, addresses and services to
	// every machine on the broadcast domain, and answers queries about them.
	"avahi-daemon.service", "avahi-daemon.socket",
	// cups-browsed: discovers and mounts remote printers announced over the
	// network, which is a listening service that acts on unauthenticated
	// broadcast input.
	"cups-browsed.service",
	// rpcbind: the portmapper. Publishes which RPC service is on which port to
	// anyone who asks, and has a long history as a UDP amplification reflector.
	"rpcbind.service", "rpcbind.socket",
}

// Check0002 tests that network-discovery and RPC portmapping services are not
// enabled.
var Check0002 = catalog.Check{
	ID:     "SERVICES-0002",
	Module: "SERVICES",
	Title:  "Network discovery and RPC portmapping services are not enabled",
	Description: `avahi-daemon, cups-browsed and rpcbind each open a listening
socket to the local network, each is enabled by a desktop-oriented package set
rather than by anybody's decision, and each is unnecessary on the large
majority of servers.

What they cost is reconnaissance and reachable code. avahi-daemon announces the
host's name, its addresses and the services it offers to every machine in the
broadcast domain, and answers queries about them — an attacker who lands on any
host on the segment gets an inventory of the others without sending a single
scan. rpcbind publishes which RPC service is listening on which port to anyone
who asks, and has spent years on abuse lists as a UDP amplification reflector
because a small query returns a large answer to a spoofed source. cups-browsed
acts on unauthenticated network broadcasts to configure printers, and its
history of remote code execution follows directly from that design.

The judgement here is genuinely a policy one, and the check says so rather than
pretending otherwise. A print server should run CUPS. An NFS server needs
rpcbind. A desktop fleet may want mDNS. What the check asserts is that these
services should be present because somebody decided they should be, and the
common case — a server image that inherited them from a desktop package set —
is not that. Where the service is intentional, suppress the finding: a recorded
decision is worth more than a silent exception.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"services", "systemd", "attack-surface", "network"},
	Requires:     []fact.ID{fact.ServicesID},
	SinceCatalog: 9,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := servicesFact(fs)
		if !s.Systemd {
			return notSystemd()
		}

		if enabled := s.AnyEnabled(DiscoveryUnits...); len(enabled) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: enabled[0],
				Detail: fmt.Sprintf(
					"%s %s enabled and will start at boot, opening a listening socket to the local network. Each of these advertises or answers questions about the host to unauthenticated callers on the segment, which hands an attacker who reaches any machine there an inventory of the rest. If this host genuinely serves that role, suppress this finding so the decision is recorded rather than repeatedly rediscovered.",
					join(enabled), plural(len(enabled), "is", "are")),
				Evidence: enabledEvidence(s, enabled),
			}
		}

		return unknownIfIncomplete(s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"Neither the mDNS responder, the printer browser nor the RPC portmapper is enabled.%s",
				describeStatuses(s, DiscoveryUnits)),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Disable the service, or record the decision to keep it as a suppression.",
		Effort:  "LOW",
		Steps: []string{
			"Decide first whether this host serves the role. rpcbind is needed by an NFS server and by an NFS client using NFSv3; NFSv4 does not need it. cups-browsed is needed to discover printers announced on the network, not to print to one configured by address. avahi-daemon is needed for .local name resolution, which almost nothing on a server uses.",
			"Where it is not needed: 'systemctl disable --now <unit>'. For socket-activated units disable the .socket as well as the .service, or the socket will start the service on the next connection.",
			"Remove the package where the role is settled — 'apt purge avahi-daemon', 'dnf remove avahi' — which prevents a later dependency from pulling it back in enabled.",
			"Where it is needed, keep it and bound it instead: rpcbind and avahi both take a listen-address, and a firewall rule confining them to the segment that needs them removes most of the exposure without removing the function.",
			"Where the service is intentional, add a suppression for this check with the reason. A recorded decision survives the next audit; an unexplained failing check gets ignored, and then so does the next one.",
		},
		Commands: []string{
			"systemctl is-enabled avahi-daemon.service cups-browsed.service rpcbind.service",
			"ss -lnp | grep -E ':(111|631|5353)\\b'",
			"systemctl disable --now avahi-daemon.socket avahi-daemon.service",
		},
		Caution: "Disabling rpcbind on a host that mounts NFSv3 shares breaks those mounts at the next boot, and the failure looks like a network problem rather than a configuration one. Confirm the NFS version in use — 'nfsstat -m' names it per mount — before touching it.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SC-7"},
	},

	References: []finding.Reference{
		{Title: "rpcbind(8)", URL: "https://man7.org/linux/man-pages/man8/rpcbind.8.html"},
		{Title: "avahi-daemon(8)", URL: "https://man7.org/linux/man-pages/man8/avahi-daemon.8.html"},
	},
}
