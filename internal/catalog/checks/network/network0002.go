package network

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests that the firewall's default inbound disposition is deny.
var Check0002 = catalog.Check{
	ID:     "NETWORK-0002",
	Module: "NETWORK",
	Title:  "The firewall's default inbound policy denies",
	Description: `A firewall is a list of exceptions to a default, and the
default is what the firewall actually is. Everything else is detail.

Default-accept with a list of blocks is a **deny list**. It protects against
the ports somebody thought of on the day they wrote it, and against nothing
else. Every port a future package opens is reachable the moment it opens;
every service moved to a new port is reachable at the new one; every daemon
that binds an ephemeral port is reachable there. The ruleset does not have to
be wrong for this to happen — it only has to be finished.

Default-deny with a list of allows fails closed. A new listening socket is
unreachable until somebody decides otherwise, which converts "we did not think
of it" from an exposure into an inconvenience. That is the whole value of a
host firewall, and a default-accept ruleset does not have it, however many
rules it contains.

How the default is written depends on the tool. nftables and iptables state it
on the input chain (` + "`policy drop`" + `, ` + "`:INPUT DROP`" + `). ufw states it in
/etc/default/ufw as DEFAULT_INPUT_POLICY. firewalld has no policy keyword at
all: every zone it ships rejects what it does not explicitly allow **except**
` + "`trusted`" + `, whose target is ACCEPT — so on firewalld the default zone's name
is the policy, and it is the one setting an operator can get catastrophically
wrong in a single word.`,

	BaseSeverity: finding.High,
	Tags:         []string{"network", "firewall", "default-deny"},
	Requires:     []fact.ID{fact.FirewallID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		f := firewallFact(fs)

		active := f.Active()
		if len(active) == 0 {
			// A firewall we could not read is not a firewall that is absent.
			return unknownIfUnreadable(f, noFirewall("a default inbound policy"))
		}

		var allow, undetermined, deny []fact.FirewallSource
		for _, s := range active {
			switch s.Policy {
			case fact.PolicyAllow:
				allow = append(allow, s)
			case fact.PolicyDeny:
				deny = append(deny, s)
			default:
				undetermined = append(undetermined, s)
			}
		}

		// Positive: we read the policy line. Nothing we missed can unmake it.
		if len(allow) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: allow[0].Path,
				Detail: fmt.Sprintf(
					"The default inbound policy accepts: %s. Every rule in this configuration is an exception to that, so the firewall protects against the ports somebody listed and against nothing else — a service that starts listening tomorrow is reachable the moment it does.%s",
					policyDetail(allow), trustedNote(allow)),
				Evidence: evidenceFor(allow),
			}
		}

		if len(undetermined) > 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonParse,
				Subject:       undetermined[0].Path,
				Detail: fmt.Sprintf(
					"A firewall is configured in %s, but no default inbound policy could be read from it. The file may set the policy in a form this parser does not recognise, or may leave it to the tool's own default. Reporting either verdict from here would be a guess, and the insecure guess is as much a guess as the secure one.",
					paths(undetermined)),
				Evidence: evidenceFor(undetermined),
			}
		}

		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"The default inbound policy denies: %s. Unmatched inbound traffic is dropped, so a service that starts listening without anybody deciding it should is unreachable until somebody does decide.",
				policyDetail(deny)),
			Evidence: evidenceFor(deny),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set the input chain's default to drop, then add allow rules for the services this host offers.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Enumerate what must keep working before changing the default: 'ss -tulpn' for listening sockets, and the firewall's own rule list for what is currently permitted. Anything reachable today that is not in your allow list will stop being reachable.",
			"Write the allow rules first, with the default still at accept. They have no effect yet, which is exactly why this order is safe.",
			"Change the default last. ufw: 'ufw default deny incoming'. nftables: set 'policy drop' on the input chain. iptables: ':INPUT DROP' in the saved rules, or 'iptables -P INPUT DROP'. firewalld: change DefaultZone away from 'trusted' — 'firewall-cmd --set-default-zone=public'.",
			"Do not forget loopback and established traffic. A default-drop input chain with no 'iif lo accept' breaks every local service that talks to itself, and one with no conntrack accept for established connections breaks every outbound connection's replies. Both failures look like the network is broken rather than like the firewall is.",
			"Verify from another host: 'nmap -Pn <host>' from somewhere else is the only measurement that reflects what an attacker sees.",
		},
		Commands: []string{
			"ufw default deny incoming",
			"nft list chain inet filter input",
			"firewall-cmd --get-default-zone",
		},
		Caution: "Changing the default to drop without an allow rule for ssh disconnects you immediately and leaves the host running with no way in. Add the ssh rule, confirm it from a second session, and on a host you cannot physically reach schedule a job that reverts the change in ten minutes unless you cancel it. Loopback and established-connection accepts are needed too, and their absence looks like a network fault rather than a firewall one.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "AC-4"},
	},

	References: []finding.Reference{
		{Title: "firewalld.zone(5) — zone targets", URL: "https://firewalld.org/documentation/man-pages/firewalld.zone.html"},
	},
}

// policyDetail names each source and the text the policy was read from.
func policyDetail(srcs []fact.FirewallSource) string {
	out := ""
	for i, s := range srcs {
		if i > 0 {
			out += "; "
		}
		out += s.Path
		if s.PolicyRaw != "" {
			out += " (" + s.PolicyRaw + ")"
		}
	}
	return out
}

// trustedNote adds the firewalld-specific explanation, because "DefaultZone is
// trusted" does not read as "accept everything" to anybody who has not had to
// learn it.
func trustedNote(srcs []fact.FirewallSource) string {
	for _, s := range srcs {
		if s.Kind == fact.FirewallFirewalld {
			return " On firewalld the default zone is the policy: every zone it ships rejects what it does not explicitly allow except 'trusted', whose target is ACCEPT. Setting the default zone to trusted disables the firewall without disabling the service, so it keeps reporting as running."
		}
	}
	return ""
}
