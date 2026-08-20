package network

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests that a host-based firewall is configured.
var Check0001 = catalog.Check{
	ID:     "NETWORK-0001",
	Module: "NETWORK",
	Title:  "A host-based firewall is configured",
	Description: `A host firewall is the control that survives every mistake
made above it. A perimeter is a statement about where an attacker is, and it
stops being true the moment one is inside it — a compromised workstation on the
same VLAN, a container escaping onto the host network, a cloud security group
edited to unblock a deployment and never edited back. The host firewall is the
only rule set that does not depend on that assumption.

What it defends against specifically is the service nobody decided to run. A
package installs a daemon that listens on all interfaces by default; a
development build ships with a debug port; an operator binds a database to
0.0.0.0 to test something. None of those is visible until somebody scans for
it, and every one of them is closed by a default-deny host firewall without
anybody having to notice.

This check reports what is **configured**, not what is loaded. It reads the
files a firewall is restored from — nftables.conf, an iptables-save file,
ufw.conf, firewalld.conf — and a file that exists but holds no statements does
not count. Debian's nftables package installs /etc/nftables.conf whether or not
anybody has written a rule in it, and a check that treated the file's existence
as a firewall would report every such host as protected.

The other half — whether the unit that loads the ruleset is enabled — is the
SERVICES module's to answer, and this check does not claim it.`,

	BaseSeverity: finding.High,
	Tags:         []string{"network", "firewall", "attack-surface"},
	Requires:     []fact.ID{fact.FirewallID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		f := firewallFact(fs)

		// Positive: we read these files and they hold a configuration. No file
		// we failed to read can unmake that.
		if active := f.Active(); len(active) > 0 {
			return catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"A host firewall is configured: %s (%s). Whether the unit that loads it is enabled is a separate question, which the SERVICES module answers.",
					fact.KindNames(f.Kinds()), paths(active)),
				Evidence: evidenceFor(active),
			}
		}

		// The conclusion is drawn from absence, so it is only as good as the
		// reads behind it.
		return unknownIfUnreadable(f, catalog.Outcome{
			Result:   finding.Fail,
			Subject:  "/etc/nftables.conf",
			Detail:   emptyDetail(f),
			Evidence: evidenceFor(f.Sources),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Configure a default-deny host firewall that permits only the services this host is meant to offer.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Establish what is listening before you block anything: 'ss -tulpn' names every socket and the process behind it. Every entry is either something this host is meant to offer, or a finding in its own right.",
			"Pick the tool the distribution manages. ufw on Ubuntu and Debian, firewalld on RHEL and Fedora, plain nftables where configuration management owns the ruleset. Running two is worse than running one — NETWORK-0003 checks for that.",
			"Set the default before adding any rule: 'ufw default deny incoming' or, in nftables, 'policy drop' on the input chain. A ruleset built the other way round is a deny list, and everything a future package opens is reachable until somebody notices.",
			"Allow ssh first, and from a session you can afford to lose: 'ufw allow OpenSSH'. Locking yourself out of a remote host is the ordinary failure of this task, not an exotic one.",
			"Enable it and make it survive a reboot: 'ufw enable', or 'systemctl enable --now nftables.service'. A ruleset in a file that no unit loads is a document, not a control.",
			"Verify from another host rather than from this one: 'nmap -Pn <host>' from somewhere else shows what is actually reachable, which is the only measurement that matters.",
		},
		Commands: []string{
			"ss -tulpn",
			"ufw status verbose",
			"nft list ruleset",
			"firewall-cmd --list-all",
		},
		Caution: "Enabling a default-deny firewall over ssh will disconnect you if the ssh rule is wrong, and the host will still be running with no way in. Add the ssh allow rule and confirm it before enabling, keep a second session open throughout, and on a host you cannot physically reach schedule a job that disables the firewall in ten minutes unless you cancel it.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "AC-4"},
	},

	References: []finding.Reference{
		{Title: "nft(8)", URL: "https://man7.org/linux/man-pages/man8/nft.8.html"},
		{Title: "ufw(8)", URL: "https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html"},
	},
}

// emptyDetail distinguishes "no configuration file at all" from "a file exists
// and has nothing in it", because they are different mistakes and the second
// is the one an operator will argue with.
func emptyDetail(f fact.Firewall) string {
	var empty, disabled []fact.FirewallSource
	for _, s := range f.Sources {
		if s.State != fact.SourcePresent {
			continue
		}
		if s.Kind.Manager() && s.Enabled == fact.EnabledNo {
			disabled = append(disabled, s)
			continue
		}
		empty = append(empty, s)
	}

	switch {
	case len(disabled) > 0:
		return fmt.Sprintf(
			"A firewall is configured but switched off: %s %s ENABLED=no. Every rule in it is present and none of them applies, which is the state that most reliably survives an audit of the ruleset itself — the file reads correctly and the host is open.",
			paths(disabled), plural(len(disabled), "records", "record"))
	case len(empty) > 0:
		return fmt.Sprintf(
			"A firewall configuration file exists but contains no statements: %s. An empty ruleset is not a firewall — on Debian the nftables package installs this file whether or not anybody has written a rule in it, so its presence says which package is installed and nothing about what is filtered.",
			paths(empty))
	default:
		return "No host firewall configuration was found. None of the files a firewall is restored from exists — nftables.conf, an iptables-save file, ufw.conf, firewalld.conf — so every port on this host that something is listening on is reachable from anywhere that can route to it, including the services no one decided to run."
	}
}
