package network

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests that exactly one firewall configuration is in force.
var Check0003 = catalog.Check{
	ID:     "NETWORK-0003",
	Module: "NETWORK",
	Title:  "Exactly one firewall configuration is in force",
	Description: `Two firewall configurations on one host do not add up. They
overwrite each other, and which one survives depends on unit start order rather
than on anything anybody wrote down.

The mechanism is the same in every combination. ufw and firewalld are
*managers*: each owns the ruleset, and each begins by flushing what is there
and installing its own. A saved ruleset, /etc/nftables.conf, an iptables-save
file, is loaded verbatim by its own unit. Whichever runs last wins outright,
and the others' rules are simply not present in the kernel afterwards.

**The danger is not that the host ends up unprotected.** It usually does not;
one of the two is generally sane. The danger is that somebody edits the wrong
file. They add an allow rule to nftables.conf, reload it, watch the service
report success, and the rule is gone at the next boot when ufw flushes the
table. Or they remove an allow rule believing they have closed a port that
firewalld is still opening. Every subsequent change is made against a model of
the host that is wrong, and nothing about the tooling says so, each tool
reports its own view correctly.

This is the same shape as the trap CRON-0003 names: a configuration file that
is maintained, believed, and inert.

A manager and a saved ruleset together count as two, because they are. A
manager flushes the table the ruleset installed; the ruleset file keeps
existing, keeps being edited, and stops meaning anything.

Two files of the *same* kind are one configuration, not two: rules.v4 and
rules.v6 are the IPv4 and IPv6 halves of one ruleset and are loaded together.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"network", "firewall", "configuration-conflict"},
	Requires:     []fact.ID{fact.FirewallID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		f := firewallFact(fs)

		kinds := f.Kinds()
		if len(kinds) == 0 {
			return unknownIfUnreadable(f, noFirewall("having exactly one firewall configuration"))
		}

		// Positive: we read these files and each holds a configuration. A file
		// we could not read could only add to the count, never reduce it, so
		// this branch is never wrapped.
		if len(kinds) > 1 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: f.Active()[0].Path,
				Detail: fmt.Sprintf(
					"%d firewall configurations are in force at once (%s, across %s). They overwrite each other rather than combining: whichever unit runs last flushes the table and installs its own rules, so which one is actually filtering depends on start order. The risk is not that the host ends up open — it is that somebody edits the file that is not in effect, watches the reload succeed, and works from a model of the host that is wrong from then on.%s",
					len(kinds), fact.KindNames(kinds), paths(f.Active()), conflictNote(f)),
				Evidence: evidenceFor(f.Active()),
			}
		}

		return unknownIfUnreadable(f, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"One firewall configuration is in force (%s, %s), so the file an operator edits is the one that governs the host.",
				fact.KindNames(kinds), paths(f.Active())),
			Evidence: evidenceFor(f.Active()),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Choose the tool the distribution manages, migrate the other's rules into it, and remove the loser outright.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out which one is actually in effect before deciding anything. 'nft list ruleset' shows what is in the kernel now; compare it against each configuration file. The one that matches is the winner, and it is often not the one the team believes in.",
			"Choose by what the distribution manages: ufw on Ubuntu and Debian, firewalld on RHEL and Fedora, plain nftables where configuration management owns the ruleset and no interactive tool should be touching it.",
			"Migrate the losing configuration's rules into the winner before removing anything, working from the file rather than from the kernel, the loser's rules are not loaded, so they will not appear in 'nft list ruleset'.",
			"Disable and mask the losing unit: 'systemctl disable --now iptables.service' then 'systemctl mask' it. Masking matters here for the reason it matters in SERVICES-0001, a package upgrade re-runs its preset and a merely disabled unit can come back enabled.",
			"Remove or rename the losing configuration file. Leaving it is not dangerous, but an inert firewall configuration is one somebody will eventually edit believing it works, which is the whole failure this check is about.",
			"Verify from another host afterwards: 'nmap -Pn <host>' from somewhere else confirms the surviving ruleset actually does what the removed one was believed to be doing.",
		},
		Commands: []string{
			"nft list ruleset",
			"systemctl is-enabled ufw firewalld nftables iptables",
			"ufw status verbose",
		},
		Caution: "Removing the configuration that turns out to be the one in effect opens every port it was closing, and the change is invisible until something is scanned. Establish which is loaded, compare 'nft list ruleset' against each file, before disabling either.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-6"},
		{Framework: "nist-800-53-r5", Control: "SC-7"},
	},

	References: []finding.Reference{
		{Title: "nftables, replacing iptables", URL: "https://wiki.nftables.org/wiki-nftables/index.php/Main_Page"},
	},
}

// conflictNote names the specific combination, because "two firewalls" is
// abstract and "ufw will flush the table nftables.conf installed" is not.
func conflictNote(f fact.Firewall) string {
	managers, rulesets := f.Managers(), f.Rulesets()
	switch {
	case len(managers) > 1:
		return fmt.Sprintf(
			" Two managers are configured (%s). Each one flushes the ruleset on start and installs its own, so they cannot coexist at all — this is not a tuning problem, one of them has to go.",
			paths(managers))
	case len(managers) == 1 && len(rulesets) > 0:
		return fmt.Sprintf(
			" %s is a manager and flushes the table on start, so the rules in %s are installed and then discarded. That file is being maintained and is not in effect.",
			managers[0].Path, paths(rulesets))
	default:
		return " Both are saved rulesets loaded by their own units, so the one whose unit starts second replaces the other's rules entirely."
	}
}
