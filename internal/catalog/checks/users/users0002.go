package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests that system accounts cannot open an interactive session.
var Check0002 = catalog.Check{
	ID:     "USERS-0002",
	Module: "USERS",
	Title:  "System accounts have no interactive login shell",
	Description: `A system account exists to own files and run a daemon, not to be
logged into. Leaving it with a real shell turns every one of them into a
potential entry point: an attacker who obtains its credential, from a
configuration file, a backup, a compromised service, gets a session rather
than an error, and from a session they get an environment, a shell history and
somewhere to run things.

Setting the shell to nologin or false costs nothing, because nothing about
running a daemon requires the ability to log in.

Two details decide whether this check is right or merely plausible. **An empty
shell field is not "no shell"**, the system substitutes /bin/sh, so an empty
field is the most permissive setting in the file, not the most restrictive.
And the path to nologin differs by distribution, /usr/sbin on Debian-family
systems and /sbin on Red Hat-family ones, so a check that knew only one would
report every account on the other as interactive.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"users", "attack-surface", "lateral-movement"},
	Requires:     []fact.ID{fact.PasswdID},
	SinceCatalog: 4,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := passwdFact(fs)

		var (
			interactive []string
			evidence    []finding.Evidence
			considered  int
		)
		for _, e := range p.Entries {
			if !isSystemAccount(e.UID) {
				continue
			}
			considered++
			if !interactiveShell(e.Shell) {
				continue
			}
			interactive = append(interactive, e.Name)
			shown := e.Shell
			if shown == "" {
				shown = "(empty — the system substitutes /bin/sh)"
			}
			evidence = append(evidence, finding.NewEvidence(p.Path, e.Line,
				fmt.Sprintf("%s:x:%d:%d:...:%s:%s", e.Name, e.UID, e.GID, e.Home, shown),
				p.Digest))
		}

		if len(interactive) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: joinNames(interactive),
				Detail: fmt.Sprintf(
					"%d system account(s) (uid 1-%d) have a shell that can open a session: %s. Anyone who obtains one of these credentials gets a login rather than a refusal.",
					len(interactive), SystemUIDMax, joinNames(interactive)),
				Evidence: evidence,
			}
		}

		if considered == 0 {
			// No account falls in the system range at all. Containers built
			// from a single application image look like this.
			return unknownIfIncomplete(p, catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"No account in %s has a uid between 1 and %d, so this host has no system accounts for the check to apply to.",
					p.Path, SystemUIDMax),
			})
		}

		return unknownIfIncomplete(p, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d system account(s) (uid 1-%d) have a shell that cannot open a session.",
				considered, SystemUIDMax),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Set the shell of every system account to nologin.",
		Effort:  "LOW",
		Steps: []string{
			"Confirm the account does not need a shell: a service started by systemd does not, but one invoked through 'su - <name>' by a cron job or a deployment script does.",
			"Set the shell: 'usermod -s /usr/sbin/nologin <name>' on Debian-family systems, '/sbin/nologin' on Red Hat-family ones. Use the path that exists on this host.",
			"Verify: 'getent passwd <name>' should show the nologin path.",
			"Re-run any job that used the account and confirm it still works.",
		},
		Commands: []string{
			"awk -F: '$3 >= 1 && $3 <= 999 {print $1, $7}' /etc/passwd",
			"usermod -s /usr/sbin/nologin <name>",
		},
		Caution: "Some deployment tooling runs commands as a service account through 'su' or 'runuser', both of which need a working shell. Changing the shell will break those jobs silently, they will fail at the next run rather than immediately.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "AC-2"},
	},

	References: []finding.Reference{
		{Title: "nologin(8)", URL: "https://man7.org/linux/man-pages/man8/nologin.8.html"},
	},
}
