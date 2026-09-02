package services

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests that every enablement symlink resolves to a unit file that
// exists.
//
// This is the check the Readlink seam was added for, and it is only answerable
// because enablement is a symlink: the link records what an administrator
// turned on, and the target records whether the software is still there. The
// two disagreeing is a state systemd itself reports only in a boot log line
// nobody reads.
var Check0004 = catalog.Check{
	ID:     "SERVICES-0004",
	Module: "SERVICES",
	Title:  "Every enabled unit resolves to a unit file that exists",
	Description: `An enablement symlink and the unit file it points at are
separate objects, and they come apart. A package removed without disabling its
units first, an administrator who deleted a unit file by hand, a vendor path
that moved between distribution releases, a configuration management run that
wrote the link before the payload: each leaves
/etc/systemd/system/<target>.wants/<unit> pointing at nothing.

systemd's response is to log "Unit <name> not found" once during boot and carry
on. Nothing else marks it. 'systemctl is-enabled' still answers "enabled",
because the symlink is what that command reads. The operator's belief that the
service is enabled is correct; their belief that it runs is not, and there is
no routine moment at which those two diverge visibly.

The security consequence depends on what dangled. A dangling link to auditd, to
a firewall unit, to a log shipper or to an intrusion detection agent is a
control that everybody believes is in place and that has not run since the
package was removed, which is the most expensive failure a control can have,
because it also suppresses the alarm that would have reported its absence.

There is a second, sharper reading. A symlink is a name that resolves at use.
A dangling one names a path that does not exist *yet*, and anyone who can
create a file there decides what systemd loads at the next boot. Where the
target is under a directory a non-root account can write, the dangling link is
not merely inert, it is a scheduled execution slot waiting to be filled.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"services", "systemd", "integrity", "symlink"},
	Requires:     []fact.ID{fact.ServicesID},
	SinceCatalog: 9,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := servicesFact(fs)
		if !s.Systemd {
			return notSystemd()
		}

		// Positive: we followed these links and found nothing at the other
		// end. A directory we failed to list elsewhere cannot unmake that.
		if bad := s.Dangling(); len(bad) > 0 {
			ev := make([]finding.Evidence, 0, len(bad))
			names := make([]string, 0, len(bad))
			for _, l := range bad {
				ev = append(ev, linkEvidence(l))
				names = append(names, l.Unit)
			}
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: bad[0].Unit,
				Detail: fmt.Sprintf(
					"%d enablement symlink%s point at a unit file that does not exist (%s). systemctl still reports %s as enabled — the symlink is what it reads — but systemd logs \"Unit not found\" at boot and starts nothing. Whatever these units were for has not run since the target went away, and if one of them is a security control, so has the alarm that would have reported its absence.",
					len(bad), plural(len(bad), "", "s"), join(names),
					plural(len(bad), "it", "them")),
				Evidence: ev,
			}
		}

		// A link whose target could not be stat'ed might be dangling. Saying
		// PASS over it would be reporting integrity we did not verify.
		if unresolved := s.Unresolved(); len(unresolved) > 0 {
			ev := make([]finding.Evidence, 0, len(unresolved))
			names := make([]string, 0, len(unresolved))
			for _, l := range unresolved {
				ev = append(ev, linkEvidence(l))
				names = append(names, l.Unit)
			}
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonPermission,
				Subject:       unresolved[0].Unit,
				Detail: fmt.Sprintf(
					"Every enablement symlink that could be followed resolves to a unit file that exists, but %d of them could not be followed (%s). A link whose target cannot be examined may be the dangling one, so the absence of a broken link cannot be confirmed.",
					len(unresolved), join(names)),
				Evidence: ev,
			}
		}

		total := len(s.Links)
		if total == 0 {
			// Nothing enabled at all is drawn from absence, so the listings
			// have to have been complete for it to mean anything.
			return unknownIfIncomplete(s, catalog.Outcome{
				Result: finding.Pass,
				Detail: "No enablement symlink exists in any unit directory, so there is none that could be broken. On a host that boots, this means every running service is either static — pulled in by another unit's Wants= rather than enabled — or started by something other than systemd.",
			})
		}

		return unknownIfIncomplete(s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d enablement symlink%s resolve to a unit file that exists, so every service an administrator enabled on this host has something for systemd to start.",
				total, plural(total, "", "s")),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Decide per link whether the service should return or the link should go, then remove the dangling links.",
		Effort:  "LOW",
		Steps: []string{
			"Ask systemd for its own account first: 'systemctl list-unit-files --state=enabled' beside 'journalctl -b | grep \"Unit .* not found\"' shows what it tried to start and could not.",
			"For each broken link, decide which half is wrong. A unit that should be running means the package was removed by accident, reinstall it. A unit that should not means the link is left over, remove it.",
			"Remove a leftover link with 'systemctl disable <unit>' rather than 'rm'. disable removes every link for that unit across all targets; deleting the one you found leaves the others, and the problem recurs looking slightly different.",
			"Where 'systemctl disable' refuses because the unit file is gone, remove the link directly: 'rm /etc/systemd/system/multi-user.target.wants/<unit>', then 'systemctl daemon-reload'.",
			"Treat a dangling link under a writable directory as urgent rather than untidy. Anyone who can create the target file decides what systemd loads at the next boot; check the target's parent directory with 'ls -ld' before deciding how quickly to act.",
			"Add the check to whatever runs after package removal. These links are created by an operation that succeeds, removing a package without disabling its units first, so they accumulate silently unless something looks.",
		},
		Commands: []string{
			"find /etc/systemd/system /usr/lib/systemd/system -xtype l -print",
			"systemctl list-unit-files --state=enabled",
			"journalctl -b -p warning | grep -i 'not found'",
		},
		Caution: "'find -xtype l' lists links whose target does not exist, which is what you want, but it follows the link to decide, so run it as a user who can read the target directories or it will report links as broken that are merely unreadable.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-6"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "systemctl(1), enable, disable, is-enabled", URL: "https://man7.org/linux/man-pages/man1/systemctl.1.html"},
	},
}
