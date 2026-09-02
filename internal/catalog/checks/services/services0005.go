package services

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests that the unit directories and the unit files in them are
// writable by root alone.
var Check0005 = catalog.Check{
	ID:     "SERVICES-0005",
	Module: "SERVICES",
	Title:  "Unit directories and unit files are writable by root alone",
	Description: `A systemd unit file is a list of commands run as whatever user
it names, at boot, before anybody logs in. Write access to a unit file, or to
the directory holding one, is therefore arbitrary code execution as root on the
next reboot, with no exploit, no authentication step and nothing to detect,
because the resulting process is exactly the sort of thing that is supposed to
start at boot.

Write access to the *directory* is as good as write access to the file. A
non-root account that can write /etc/systemd/system can create a unit file
there, and /etc is the highest-precedence unit directory: a file it places
shadows the vendor's version of the same unit outright. It can equally create a
symlink in <target>.wants/ and enable something the administrator never
approved.

This is the same failure the CRON module checks, reached by a different
mechanism, and it is produced by the same ordinary accidents: a deployment
script that chowns a directory to its service account so the account can drop a
unit file in, an installer that leaves a package directory group-writable, an
administrator who ran chmod -R on the wrong path. None of those looks like an
attack while it is happening, and each of them ends with somebody other than
root deciding what the machine runs at boot.

Ownership and writability are reported together because they are one exposure
reached two ways. A file owned by an unprivileged account is one that account
can chmod at will, so "root-owned but group-writable" and "owned by deploy"
mean the same thing in the end.`,

	BaseSeverity: finding.High,
	Tags:         []string{"services", "systemd", "permissions", "privilege-escalation"},
	Requires:     []fact.ID{fact.ServicesID},
	SinceCatalog: 9,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := servicesFact(fs)
		if !s.Systemd {
			return notSystemd()
		}

		var problems []string
		var ev []finding.Evidence
		var subject string
		dirs, files := 0, 0

		for _, d := range s.Dirs {
			// Only a directory we actually listed carries meaningful metadata,
			// and an alias was already examined under its canonical path.
			if d.State != fact.DirRead {
				continue
			}
			dirs++
			if f := faultsOf(d.Mode, d.UID, d.GID); f != "" {
				if subject == "" {
					subject = d.Path
				}
				problems = append(problems, d.Path+" is "+f)
				ev = append(ev, dirEvidence(d))
			}
		}

		for _, u := range s.Units {
			files++
			// A symlink's own mode and owner do not govern anything: the
			// kernel ignores a symlink's permission bits, and what matters is
			// the file at the other end, which is recorded separately if it
			// lives in a unit directory. Judging the link would report a
			// mask — lrwxrwxrwx by construction — as world-writable.
			if u.IsSymlink {
				continue
			}
			if f := faultsOf(u.Mode, u.UID, u.GID); f != "" {
				if subject == "" {
					subject = u.Path
				}
				problems = append(problems, u.Path+" is "+f)
				ev = append(ev, unitEvidence(u))
			}
		}

		// Positive: we read these modes and owners. Nothing we failed to read
		// elsewhere can unmake them.
		if len(problems) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: subject,
				Detail: fmt.Sprintf(
					"%d unit path%s can be modified by an account other than root: %s. A unit file is a list of commands run at boot as the user it names, so whoever can write one — or write the directory holding one — decides what this host executes as root at the next reboot, with nothing that looks like an attack while it happens.",
					len(problems), plural(len(problems), "", "s"),
					strings.Join(problems, "; ")),
				Evidence: ev,
			}
		}

		return unknownIfIncomplete(s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d unit director%s and %d unit file%s are owned by root and writable by root alone, so nothing but root decides what starts at boot.",
				dirs, plural(dirs, "y", "ies"), files, plural(files, "", "s")),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Restore root ownership and remove group and other write on the unit paths named in the finding.",
		Effort:  "LOW",
		Steps: []string{
			"Read the unit file before changing its mode. A unit that a non-root account could write may already have been written; 'systemctl cat <unit>' shows the effective content including drop-ins, and its ExecStart is the line to look at first.",
			"Restore ownership: 'chown root:root <path>'.",
			"Remove group and other write: 'chmod go-w <path>'. The conventional modes are 0644 for a unit file and 0755 for a unit directory.",
			"Find out why it was wrong, or it will be wrong again next week. Ownership by a service account almost always comes from a deployment step that wanted to drop a unit file in; the fix is for that step to place the file as root, not for the directory to be writable.",
			"Where a service genuinely needs to manage its own units, give it a narrow sudo rule for 'systemctl' and the specific units, rather than write access to the directory. The first is auditable and bounded; the second is root.",
			"Reload afterwards so systemd picks up the corrected files: 'systemctl daemon-reload'.",
		},
		Commands: []string{
			"ls -la /etc/systemd/system /usr/lib/systemd/system",
			"find /etc/systemd/system /usr/lib/systemd/system \\( ! -user root -o -perm /022 \\) -print",
			"chown root:root <path> && chmod go-w <path>",
		},
		Caution: "A unit path writable by a non-root account should be treated as possibly already modified, not merely as misconfigured. Fix the mode, but also compare the unit against the package's version, 'rpm -V' or 'dpkg --verify' names the package files that have changed, before concluding nothing happened.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-5"},
	},

	References: []finding.Reference{
		{Title: "systemd.unit(5), unit load path and precedence", URL: "https://man7.org/linux/man-pages/man5/systemd.unit.5.html"},
	},
}

// faultsOf describes what is wrong with one path's mode and ownership, as a
// clause completing "<path> is …". An empty result means it is sound.
func faultsOf(mode, uid, gid uint32) string {
	var out []string
	if uid != 0 || gid != 0 {
		out = append(out, fmt.Sprintf("owned by uid %d / gid %d rather than root, so that account can change its contents and its mode at will", uid, gid))
	}
	if mode&0o022 != 0 {
		out = append(out, fmt.Sprintf("mode %s, which is writable by group or other", renderPerm(mode)))
	}
	return strings.Join(out, " and ")
}
