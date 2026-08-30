package remediate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// dropInFunc writes a systemd drop-in and reloads the manager.
//
// **A drop-in, never an edit of the shipped unit.** /usr/lib/systemd/system is
// the package manager's; a directive written there is reverted by the next
// upgrade of the package, silently and at a moment nobody is watching. A file
// under /etc/systemd/system/<unit>.d/ survives that, is what `systemctl edit`
// itself creates, and is removable by deleting one file — which matters more
// here than usual, because a sandboxing directive that turns out to break the
// daemon has to be undoable at three in the morning.
//
// It is idempotent by writing the whole file rather than appending to it:
// running the script twice produces the same bytes, and there is no accumulated
// second copy of a directive for systemd to resolve.
const dropInFunc = `
# Write a systemd drop-in for UNIT containing BODY, and reload. Writing the
# whole file rather than appending is what makes this safe to run twice.
plumbline_dropin() {
	pl_unit=$1 pl_name=$2 pl_body=$3
	pl_dir=$UNITDIR/$pl_unit.d
	mkdir -p "$pl_dir"
	printf '%s\n' "$pl_body" > "$pl_dir/$pl_name"
	chmod 0644 "$pl_dir/$pl_name"
}
`

// sandboxFix proposes the systemd sandboxing directives a check found missing.
//
// **The directives are per check, and the unit list comes from the finding.**
// Each of the four sandbox checks reports the units it judged and what each one
// was set to, so the script names the units that actually failed on this host
// rather than every unit the check audits.
type sandboxFix struct {
	checkID string
	title   string
	// name is the drop-in's filename. One per concern rather than one shared
	// file, so removing the change that broke a daemon is deleting the file
	// that made it and nothing else.
	name string
	// directives are the lines written into the [Service] section.
	directives []string
	// notes are what an operator must weigh before running it.
	notes []string
}

func (s sandboxFix) CheckID() string { return s.checkID }

func (s sandboxFix) Build(f finding.Finding, _ Options) (Action, bool) {
	units := unitsIn(f)
	if len(units) == 0 {
		// Nothing to act on. A drop-in with no unit to write it for would be a
		// script that fails at its first line under `set -e`.
		return Action{}, false
	}

	a := Action{CheckID: s.checkID, Title: titleOf(f, s.title)}
	for _, n := range s.notes {
		note(&a, n)
	}
	note(&a, "Written to /etc/systemd/system/<unit>.d/ — a drop-in, not the shipped unit, so a")
	note(&a, "package upgrade cannot revert it and deleting one file undoes it.")

	body := "[Service]\n" + strings.Join(s.directives, "\n")
	for _, unit := range units {
		command(&a, "plumbline_dropin", unit, s.name, body)
	}
	command(&a, "systemctl", "daemon-reload")

	// **Not a restart.** Restarting dbus.service or systemd-journald.service
	// from a script is a way to take a host down, and the directives do not
	// take effect until the service restarts anyway — so the operator is told,
	// and chooses the moment.
	literal(&a, `echo "plumbline: the drop-ins are written; restart each unit for them to take effect." >&2`)
	for _, unit := range units {
		literal(&a, fmt.Sprintf(`echo "plumbline:   systemctl restart %s" >&2`, unit))
	}

	return a, true
}

// unitPattern matches a systemd unit name in a path.
var unitPattern = regexp.MustCompile(`\b[A-Za-z0-9@:_.\\-]+\.(?:service|socket|timer|mount|path)\b`)

// unitsIn is the units a finding cited as failing, deduplicated and sorted.
//
// **It reads the evidence and deliberately not the detail**, and the first
// version of this did the opposite — which produced a drop-in for
// cron.service, the one unit all four sandbox checks *exempt*.
//
// The detail names every unit the check has anything to say about: the ones
// that failed, the ones that are masked, and the ones excused with the reason
// they were excused. Reading unit names out of that sentence therefore picks up
// the exemptions, and writing `ProtectSystem=strict` into cron.service is
// exactly the breakage the exemption exists to prevent — cron runs arbitrary
// operator-supplied jobs, and a read-only filesystem makes them fail at the
// job rather than at the restart.
//
// The evidence is the structured half: these checks cite one entry per *failed*
// unit and nothing else. A finding with no evidence yields no action and lands
// in the unfixable list, which is visible, rather than a drop-in for a unit
// nobody named.
func unitsIn(f finding.Finding) []string {
	seen := map[string]bool{}
	for _, e := range f.Evidence {
		for _, u := range unitPattern.FindAllString(e.Source, -1) {
			seen[u] = true
		}
	}
	delete(seen, "")

	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func init() {
	register(sandboxFix{
		checkID: "SERVICES-0011",
		title:   "Audited system services are sandboxed at the strict tier",
		name:    "50-plumbline-sandbox.conf",
		directives: []string{
			"ProtectSystem=strict",
			"ProtectHome=yes",
		},
		notes: []string{
			"**Find out what each service writes before running this.** Under",
			"ProtectSystem=strict the whole filesystem is read-only except what the unit",
			"declares, and an undeclared path fails at the *write* — so the service starts",
			"cleanly and misbehaves later, which is the worst shape a failure can take.",
			"  systemd-analyze filesystems <unit>",
			"  systemctl show <unit> -p ReadWritePaths,StateDirectory,LogsDirectory",
			"Add ReadWritePaths= — or better StateDirectory= and LogsDirectory=, which",
			"create the directory with the right ownership as well as permitting it — to the",
			"drop-in below for anything the service legitimately writes.",
			"ProtectHome=yes hides /home and /root entirely. A service that reads a user's",
			"key, script or data file stops working; use read-only if it must still read.",
		},
	})
	register(sandboxFix{
		checkID: "SERVICES-0007",
		title:   "Audited system services run with the system directories read-only",
		name:    "50-plumbline-protectsystem.conf",
		directives: []string{
			// full rather than strict: this check's bar is "cannot rewrite
			// /usr", and full delivers that plus /etc while leaving /var and
			// /srv writable — so it is the level that fixes the finding
			// without requiring the service to be profiled first.
			// SERVICES-0011 is the check that asks for strict, and it carries
			// the investigation that goes with it.
			"ProtectSystem=full",
		},
		notes: []string{
			"ProtectSystem=full mounts /usr, /boot, /efi and /etc read-only. It is the level",
			"that satisfies this check without profiling the service first — SERVICES-0011",
			"asks for strict, which requires declaring every path the daemon writes.",
			"A service that writes its own configuration under /etc will fail: check with",
			"  systemd-analyze filesystems <unit>",
		},
	})
	register(sandboxFix{
		checkID: "SERVICES-0008",
		title:   "Audited system services cannot reach user home directories",
		name:    "50-plumbline-protecthome.conf",
		directives: []string{
			"ProtectHome=yes",
		},
		notes: []string{
			"ProtectHome=yes makes /home, /root and /run/user empty and inaccessible.",
			"A service that reads a user's key, script or data file from there stops working;",
			"read-only lets it keep reading while stopping it writing, which is weaker and",
			"still satisfies this check.",
		},
	})
	register(sandboxFix{
		checkID: "SERVICES-0006",
		title:   "Audited system services set NoNewPrivileges",
		name:    "50-plumbline-nonewprivileges.conf",
		directives: []string{
			"NoNewPrivileges=yes",
		},
		notes: []string{
			"A service that legitimately calls a setuid helper — su, sudo, ping, a mount",
			"helper — will fail after this, and fail at the call rather than at the restart.",
		},
	})
}
