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
// Each sandbox check reports the units it judged and what each one was set to,
// so the script names the units that actually failed on this host rather than
// every unit the check audits.
//
// Three of the four sandbox checks are registered below. SERVICES-0011, the
// strict tier, deliberately is not — see the comment above init.
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
// the exemptions, and writing a sandboxing directive into cron.service is
// exactly the breakage the exemption exists to prevent — cron runs arbitrary
// operator-supplied jobs, and restricting its filesystem makes them fail at the
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

// **SERVICES-0011 has no generated fix, deliberately, and must not be given one
// again.** It is the one sandbox check whose remediation cannot be written from
// a scan, and the registration that used to be here took a host down.
//
// The directives were `ProtectSystem=strict` and `ProtectHome=yes`, written as
// a drop-in for every unit the check failed. Under strict, the *entire*
// filesystem hierarchy is read-only apart from /dev, /proc and /sys — which
// includes /run and /var, not merely /usr and /etc. An operator followed the
// script's own instruction to restart the units it had written for, and
// systemd-journald.service (which writes /var/log) and dbus.service (which
// creates its socket under /run) both failed to come back.
//
// **The note the fix carried was not enough, and that is the lesson.** It said
// in six lines to run `systemd-analyze filesystems` first and to add
// ReadWritePaths= for anything the service legitimately writes. That is correct
// advice attached to a file that was already written: the script's own shape —
// commands above, comments about them — invites reading the comment as context
// for a step rather than as a precondition for it, and everything else in the
// script is genuinely safe to run first and read after.
//
// What makes this different from the other three sandbox fixes is that the
// missing information is per-service and is not in the finding. NoNewPrivileges
// (0006), ProtectSystem=full (0007) and ProtectHome=yes (0008) each need one
// decision the operator can make from the unit's purpose. strict needs the
// complete set of paths a daemon writes at runtime, which the check does not
// collect, cannot infer, and which differs per host and per workload. A
// generator that must guess a set it has no way to observe is proposing an
// outage, however well it is commented.
//
// So the check falls back to its catalog Remediation — `systemctl edit`,
// `systemd-analyze filesystems`, declare ReadWritePaths= — which is the same
// procedure, in the one form that cannot be pasted into a root shell whole.
// That fallback is a designed path, not an absence: SARIF emits the advisory
// commands with `"source": "advisory"` (see remediationFor), and the --fix
// block counts the finding in "still failing with no automated fix".
//
// Undoing this needs the missing fact, not a stronger warning: a collector that
// records what each unit actually writes, and a fix that emits ReadWritePaths=
// from it. ADR-0006 is the standing reason plumbline proposes rather than
// applies; this is the case that says a proposal can be too dangerous to make.
func init() {
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
