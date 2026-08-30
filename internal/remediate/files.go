package remediate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// backupFunc copies a file aside before the script's first change to it.
//
// **Once, and never again — which is the whole subtlety.** `cp file file.bak`
// on a second run would overwrite the backup with the already-edited file and
// destroy the only copy of what the host looked like before plumbline touched
// it. The guard makes the backup a record of the original rather than of the
// previous run, and makes the step idempotent along with everything else here.
//
// -p keeps mode, ownership and timestamps, so the copy is a restorable original
// rather than a root-owned 0644 approximation of one.
const backupFunc = `
# Copy FILE to FILE.bak, once. An existing backup is never overwritten: on a
# second run that would replace the original with the already-edited version.
plumbline_backup() {
	if [ ! -e "$1.bak" ]; then
		cp -p -- "$1" "$1.bak"
	fi
}
`

// pathsFrom is the set of host paths a finding cited, deduplicated and sorted.
//
// **Evidence is capped and this is where that becomes a correctness problem.**
// A finding for four hundred world-writable files carries five excerpts and a
// line saying so; a script built from those five and silent about it reads as
// the whole of the work. So the caller is told how many paths came back, and
// every fix that uses this emits the command that enumerates the rest.
//
// The synthetic "… and N more" evidence entry carries no source, which is what
// the emptiness check skips — not a defensive nil-guard but the mechanism by
// which a summary line stays out of a list of chmod targets.
func pathsFrom(f finding.Finding) []string {
	seen := map[string]bool{}
	for _, e := range f.Evidence {
		if e.Source == "" {
			continue
		}
		seen[e.Source] = true
	}
	if len(seen) == 0 && f.Subject != "" {
		seen[f.Subject] = true
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// modeFix runs one command over every path a finding cited.
//
// The three permission findings in this phase are the same shape — a list of
// paths and one command to run over each — and differ only in the command and
// in what an operator should be told to check first.
type modeFix struct {
	checkID string
	title   string
	// argv is the command, with the path appended as its last argument.
	argv []string
	// enumerate is the command that lists every affected path on the host, for
	// the note that admits the script's list may be partial.
	enumerate string
	// caution is a line the operator should read before running it.
	caution string
}

func (m modeFix) CheckID() string { return m.checkID }

func (m modeFix) Build(f finding.Finding, _ Options) (Action, bool) {
	paths := pathsFrom(f)
	if len(paths) == 0 {
		// Nothing to act on. A fix that emitted a command with no operand
		// would produce a script that fails at the first line under `set -e`,
		// which is a worse outcome than declining the finding.
		return Action{}, false
	}

	a := Action{CheckID: m.checkID, Title: titleOf(f, m.title)}
	if m.caution != "" {
		note(&a, m.caution)
	}
	note(&a, fmt.Sprintf("%s below came from this scan's evidence, which is capped.", pathCount(len(paths))))
	note(&a, "List every one on the host with: "+m.enumerate)

	for _, p := range paths {
		command(&a, append(append([]string{}, m.argv...), p)...)
	}
	return a, true
}

func pathCount(n int) string {
	if n == 1 {
		return "The path"
	}
	return fmt.Sprintf("The %d paths", n)
}

// pamNullokFix strips the empty-password argument from the pam_unix.so rules a
// finding named.
//
// **It edits the files the scan actually read, not a path written down here.**
// /etc/pam.d/common-password is the Debian family's; RHEL keeps the same rules
// in /etc/pam.d/system-auth, and a service that has diverged from the shared
// stack has diverged exactly here — AUTH-0004 reports every file it found the
// argument in, and this fixes those.
type pamNullokFix struct{}

func (pamNullokFix) CheckID() string { return "AUTH-0004" }

func (pamNullokFix) Build(f finding.Finding, _ Options) (Action, bool) {
	files := pathsFrom(f)
	if len(files) == 0 {
		return Action{}, false
	}
	// The subject is the module name rather than a path for this check, so a
	// fallback to it would produce `sed -i ... pam_unix.so`.
	files = keepPaths(files)
	if len(files) == 0 {
		return Action{}, false
	}

	a := Action{
		CheckID: "AUTH-0004",
		Title:   titleOf(f, "PAM does not accept an empty password"),
	}
	note(&a, "USERS-0003 reports which accounts have an empty password field. Check it first:")
	note(&a, "an account relying on nullok stops being able to log in the moment this runs.")
	note(&a, "Each file is copied to FILE.bak before it is edited.")

	for _, file := range files {
		command(&a, "plumbline_backup", file)
		// **The address restricts the edit to pam_unix.so lines.** nullok on
		// pam_ldap or pam_sss is a different decision about a different
		// credential store, and AUTH-0004 says nothing about it — an
		// unaddressed substitution would silently make that decision too.
		//
		// The pattern takes the whitespace before the argument and gives back
		// whatever followed it, so ` nullok ` becomes ` ` and a trailing
		// ` nullok` becomes nothing. Running it again matches nothing, which
		// is what makes the step idempotent.
		command(&a, "sed", "-E", "-i",
			`/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?([[:space:]]|$)/\2/g`,
			file)
	}
	return a, true
}

// keepPaths drops anything that is not an absolute path. A finding's Subject
// can be a module name, a unit, a sysctl key — none of which sed can open.
func keepPaths(in []string) []string {
	var out []string
	for _, p := range in {
		if strings.HasPrefix(p, "/") {
			out = append(out, p)
		}
	}
	return out
}

// ownerFix restores ownership and mode on one file.
type ownerFix struct {
	checkID  string
	title    string
	fallback string
	owner    string
	mode     string
}

func (o ownerFix) CheckID() string { return o.checkID }

func (o ownerFix) Build(f finding.Finding, _ Options) (Action, bool) {
	path := f.Subject
	if !strings.HasPrefix(path, "/") {
		if p := keepPaths(pathsFrom(f)); len(p) > 0 {
			path = p[0]
		} else {
			path = o.fallback
		}
	}
	if path == "" {
		return Action{}, false
	}

	a := Action{CheckID: o.checkID, Title: titleOf(f, o.title)}
	note(&a, "Both steps are already-correct no-ops on a host where only one of them was wrong.")
	command(&a, "chown", o.owner, "--", path)
	command(&a, "chmod", o.mode, "--", path)
	return a, true
}

func init() {
	register(modeFix{
		checkID: "FILESYS-0003",
		title:   "No file is world-writable",
		// o-w rather than a fixed mode: the owner's and the group's
		// permissions are not this check's business, and `chmod 644` would
		// silently take away a group write that something depends on.
		argv:      []string{"chmod", "o-w", "--"},
		enumerate: "find / -xdev -type f -perm -0002 -ls",
		caution:   "A file made world-writable is usually two accounts sharing it. Prefer a group over removing the bit outright.",
	})
	register(modeFix{
		checkID: "FILESYS-0004",
		title:   "World-writable directories have the sticky bit set",
		// +t and nothing else. A world-writable directory that needs to stay
		// world-writable — /tmp, /var/tmp, a spool — is fixed by the sticky
		// bit, not by taking the permission away, and taking it away is what
		// breaks the host.
		argv:      []string{"chmod", "a+t", "--"},
		enumerate: "find / -xdev -type d -perm -0002 ! -perm -1000 -ls",
		caution:   "The sticky bit is the fix here rather than removing the write permission: these directories are usually shared on purpose.",
	})
	register(pamNullokFix{})
	register(ownerFix{
		checkID:  "CRON-0001",
		title:    "The system crontab is owned by root and writable only by root",
		fallback: "/etc/crontab",
		owner:    "root:root",
		// 600 rather than the conventional 644. Nothing but cron reads it, and
		// the schedule of a root process is reconnaissance — CRON-0005 is the
		// check that says so.
		mode: "600",
	})
}
