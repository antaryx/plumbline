package remediate

import (
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// sysctlFix sets one or more kernel parameters, live and persistently.
//
// Both halves are needed and neither is sufficient. `sysctl -w` changes the
// running kernel and is undone by the next reboot; a line in a drop-in changes
// what the kernel boots with and does nothing until something applies it. A
// remediation that did one and called it done would leave a host that passes
// today and fails in three months, or one that passes the file check and is
// still exposed right now.
type sysctlFix struct {
	checkID string
	title   string
	// pairs are the parameters and the values this check wants, in a slice
	// rather than a map so the order the script sets them in is the order they
	// were written here rather than a map iteration.
	pairs [][2]string
}

func (s sysctlFix) CheckID() string { return s.checkID }

func (s sysctlFix) Build(f finding.Finding, opts Options) (Action, bool) {
	a := Action{
		CheckID:     s.checkID,
		Title:       titleOf(f, s.title),
		SysctlPairs: map[string]string{},
	}
	for _, kv := range s.pairs {
		// The live half. `sysctl -w key=value` and not `sysctl key=value`,
		// because the short form is ambiguous with a read on some
		// implementations and this is being handed to an operator to run as
		// root.
		command(&a, "sysctl", "-w", kv[0]+"="+kv[1])
		a.SysctlPairs[kv[0]] = kv[1]
	}
	return a, true
}

// titleOf prefers the finding's own title, so the script says what the report
// said. The fix carries a fallback for a finding that arrived without one —
// a hand-built Plan in a test, or a bundle from a catalog that has since
// renamed the check.
func titleOf(f finding.Finding, fallback string) string {
	if f.Title != "" {
		return f.Title
	}
	return fallback
}

// The four kernel parameters this phase covers.
//
// **They are written out rather than derived from the catalog's remediation
// text.** Every one of these checks already says "Set kernel.dmesg_restrict to
// 1" in prose, and reading the key and the value back out of that sentence
// would make the wording of a summary — reviewed as English, changed freely in
// a patch release — the thing that decides what plumbline writes to
// /etc/sysctl.d as root. The duplication is the point: a fix is a second,
// deliberate statement of the same intent, and the fixture tests hold the two
// together.
func init() {
	register(sysctlFix{
		checkID: "KERNEL-0004",
		title:   "The kernel ring buffer is not readable by unprivileged users",
		pairs:   [][2]string{{"kernel.dmesg_restrict", "1"}},
	})
	register(sysctlFix{
		checkID: "KERNEL-0016",
		title:   "TCP SYN cookies are enabled",
		pairs:   [][2]string{{"net.ipv4.tcp_syncookies", "1"}},
	})
	register(sysctlFix{
		checkID: "KERNEL-0026",
		title:   "IPv6 router advertisements are refused in the sysctl configuration",
		// Both pseudo-interfaces, because neither alone is the effective
		// setting: `all` and `default` combine, and a host with one set and the
		// other not still accepts advertisements on an interface that appeared
		// after boot.
		pairs: [][2]string{
			{"net.ipv6.conf.all.accept_ra", "0"},
			{"net.ipv6.conf.default.accept_ra", "0"},
		},
	})
	register(sysctlFix{
		checkID: "KERNEL-0030",
		title:   "Hardlink protection is written to the sysctl configuration",
		pairs:   [][2]string{{"fs.protected_hardlinks", "1"}},
	})
}

// Merge writes pairs into the text of a sysctl drop-in and returns the result.
//
// **This is the idempotency, and it is a pure function over a string so that it
// can be tested as one.** The rule per key:
//
//   - the first line that sets the key is replaced, in place, with the
//     canonical `key = value`;
//   - any further line setting the same key is removed, so a file that already
//     had a duplicate comes out with one;
//   - a key that appears nowhere is appended;
//   - every other line — comments, blanks, keys nobody asked about — is kept
//     exactly as it was.
//
// From which Merge(Merge(x, p), p) == Merge(x, p) for every x and p, which is
// the property a remediation run repeatedly needs and the one the tests assert
// directly rather than by inspection.
//
// **In place rather than delete-and-append**, which was the simpler
// implementation and the wrong one. Appending moves a key to the end of the
// file on the run that first corrects it; sysctl applies last-wins, so a key an
// operator had deliberately placed *before* a later override would silently
// change meaning. Replacing where it stands changes the value and nothing else.
//
// A leading `-` is recognised as the key it marks. sysctl.d(5) gives it the
// meaning "do not fail if this key does not exist", so `-kernel.dmesg_restrict
// = 1` is a line that sets the key — and a merge that did not see it would
// append a second line for a key that was already there, which is exactly the
// duplicate this function exists to prevent. The rewritten line drops the `-`,
// because plumbline is writing a key it has just observed the kernel to have.
func Merge(existing string, pairs map[string]string) string {
	lines := splitLines(existing)

	for _, key := range sortedKeys(pairs) {
		value := pairs[key]
		out := make([]string, 0, len(lines)+1)
		written := false
		for _, l := range lines {
			if keyOf(l) != key {
				out = append(out, l)
				continue
			}
			if !written {
				out = append(out, key+" = "+value)
				written = true
			}
			// Later duplicates are dropped by not appending anything.
		}
		if !written {
			out = append(out, key+" = "+value)
		}
		lines = out
	}

	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// keyOf is the sysctl key one configuration line sets, or "" for a line that
// sets nothing — a comment, a blank, or anything without an `=`.
func keyOf(line string) string {
	l := strings.TrimLeft(line, " \t")
	l = strings.TrimPrefix(l, "-")
	if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
		return ""
	}
	eq := strings.Index(l, "=")
	if eq < 0 {
		return ""
	}
	return strings.TrimRight(l[:eq], " \t")
}

// splitLines splits a file into its lines, dropping the trailing empty element
// a final newline produces so that appending does not leave a blank line in the
// middle of the file.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// sysctlSetFunc is Merge, written in shell, for the proposed script.
//
// **Two implementations of one rule is a real cost and it is paid on purpose.**
// plumbline itself will apply a plan with Merge — pure Go, through the system
// seam, no shell anywhere — and this exists so that an operator can read what
// that would do and, if they would rather, run it by hand on a host plumbline
// is not installed on. The two are held together by a test that runs this
// script twice against a temporary file and compares the result with Merge's,
// so a change to either that the other did not follow fails the build rather
// than the host.
//
// awk rather than sed because the rule is not a substitution: the first
// occurrence is replaced, later ones are removed, and an absent key is
// appended. A sed one-liner can do the first of those and quietly gets the
// other two wrong.
const sysctlSetFunc = `
# Set KEY=VALUE in FILE: in place if the key is already there, appended if it
# is not, and duplicates collapsed to one. Running it twice leaves the file
# byte-identical, which is what makes this whole script safe to re-run.
plumbline_sysctl_set() {
	pl_key=$1 pl_val=$2 pl_file=$3
	[ -f "$pl_file" ] || : > "$pl_file"
	pl_tmp=$(mktemp)
	awk -v key="$pl_key" -v val="$pl_val" '
		{
			line = $0
			sub(/^[ \t]*/, "", line)
			sub(/^-/, "", line)
			if (line ~ /^[#;]/ || index(line, "=") == 0) { print; next }
			k = substr(line, 1, index(line, "=") - 1)
			sub(/[ \t]+$/, "", k)
			if (k != key) { print; next }
			if (!done) { print key " = " val; done = 1 }
			next
		}
		END { if (!done) print key " = " val }
	' "$pl_file" > "$pl_tmp"
	cat "$pl_tmp" > "$pl_file"
	rm -f "$pl_tmp"
}
`
