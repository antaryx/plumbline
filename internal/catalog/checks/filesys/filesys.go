// Package filesys holds the FILESYS module's checks.
//
// Every check here is a claim about a filesystem that may hold ten million
// inodes, answered from a single shared traversal. That shape brings one rule
// with it, and it governs the whole module:
//
//	A truncated walk can invalidate a negative result.
//	It can never invalidate a positive one.
//
// A SUID binary the walk found is a SUID binary that exists, so a check
// reporting it returns FAIL whether or not the traversal finished. "There are
// no world-writable files" is a claim about everything that was never
// examined, so over a partial walk it is not PASS but
// UNKNOWN(source_truncated). `fact.FSMatches.Complete()` mechanises the
// distinction and `mustBeComplete` below is where every check applies it.
//
// **No check here carries an allowlist of blessed binaries.** Which SUID
// executables are legitimate differs per distribution and per release, and a
// hardcoded list silently excuses whatever an attacker happens to name their
// implant after. What is asserted instead are properties no legitimate binary
// has: a SUID executable that unprivileged users can rewrite, and a SUID
// executable outside the directories a package manager installs into.
package filesys

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// matches reads one walker fact. The runner's required-fact gate guarantees it
// is present and typed before Eval is entered.
func matches(fs *fact.Set, interest string) fact.FSMatches {
	m, _, _ := fact.Get[fact.FSMatches](fs, fact.FSFactID(interest))
	return m
}

// mountFact reads the mount table.
func mountFact(fs *fact.Set) fact.Mounts {
	m, _, _ := fact.Get[fact.Mounts](fs, fact.MountsID)
	return m
}

// mustBeComplete converts an outcome that rests on **absence** into
// UNKNOWN(source_truncated) when the walk behind it did not finish.
//
// It is applied by the call site rather than inferred from the result, for the
// reason the SERVICES and AUTH modules apply their equivalents that way: which
// outcome rests on absence is a property of the check, not of the verdict. In
// this module it happens to always be the PASS — but writing that assumption
// into the helper would make the next check that inverts the polarity wrong in
// a way nothing would catch.
//
// Several facts may back one check. All of them must be complete, because a
// check reading fs.suid and fs.sgid is making one claim about both.
func mustBeComplete(o catalog.Outcome, sources ...fact.FSMatches) catalog.Outcome {
	var bad []fact.FSMatches
	for _, m := range sources {
		if !m.Complete() {
			bad = append(bad, m)
		}
	}
	if len(bad) == 0 {
		return o
	}

	var reasons []string
	var ev []finding.Evidence
	for _, m := range bad {
		reasons = append(reasons, fmt.Sprintf("fs.%s (%s)", m.Interest, m.TruncationSummary()))
		ev = append(ev, truncationEvidence(m))
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonTruncated,
		Subject:       o.Subject,
		Detail: fmt.Sprintf(
			"The filesystem traversal this result rests on did not finish: %s. Nothing was found that violates the rule, but the claim is about everything the walk did not examine, and part of the tree was never reached. Reporting PASS here would convert \"we stopped looking\" into \"there is nothing there\".",
			strings.Join(reasons, "; ")),
		Evidence: append(ev, o.Evidence...),
	}
}

// truncationEvidence cites why a walk stopped short, and how much it saw.
func truncationEvidence(m fact.FSMatches) finding.Evidence {
	root := "/"
	if len(m.Roots) > 0 {
		root = strings.Join(m.Roots, ", ")
	}
	note := fmt.Sprintf("walk truncated: %s; %d inode(s) examined, %d row(s) recorded",
		m.TruncationSummary(), m.InodesVisited, len(m.Rows))
	if m.Overflow > 0 {
		note += fmt.Sprintf(", %d discarded past the cap", m.Overflow)
	}
	return finding.NewEvidence(root, 0, note, "")
}

// renderPerm formats permission bits the way an operator reads them out of
// `stat -c %a`, which is the form they will type into chmod.
func renderPerm(m fs.FileMode) string { return fmt.Sprintf("%04o", m.Perm()) }

// rowEvidence cites one matched inode.
//
// There is deliberately no digest. The walk stats inodes and never opens one,
// so there are no bytes in the evidence store for a digest to point at, and
// one here would be a reference into an archive that does not contain the
// thing it references. Line is 0 for the same reason: the finding is about the
// inode, not about anything inside it.
func rowEvidence(r fact.FSRow) finding.Evidence {
	kind := "file"
	switch {
	case r.IsDir:
		kind = "directory"
	case r.Mode&fs.ModeDevice != 0:
		kind = "device node"
	}
	special := ""
	switch {
	case r.Mode&fs.ModeSetuid != 0 && r.Mode&fs.ModeSetgid != 0:
		special = ", setuid+setgid"
	case r.Mode&fs.ModeSetuid != 0:
		special = ", setuid"
	case r.Mode&fs.ModeSetgid != 0:
		special = ", setgid"
	case r.Mode&fs.ModeSticky != 0:
		special = ", sticky"
	}
	return finding.NewEvidence(r.Path, 0,
		fmt.Sprintf("%s: mode %s%s, uid %d, gid %d", kind, renderPerm(r.Mode), special, r.UID, r.GID), "")
}

// rowsEvidence cites a list of inodes, capped so that a finding stays readable.
//
// A host with four thousand world-writable files produces a finding nobody
// reads if every one is listed. The cap is on the *evidence*, not on the
// verdict or the count: the detail always states the true total, so the
// finding never understates the problem it is summarising.
const maxEvidenceRows = 25

func rowsEvidence(rows []fact.FSRow) []finding.Evidence {
	n := len(rows)
	if n > maxEvidenceRows {
		n = maxEvidenceRows
	}
	ev := make([]finding.Evidence, 0, n+1)
	for _, r := range rows[:n] {
		ev = append(ev, rowEvidence(r))
	}
	if len(rows) > n {
		ev = append(ev, finding.NewEvidence("", 0,
			fmt.Sprintf("… and %d more; the count in the detail is the full total", len(rows)-n), ""))
	}
	return ev
}

// paths renders a row list for a detail string, capped the same way.
func paths(rows []fact.FSRow) string {
	n := len(rows)
	if n > maxEvidenceRows {
		n = maxEvidenceRows
	}
	out := make([]string, 0, n)
	for _, r := range rows[:n] {
		out = append(out, r.Path)
	}
	joined := strings.Join(out, ", ")
	if len(rows) > n {
		joined += fmt.Sprintf(", and %d more", len(rows)-n)
	}
	return joined
}

// under reports whether p is at or beneath any of the given directories.
func under(p string, dirs ...string) bool {
	for _, d := range dirs {
		d = strings.TrimSuffix(d, "/")
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// filter returns the rows satisfying keep, preserving the fact's path order.
func filter(rows []fact.FSRow, keep func(fact.FSRow) bool) []fact.FSRow {
	var out []fact.FSRow
	for _, r := range rows {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

// concat joins two row lists, which is how a check reading fs.suid and fs.sgid
// makes one claim about both.
func concat(a, b []fact.FSRow) []fact.FSRow {
	out := make([]fact.FSRow, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// plural picks the suffix or verb form for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
