// Package users holds the USERS module's checks.
//
// Almost every check here is a negative assertion — no account other than root
// holds uid 0, no account has an empty password, no uid is duplicated — and a
// negative assertion is only as good as the completeness of what it was drawn
// from. Two things make /etc/passwd incomplete in ways that are invisible if
// you do not look for them:
//
//   - **NIS/LDAP compatibility entries.** A line beginning "+" tells glibc to
//     import accounts from a directory service. Those accounts are not in the
//     file. "No account has uid 0" over a file that ends in "+::::::" is a
//     claim about a list that is explicitly not the whole list.
//   - **Lines that would not parse.** A line we could not read is a line that
//     could have held the account we are asserting does not exist.
//
// In both cases a positive result still stands — an account we found with uid
// 0 has uid 0 — and only the negative one becomes UNKNOWN. That is the same
// asymmetry the shared filesystem walker enforces (ADR-0014), arrived at
// independently because it is a property of negative assertions rather than of
// filesystems.
package users

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// passwdFact and shadowFact read the module's facts. The runner's required-fact
// gate guarantees they are present and typed before Eval is entered, so these
// cannot fail in a way a check must handle.
func passwdFact(fs *fact.Set) fact.Passwd {
	p, _, _ := fact.Get[fact.Passwd](fs, fact.PasswdID)
	return p
}

func shadowFact(fs *fact.Set) fact.Shadow {
	s, _, _ := fact.Get[fact.Shadow](fs, fact.ShadowID)
	return s
}

// incompleteness describes why /etc/passwd may not be the whole account list.
type incompleteness struct {
	compat    []fact.CompatEntry
	malformed []int
}

func (i incompleteness) any() bool { return len(i.compat) > 0 || len(i.malformed) > 0 }

// reason renders the explanation for an UNKNOWN.
func (i incompleteness) reason(p fact.Passwd) string {
	var parts []string
	if len(i.compat) > 0 {
		specs := make([]string, 0, len(i.compat))
		for _, c := range i.compat {
			specs = append(specs, fmt.Sprintf("%q at line %d", c.Spec, c.Line))
		}
		parts = append(parts, fmt.Sprintf(
			"%s imports accounts from a directory service (%s), so the accounts it governs are not in this file",
			p.Path, strings.Join(specs, ", ")))
	}
	if len(i.malformed) > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d line(s) of %s could not be parsed (line %s), and a line we could not read could have held the account in question",
			len(i.malformed), p.Path, joinInts(i.malformed)))
	}
	return strings.Join(parts, "; ")
}

// evidence cites the lines that make the file incomplete.
func (i incompleteness) evidence(p fact.Passwd) []finding.Evidence {
	var out []finding.Evidence
	for _, c := range i.compat {
		out = append(out, finding.NewEvidence(p.Path, c.Line,
			c.Spec+"  (directory-service import; the accounts it adds are not in this file)", p.Digest))
	}
	for _, line := range i.malformed {
		out = append(out, finding.NewEvidence(p.Path, line, "unparseable line", p.Digest))
	}
	return out
}

// incompleteView reports what stops /etc/passwd being the whole account list.
func incompleteView(p fact.Passwd) incompleteness {
	return incompleteness{compat: p.CompatEntries, malformed: p.Malformed}
}

// unknownIfIncomplete converts a would-be negative result into UNKNOWN when
// the account list is not the whole list.
//
// It is a helper rather than a convention because every check in this module
// needs it and the failure mode of forgetting is silent: a PASS that means "we
// looked at the accounts we could see", which is exactly the false assurance
// this project exists to prevent.
func unknownIfIncomplete(p fact.Passwd, pass catalog.Outcome) catalog.Outcome {
	inc := incompleteView(p)
	if !inc.any() {
		return pass
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonAmbiguousState,
		Subject:       pass.Subject,
		Detail: fmt.Sprintf(
			"No violation was found among the accounts defined locally, but %s. The result therefore cannot be confirmed for every account on this host.",
			inc.reason(p)),
		Evidence: inc.evidence(p),
	}
}

// shadowIncomplete reports whether /etc/shadow itself had unparseable lines.
func shadowIncomplete(s fact.Shadow) bool { return len(s.Malformed) > 0 }

// unknownIfShadowIncomplete is unknownIfIncomplete for the shadow database.
func unknownIfShadowIncomplete(p fact.Passwd, s fact.Shadow, pass catalog.Outcome) catalog.Outcome {
	if shadowIncomplete(s) {
		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonParse,
			Subject:       pass.Subject,
			Detail: fmt.Sprintf(
				"No violation was found among the entries that parsed, but %d line(s) of %s could not be read (line %s), and an unreadable line could have held the account in question.",
				len(s.Malformed), s.Path, joinInts(s.Malformed)),
			Evidence: shadowEvidence(s, s.Malformed, "unparseable line"),
		}
	}
	return unknownIfIncomplete(p, pass)
}

// passwdEvidence cites one account's line in /etc/passwd.
//
// The excerpt is reconstructed from the parsed fields rather than quoting the
// raw line, because the raw line carries the GECOS field and the GECOS field
// carries somebody's name and telephone number. A finding says what it needs
// to say and no more.
func passwdEvidence(p fact.Passwd, e fact.PasswdEntry) finding.Evidence {
	return finding.NewEvidence(p.Path, e.Line,
		fmt.Sprintf("%s:x:%d:%d:...:%s:%s", e.Name, e.UID, e.GID, e.Home, e.Shell),
		p.Digest)
}

// shadowEvidence cites lines in /etc/shadow.
//
// There is deliberately no digest. The bytes of /etc/shadow are never stored
// as evidence (internal/collect.IsCredentialFile), so a digest here would
// point into an archive that does not contain what it points at.
func shadowEvidence(s fact.Shadow, lines []int, excerpt string) []finding.Evidence {
	out := make([]finding.Evidence, 0, len(lines))
	for _, line := range lines {
		out = append(out, finding.NewEvidence(s.Path, line, excerpt, ""))
	}
	return out
}

// shadowEntryEvidence cites one account's password state without quoting the
// field it was derived from.
func shadowEntryEvidence(s fact.Shadow, e fact.ShadowEntry, what string) finding.Evidence {
	return finding.NewEvidence(s.Path, e.Line, fmt.Sprintf("%s: %s", e.Name, what), "")
}

// nonLoginShells are the shells that cannot yield an interactive session.
//
// The list spans distributions on purpose: nologin lives in /usr/sbin on
// Debian-family systems and /sbin on Red Hat-family ones, and a check that
// knew only one would report every account on the other as interactive.
//
// /bin/sync is here because it runs sync(1) and exits. It permits a password
// prompt but cannot produce a session, and the account that traditionally uses
// it exists on almost every system — failing it would put a finding nobody can
// act on into almost every report.
//
// **An unrecognised shell is treated as interactive.** That is the safe
// direction: a FAIL an operator suppresses costs them a minute, while a PASS
// that silently accepted an unfamiliar login shell costs them the finding
// entirely.
var nonLoginShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/usr/bin/nologin":  true,
	"/bin/nologin":      true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"/dev/null":         true,
	"/bin/sync":         true,
	"/usr/bin/sync":     true,
}

// interactiveShell reports whether this shell field can yield a session.
//
// An empty shell field is interactive. That is the trap in this check: an
// account with no shell does not get "no shell", it gets the system default,
// which is /bin/sh. A parser that read empty as "nothing" would report the
// most permissive configuration in the file as the most restricted.
func interactiveShell(shell string) bool {
	s := strings.TrimSpace(shell)
	if s == "" {
		return true
	}
	return !nonLoginShells[s]
}

// SystemUIDMax is the highest uid this module treats as a system account.
//
// 1000 is the convention shipped by every current distribution, and it is an
// assumption rather than an observation: the real boundary is SYS_UID_MAX in
// /etc/login.defs, which this module does not yet collect — that fact belongs
// to the AUTH work package. Red Hat-family systems before RHEL 7 used 500, so
// on such a host an ordinary user between 500 and 999 is misread as a system
// account. The checks that rely on this state the boundary in their detail so
// a reader can see immediately whether it applies to them.
const SystemUIDMax = 999

// isSystemAccount reports whether uid falls in the system range, excluding
// root, which USERS-0001 governs.
func isSystemAccount(uid uint32) bool { return uid > 0 && uid <= SystemUIDMax }

// joinInts renders a sorted line-number list for a detail string.
func joinInts(in []int) string {
	out := append([]int(nil), in...)
	sort.Ints(out)
	parts := make([]string, 0, len(out))
	for _, n := range out {
		parts = append(parts, fmt.Sprint(n))
	}
	return strings.Join(parts, ", ")
}

// joinNames renders a sorted name list for a detail string.
func joinNames(in []string) string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return strings.Join(out, ", ")
}
