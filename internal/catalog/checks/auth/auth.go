// Package auth holds the AUTH module's checks.
//
// PAM is the only place on a Linux host where the rules for deciding that
// somebody is who they claim to be are actually written down. /etc/shadow
// holds the hashes, sshd_config decides what may be offered over the network,
// and this is where "at least fourteen characters", "locked after five
// failures" and "an empty password is not a password" either exist or do not.
//
// Two limits apply to every check here, and both are stated in the checks
// rather than papered over:
//
//   - **Presence and arguments, not control flow.** Simulating PAM means
//     implementing the bracketed `[success=1 default=ignore]` jump semantics,
//     and a stack simulator that is subtly wrong produces confident verdicts
//     about which module actually runs. What is asserted is that a rule is
//     written, with an enforcing control and the right arguments. Where the
//     surrounding control flow could still defeat it — a `sufficient` line
//     above that short-circuits the stack — the check says so in its spec
//     rather than claiming to have checked.
//
//   - **An incomplete stack cannot prove absence.** An include that could not
//     be followed might hold the rule that decides the verdict. Every check
//     that concludes something from *not* finding a module resolves to UNKNOWN
//     instead, which is ADR-0014 applied to a file format that is a graph.
package auth

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// pamFact reads the module's fact. The runner's required-fact gate guarantees
// it is present and typed before Eval is entered.
func pamFact(fs *fact.Set) fact.PAM {
	p, _, _ := fact.Get[fact.PAM](fs, fact.PAMID)
	return p
}

// notInstalled is the verdict when the host has no PAM configuration.
//
// NOT_APPLICABLE and not PASS. A host without PAM is not one whose password
// policy is satisfactory; it is one that authenticates by some mechanism this
// module cannot read — a minimal container image, a busybox appliance — and
// which may well have no password policy whatsoever. PASS here would be
// assurance about something never examined.
func notInstalled() catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: "There is no /etc/pam.d on this host, so it does not use PAM. Whatever decides that a login attempt succeeds here is a mechanism this module cannot read — a minimal container image and a busybox-based appliance both look like this — and no conclusion about password policy may be drawn from its absence.",
	}
}

// noStack is the verdict when PAM is installed but the shared stacks are not
// where either distribution family keeps them.
//
// UNKNOWN and never PASS. The stack is real and this collector cannot say
// where its rules live, so searching whatever files happened to be present
// would be guessing at the layout — and a guess that found nothing would read
// as a clean host.
func noStack(p fact.PAM, t fact.PAMType) catalog.Outcome {
	if p.DirState == fact.FileDenied || p.DirState == fact.FileError {
		reason := finding.ReasonPermission
		if p.DirState == fact.FileError {
			reason = finding.ReasonAmbiguousState
		}
		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: reason,
			Subject:       "/etc/pam.d",
			Detail: fmt.Sprintf(
				"/etc/pam.d could not be examined (%s), so no rule in the %s stack was read. Every authentication policy on this host is written there and nowhere else.",
				p.DirMsg, t),
			Evidence: []finding.Evidence{
				finding.NewEvidence("/etc/pam.d", 0, string(p.DirState)+": "+p.DirMsg, ""),
			},
		}
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonAmbiguousState,
		Subject:       "/etc/pam.d",
		Detail: fmt.Sprintf(
			"/etc/pam.d exists but neither distribution family's shared stacks were found in it: no system-auth or password-auth (Red Hat), and no common-auth or common-password (Debian). The %s rules for this host are in files this module does not know to look at, so nothing may be concluded about them — searching whatever happened to be present would be guessing at the layout, and a guess that found nothing would read as a clean host.",
			t),
		Evidence: []finding.Evidence{
			finding.NewEvidence("/etc/pam.d", 0, "present, but no recognised shared stack", ""),
		},
	}
}

// unknownIfIncomplete converts an outcome that rests on **absence** into
// UNKNOWN when any include in the stacks could not be followed.
//
// The call site decides whether to apply it rather than the helper guessing
// from the result, for the reason set out in the SERVICES module: which
// outcome rests on absence differs per check. AUTH-0001 concludes FAIL from
// finding no pam_pwquality; AUTH-0004 concludes PASS from finding no nullok.
// Both are negative conclusions, both are invalidated by an include that could
// not be read, and only one of them is a PASS.
func unknownIfIncomplete(stacks []fact.PAMService, o catalog.Outcome) catalog.Outcome {
	bad := fact.UnresolvedIncludes(stacks)
	if len(bad) == 0 {
		return o
	}

	reason := finding.ReasonAmbiguousState
	if allDenied(bad) {
		reason = finding.ReasonPermission
	}

	names := make([]string, 0, len(bad))
	ev := make([]finding.Evidence, 0, len(bad))
	for _, inc := range bad {
		names = append(names, inc.Path)
		ev = append(ev, includeEvidence(inc))
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       o.Subject,
		Detail: fmt.Sprintf(
			"This result rests on a rule not being present in the stack, and %d include%s could not be followed (%s). PAM stacks are a graph rather than a file: an include that was not read may hold exactly the rule that decides this check, so the stack examined is not the stack in force.",
			len(bad), plural(len(bad), "", "s"), strings.Join(names, ", ")),
		Evidence: append(ev, o.Evidence...),
	}
}

// allDenied reports whether every unresolved include failed for want of
// privilege, which is a different reason code from a stack that is broken.
func allDenied(incs []fact.PAMInclude) bool {
	for _, inc := range incs {
		if !strings.Contains(inc.Reason, "permission denied") {
			return false
		}
	}
	return len(incs) > 0
}

// includeEvidence cites one unresolved include.
func includeEvidence(inc fact.PAMInclude) finding.Evidence {
	directive := inc.Directive
	if inc.Type != "" {
		directive = string(inc.Type) + " " + inc.Directive
	}
	return finding.NewEvidence(inc.File, inc.Line,
		fmt.Sprintf("%s %s  → %s: %s", directive, inc.Target, inc.Path, inc.Reason), "")
}

// lineEvidence cites one PAM rule, quoting it the way it is written.
func lineEvidence(p fact.PAM, l fact.PAMLine) finding.Evidence {
	parts := []string{string(l.Type), l.Control, l.Module}
	parts = append(parts, l.Args...)
	text := strings.Join(parts, " ")
	if l.Optional {
		text = "-" + text
	}
	return finding.NewEvidence(l.File, l.Line, text, p.Digests[l.File])
}

// linesEvidence cites a list of rules.
func linesEvidence(p fact.PAM, lines []fact.PAMLine) []finding.Evidence {
	ev := make([]finding.Evidence, 0, len(lines))
	for _, l := range lines {
		ev = append(ev, lineEvidence(p, l))
	}
	return ev
}

// settingEvidence cites one key=value from /etc/security.
func settingEvidence(p fact.PAM, s fact.PwQualitySetting) finding.Evidence {
	return finding.NewEvidence(s.File, s.Line, s.Key+" = "+s.Value, p.Digests[s.File])
}

// stackEvidence cites the files a negative conclusion was drawn from, so a
// FAIL that says "no such rule exists" names the files it looked in.
func stackEvidence(stacks []fact.PAMService) []finding.Evidence {
	ev := make([]finding.Evidence, 0, len(stacks))
	for _, s := range stacks {
		path := s.Path
		note := fmt.Sprintf("%d rule(s) read", len(s.Lines))
		if s.ResolvedPath != "" {
			note += "; content from " + s.ResolvedPath
		}
		ev = append(ev, finding.NewEvidence(path, 0, note, ""))
	}
	return ev
}

// stackNames renders a stack list for a detail string, naming the file an
// operator would actually edit when it differs from the one they would look
// for.
func stackNames(stacks []fact.PAMService) string {
	names := make([]string, 0, len(stacks))
	for _, s := range stacks {
		if s.ResolvedPath != "" {
			names = append(names, fmt.Sprintf("%s (→ %s)", s.Path, s.ResolvedPath))
			continue
		}
		names = append(names, s.Path)
	}
	return strings.Join(names, " and ")
}

// modules renders a module-name list for a detail string.
func modules(lines []fact.PAMLine) string {
	seen := map[string]bool{}
	var names []string
	for _, l := range lines {
		if !seen[l.Module] {
			seen[l.Module] = true
			names = append(names, l.Module)
		}
	}
	return strings.Join(names, ", ")
}

// effectiveInt resolves a numeric parameter that may be set on the PAM line,
// in the /etc/security file, or nowhere.
//
// The precedence is the module's: the configuration file is read first and the
// arguments on the PAM line override it. A check that consulted only one
// source would be right on whichever kind of host it was written against and
// wrong on the other, silently, because both forms are common and neither is
// obviously incomplete when read alone.
func effectiveInt(lines []fact.PAMLine, file fact.SettingsFile, key string) (int, string, bool) {
	if s, ok := file.Get(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(s.Value)); err == nil {
			// The file supplies it; a module argument may still override.
			for _, l := range lines {
				if n2, ok := l.IntArg(key); ok {
					return n2, fmt.Sprintf("%s:%d", l.File, l.Line), true
				}
			}
			return n, fmt.Sprintf("%s:%d", s.File, s.Line), true
		}
	}
	for _, l := range lines {
		if n, ok := l.IntArg(key); ok {
			return n, fmt.Sprintf("%s:%d", l.File, l.Line), true
		}
	}
	return 0, "", false
}

// plural picks the suffix or verb form for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
