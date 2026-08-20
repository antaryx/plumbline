package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// boolSpec describes a keyword whose only meaningful values are "yes" and
// "no", which is most of sshd_config.
//
// The prose lives in the spec rather than in a shared template because a
// finding that says "PasswordAuthentication is yes" and stops has told the
// reader nothing they could not see themselves. Consequence and Assurance are
// what make it a finding rather than a diff, so each check writes its own.
//
// This is plumbing, not policy: the verdict, the severity, the default and
// every sentence come from the check that declares the spec. What is shared is
// the sequence — not installed, unresolved include, absent, present,
// unparseable, Match-loosened — which is identical everywhere and silently
// wrong if any branch is forgotten.
type boolSpec struct {
	Keyword string
	// Secure is the value that satisfies this check: "yes" or "no".
	Secure string
	// Default is OpenSSH's built-in value when the keyword is absent.
	Default string
	// Base is the check's BaseSeverity. Needed here because a Match-scoped
	// loosening is reported one class below it.
	Base finding.Severity
	// FailSeverity overrides Base for a global misconfiguration. Empty means
	// "use Base".
	FailSeverity finding.Severity
	// Consequence completes "…, so <Consequence>" in a FAIL detail.
	Consequence string
	// Assurance completes the PASS detail after the semicolon.
	Assurance string
}

// opposite is the insecure token for this keyword.
func (s boolSpec) opposite() string {
	if strings.EqualFold(s.Secure, "yes") {
		return "no"
	}
	return "yes"
}

// insecure reports whether a value is the recognised insecure token.
//
// It is deliberately not "anything that is not Secure": an unrecognised value
// is a parse problem, not an insecure setting, and conflating the two would
// let a typo be reported as a deliberate weakening.
func (s boolSpec) insecure(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), s.opposite())
}

// eval builds the Eval function for a boolean keyword.
func (s boolSpec) eval(fs *fact.Set) catalog.Outcome {
	failSeverity := s.FailSeverity
	if failSeverity == "" {
		failSeverity = s.Base
	}

	return evaluate(fs, s.Keyword,
		// Absent: sshd applies its built-in default. Whether that is a PASS or
		// a FAIL depends entirely on the keyword, which is why Default is a
		// declared field and not an assumption.
		func(cfg fact.SSHDConfig) catalog.Outcome {
			desc := fmt.Sprintf("not configured, so sshd applies its built-in default of %q", s.Default)
			ev := primaryEvidence(cfg, fmt.Sprintf(
				"%s not present in any parsed file; built-in default %q applies", s.Keyword, s.Default))

			if !strings.EqualFold(s.Default, s.Secure) {
				return catalog.Outcome{
					Result:   finding.Fail,
					Severity: failSeverity,
					Subject:  s.Keyword,
					Detail: fmt.Sprintf("%s is %s, so %s",
						s.Keyword, desc, s.Consequence),
					Evidence: []finding.Evidence{ev},
				}
			}

			// The default is the secure value — but a Match block can still
			// reintroduce the insecure one, and an operator reading only the
			// global section would never see it.
			if loosened := loosenedInMatch(cfg, s.Keyword, s.insecure); len(loosened) > 0 {
				return conditionalFail(cfg, s.Keyword, desc, ev, loosened, s.Base, s.Consequence)
			}
			return catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf("%s is %s, which is the secure value; %s",
					s.Keyword, desc, s.Assurance),
				Evidence: []finding.Evidence{ev},
			}
		},

		func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome {
			ev := directiveEvidence(cfg, d)
			value := strings.TrimSpace(d.Value)

			switch {
			case strings.EqualFold(value, s.Secure):
				if loosened := loosenedInMatch(cfg, s.Keyword, s.insecure); len(loosened) > 0 {
					return conditionalFail(cfg, s.Keyword,
						fmt.Sprintf("set to %q globally at %s:%d", d.Value, d.File, d.Line),
						ev, loosened, s.Base, s.Consequence)
				}
				out := catalog.Outcome{
					Result: finding.Pass,
					Detail: fmt.Sprintf("%s is set to %q at %s:%d; %s",
						s.Keyword, d.Value, d.File, d.Line, s.Assurance),
					Evidence: []finding.Evidence{ev},
				}
				// Match-scoped occurrences that do NOT loosen are still worth
				// citing, so the reader can see the tool read the whole file.
				out.Evidence = append(out.Evidence, matchScopedEvidence(cfg, s.Keyword)...)
				return out

			case s.insecure(value):
				return catalog.Outcome{
					Result:   finding.Fail,
					Severity: failSeverity,
					Subject:  s.Keyword,
					Detail: fmt.Sprintf("%s is set to %q at %s:%d, so %s",
						s.Keyword, d.Value, d.File, d.Line, s.Consequence),
					Evidence: append([]finding.Evidence{ev}, matchScopedEvidence(cfg, s.Keyword)...),
				}

			default:
				// sshd refuses to start on an unrecognised value, so the
				// running daemon is not using this file. Saying PASS or FAIL
				// here would describe a configuration that is not in force.
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonParse,
					Subject:       s.Keyword,
					Detail: fmt.Sprintf(
						"%s has unrecognised value %q at %s:%d; sshd accepts only yes or no here and would reject this configuration, so the running server may be using a different file.",
						s.Keyword, d.Value, d.File, d.Line),
					Evidence: []finding.Evidence{ev},
				}
			}
		})
}
