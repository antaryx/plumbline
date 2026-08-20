package sshd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// parseInt reads a plain integer directive value.
func parseInt(v string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseTimeSeconds reads sshd_config's TIME FORMAT: a bare number of seconds,
// or a sequence of count/unit pairs such as "2m", "1h30m", "45s".
//
// It is here rather than in the collector because it is a property of the
// keyword rather than of the file, and a check that read "2m" as the integer 2
// would report a two-minute grace period as two seconds — a PASS for exactly
// the configuration the check exists to find.
func parseTimeSeconds(v string) (int, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, false
	}
	if n, ok := parseInt(s); ok {
		return n, n >= 0
	}

	units := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	total, digits := 0, ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits += string(c)
			continue
		}
		mul, ok := units[c|0x20] // sshd accepts either case
		if !ok || digits == "" {
			return 0, false
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return 0, false
		}
		total += n * mul
		digits = ""
	}
	// A trailing run of digits with no unit is not valid in a compound value.
	if digits != "" {
		return 0, false
	}
	return total, true
}

// intSpec describes a keyword whose value is a bounded number.
//
// It carries the same plumbing contract as boolSpec: the sequence is shared,
// every sentence and every threshold belongs to the check that declares it.
type intSpec struct {
	Keyword string
	// Default is OpenSSH's built-in value when the keyword is absent.
	Default int
	// Parse reads the value. Defaults to a plain integer.
	Parse func(string) (int, bool)
	// Acceptable reports whether an observed value satisfies the check.
	Acceptable func(int) bool
	// Render turns a value into the phrase used in prose, e.g. "6 attempts".
	Render func(int) string
	// Base is the check's BaseSeverity; a Match-scoped loosening is reported
	// one class below it.
	Base finding.Severity
	// FailSeverity overrides Base for a global misconfiguration.
	FailSeverity finding.Severity
	// Consequence completes "…, so <Consequence>".
	Consequence string
	// Assurance completes the PASS detail after the semicolon.
	Assurance string
	// Syntax describes what sshd accepts, for the unparseable-value detail.
	Syntax string
}

func (s intSpec) parse(v string) (int, bool) {
	if s.Parse != nil {
		return s.Parse(v)
	}
	return parseInt(v)
}

func (s intSpec) render(n int) string {
	if s.Render != nil {
		return s.Render(n)
	}
	return strconv.Itoa(n)
}

// insecure is the Match-block predicate: a scoped value that would fail.
//
// A value this parser cannot read is NOT insecure. It is unreadable, and
// treating the two alike would report a typo inside a Match block as a
// deliberate weakening of a setting that is otherwise correct.
func (s intSpec) insecure(v string) bool {
	n, ok := s.parse(v)
	return ok && !s.Acceptable(n)
}

func (s intSpec) eval(fs *fact.Set) catalog.Outcome {
	failSeverity := s.FailSeverity
	if failSeverity == "" {
		failSeverity = s.Base
	}

	return evaluate(fs, s.Keyword,
		func(cfg fact.SSHDConfig) catalog.Outcome {
			desc := fmt.Sprintf("not configured, so sshd applies its built-in default of %s",
				s.render(s.Default))
			ev := primaryEvidence(cfg, fmt.Sprintf(
				"%s not present in any parsed file; built-in default %s applies",
				s.Keyword, s.render(s.Default)))

			if !s.Acceptable(s.Default) {
				return catalog.Outcome{
					Result:   finding.Fail,
					Severity: failSeverity,
					Subject:  s.Keyword,
					Detail:   fmt.Sprintf("%s is %s, so %s", s.Keyword, desc, s.Consequence),
					Evidence: []finding.Evidence{ev},
				}
			}
			if loosened := loosenedInMatch(cfg, s.Keyword, s.insecure); len(loosened) > 0 {
				return conditionalFail(cfg, s.Keyword, desc, ev, loosened, s.Base, s.Consequence)
			}
			return catalog.Outcome{
				Result:   finding.Pass,
				Detail:   fmt.Sprintf("%s is %s, which satisfies this check; %s", s.Keyword, desc, s.Assurance),
				Evidence: []finding.Evidence{ev},
			}
		},

		func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome {
			ev := directiveEvidence(cfg, d)

			n, ok := s.parse(d.Value)
			if !ok {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonParse,
					Subject:       s.Keyword,
					Detail: fmt.Sprintf(
						"%s has unreadable value %q at %s:%d; sshd accepts %s here and would reject this configuration, so the running server may be using a different file.",
						s.Keyword, d.Value, d.File, d.Line, s.Syntax),
					Evidence: []finding.Evidence{ev},
				}
			}

			if !s.Acceptable(n) {
				return catalog.Outcome{
					Result:   finding.Fail,
					Severity: failSeverity,
					Subject:  s.Keyword,
					Detail: fmt.Sprintf("%s is set to %s at %s:%d, so %s",
						s.Keyword, s.render(n), d.File, d.Line, s.Consequence),
					Evidence: append([]finding.Evidence{ev}, matchScopedEvidence(cfg, s.Keyword)...),
				}
			}

			if loosened := loosenedInMatch(cfg, s.Keyword, s.insecure); len(loosened) > 0 {
				return conditionalFail(cfg, s.Keyword,
					fmt.Sprintf("set to %s globally at %s:%d", s.render(n), d.File, d.Line),
					ev, loosened, s.Base, s.Consequence)
			}

			return catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf("%s is set to %s at %s:%d; %s",
					s.Keyword, s.render(n), d.File, d.Line, s.Assurance),
				Evidence: append([]finding.Evidence{ev}, matchScopedEvidence(cfg, s.Keyword)...),
			}
		})
}
