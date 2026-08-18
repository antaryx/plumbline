package fact

import "strings"

// SSHDConfigID names the parsed sshd configuration fact.
const SSHDConfigID ID = "sshd.config"

// Directive is one keyword/value pair from an sshd configuration file, with
// enough provenance to cite as evidence.
type Directive struct {
	Keyword string `json:"keyword"` // canonical case as written
	Value   string `json:"value"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	// InMatch is true when the directive appeared inside a Match block, and
	// therefore does not contribute to the global effective configuration.
	// Getting this wrong is the classic sshd-auditing bug: a tool reports
	// PermitRootLogin no because it saw it inside "Match Address 10.0.0.0/8".
	InMatch bool `json:"in_match"`
	// MatchCriteria is the raw Match line this directive falls under.
	MatchCriteria string `json:"match_criteria,omitempty"`
}

// SSHDConfig is the parsed, include-resolved sshd configuration.
type SSHDConfig struct {
	// Installed reports whether an sshd configuration was found at all. When
	// false, sshd checks are NOT_APPLICABLE rather than FAIL.
	Installed bool `json:"installed"`
	// Files lists every configuration file read, in read order, with the
	// primary file first.
	Files []string `json:"files"`
	// Directives are in effective order: first occurrence of a keyword wins,
	// which is sshd_config's documented precedence.
	Directives []Directive `json:"directives"`
	// UnresolvedIncludes records Include patterns that matched nothing or
	// could not be read. A check whose keyword might live in an unresolved
	// include must resolve to UNKNOWN, not PASS.
	UnresolvedIncludes []string `json:"unresolved_includes,omitempty"`
}

func (SSHDConfig) FactID() ID       { return SSHDConfigID }
func (SSHDConfig) FactVersion() int { return 1 }

// Effective returns the directive that governs the global configuration for
// keyword, following sshd_config precedence: the first obtained value wins,
// and Match-scoped directives are excluded.
//
// Keyword comparison is case-insensitive, as sshd itself is.
func (c SSHDConfig) Effective(keyword string) (Directive, bool) {
	want := strings.ToLower(keyword)
	for _, d := range c.Directives {
		if d.InMatch {
			continue
		}
		if strings.ToLower(d.Keyword) == want {
			return d, true
		}
	}
	return Directive{}, false
}

// AllOccurrences returns every directive for keyword, including Match-scoped
// ones, in file order. Used by findings that need to explain why a value the
// operator can see in the file is not the value in force.
func (c SSHDConfig) AllOccurrences(keyword string) []Directive {
	want := strings.ToLower(keyword)
	var out []Directive
	for _, d := range c.Directives {
		if strings.ToLower(d.Keyword) == want {
			out = append(out, d)
		}
	}
	return out
}
