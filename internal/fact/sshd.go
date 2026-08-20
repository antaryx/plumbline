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

// ConfigLine locates one line of a configuration file, with the text as read.
// It is what lets a finding cite the line an operator has to go and fix.
type ConfigLine struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
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

	// SyntaxErrors records non-blank, non-comment lines that are not a
	// keyword followed by an argument.
	//
	// **This is the field that decides whether the rest of the fact means
	// anything.** sshd_config(5) defines every keyword as taking at least one
	// argument, so a bare keyword on a line is a fatal error: `sshd -t` fails,
	// sshd refuses to load the file, and the daemon is either still running
	// the last configuration that parsed or is not running at all. Either way
	// the file on disk is *not* the configuration in force, and reporting
	// sshd's compiled-in default for a keyword the file does not set —
	// correct for a valid file — becomes a confident wrong answer.
	//
	// Only the bare-keyword form is recorded, deliberately. An *unrecognised*
	// keyword is also fatal to sshd, but the valid keyword set differs by
	// OpenSSH release, and calling `SecurityKeyProvider` a syntax error would
	// report a fault on a host that is merely more current than this build.
	// The bare-keyword rule needs no such list and cannot drift.
	SyntaxErrors []ConfigLine `json:"syntax_errors,omitempty"`
	// Digests maps each file in Files to the sha256 of the bytes that were
	// read from it. A check is a pure function and cannot hash anything
	// itself, so this is the only way a finding can cite evidence an auditor
	// can verify against the bundle's evidence store (ADR-0009).
	//
	// Absent in bundles written before the field existed. That is deliberate:
	// the field is optional, so FactVersion is not bumped, and a check reading
	// an older bundle emits evidence without a digest exactly as it did then.
	Digests map[string]string `json:"digests,omitempty"`
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
