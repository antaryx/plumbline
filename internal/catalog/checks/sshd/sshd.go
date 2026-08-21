package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// The OpenSSH baseline these checks encode.
//
// Every default below is sshd_config(5) as shipped by **OpenSSH 9.x**. The
// version matters and is stated in each check's spec, because "the keyword is
// absent" is only actionable if you know what the daemon does in its absence,
// and OpenSSH has changed several of these:
//
//   - PermitRootLogin became prohibit-password in 7.0 (2015)
//   - the default Ciphers list dropped CBC modes in 7.6 (2017)
//   - Protocol 1 was removed entirely in 7.4 (2016)
//
// Plumbline does not read the sshd binary's version — that needs `sshd -T`,
// which is an Exec through the seam and is deferred (see algorithms.go). So
// where a default has been stable for a decade the checks encode it and say so
// in the finding; where the effective value is a version-dependent *list*, the
// checks refuse to assume and return UNKNOWN. See algorithms.go.
const (
	defaultPasswordAuthentication  = "yes"
	defaultPermitEmptyPasswords    = "no"
	defaultX11Forwarding           = "no"
	defaultMaxAuthTries            = 6
	defaultClientAliveInterval     = 0
	defaultClientAliveCountMax     = 3
	defaultAllowTcpForwarding      = "yes"
	defaultLogLevel                = "INFO"
	defaultIgnoreRhosts            = "yes"
	defaultHostbasedAuthentication = "no"
	defaultPermitUserEnvironment   = "no"
	defaultLoginGraceTime          = 120
	defaultAllowAgentForwarding    = "yes"
	defaultStrictModes             = "yes"
	defaultUsePAM                  = "no"
)

// configFact reads the module's fact. The runner's required-fact gate
// guarantees it is present and typed before Eval is entered.
func configFact(fs *fact.Set) fact.SSHDConfig {
	c, _, _ := fact.Get[fact.SSHDConfig](fs, fact.SSHDConfigID)
	return c
}

// notApplicable is the verdict when no sshd configuration exists at all.
//
// NOT_APPLICABLE and not PASS: a host with no SSH server has not satisfied
// "root login over SSH is disabled", it has removed the subject of the
// sentence. Scoring treats the two very differently (docs/SCORING.md).
func notApplicable() catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: "No sshd configuration found; the SSH server is not configured on this host.",
	}
}

// unresolvedInclude is the canonical UNKNOWN of this module, and the reason
// docs/FIXTURES.md calls sshd-unresolved-include the project's reference
// UNKNOWN fixture.
//
// The keyword is absent from every file we could read, but an Include matched
// nothing — so the value may be sitting in a file this scan never saw. A
// lesser tool reports the documented default here. That would be a guess
// dressed as an observation, and CONTRIBUTING.md rule 3 exists to forbid exactly it.
func unresolvedInclude(cfg fact.SSHDConfig, keyword string) catalog.Outcome {
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonAmbiguousState,
		Detail: fmt.Sprintf(
			"%s is not set in any readable file, but %d Include directive(s) could not be resolved (%s); the effective value cannot be determined.",
			keyword, len(cfg.UnresolvedIncludes), strings.Join(cfg.UnresolvedIncludes, ", ")),
		Evidence: []finding.Evidence{primaryEvidence(cfg,
			"unresolved Include: "+strings.Join(cfg.UnresolvedIncludes, ", "))},
	}
}

// primaryEvidence cites the main configuration file with no particular line,
// for statements about what is *not* in it.
func primaryEvidence(cfg fact.SSHDConfig, excerpt string) finding.Evidence {
	var file string
	if len(cfg.Files) > 0 {
		file = cfg.Files[0]
	}
	return finding.NewEvidence(file, 0, excerpt, cfg.Digests[file])
}

// directiveEvidence cites one directive.
//
// NewEvidence is the constructor THREAT-MODEL.md T-03 names: it neutralises
// the untrusted strings a directive carries, and attaches the digest of the
// file the line came from so an auditor can re-read the source in the bundle
// rather than trusting this excerpt.
func directiveEvidence(cfg fact.SSHDConfig, d fact.Directive) finding.Evidence {
	return finding.NewEvidence(d.File, d.Line,
		fmt.Sprintf("%s %s", d.Keyword, d.Value), cfg.Digests[d.File])
}

// matchScopedEvidence returns evidence for every Match-scoped occurrence of
// keyword, labelled so a reader understands why a value they can plainly see
// in the file is not the value in force.
//
// Without this the report contradicts the operator's own reading of their
// configuration, and at that point they stop trusting the tool — which costs
// more than the finding was worth.
func matchScopedEvidence(cfg fact.SSHDConfig, keyword string) []finding.Evidence {
	var out []finding.Evidence
	for _, d := range cfg.AllOccurrences(keyword) {
		if !d.InMatch {
			continue
		}
		out = append(out, finding.NewEvidence(d.File, d.Line,
			fmt.Sprintf("%s %s  (inside 'Match %s'; conditional, does not set the global value)",
				d.Keyword, d.Value, d.MatchCriteria),
			cfg.Digests[d.File]))
	}
	return out
}

// evaluate is the plumbing every keyword check in this module shares:
// not-installed, unresolved-include, absent, present.
//
// It exists because that sequence is identical in eighteen checks and the
// failure mode of getting it wrong is silent — a check that forgot the
// unresolved-include branch would report the built-in default as though it had
// been observed, which is the one bug CONTRIBUTING.md rule 3 singles out as fatal.
func evaluate(
	fs *fact.Set,
	keyword string,
	onAbsent func(cfg fact.SSHDConfig) catalog.Outcome,
	onValue func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome,
) catalog.Outcome {
	cfg := configFact(fs)
	if !cfg.Installed {
		return notApplicable()
	}
	// The syntax gate comes before everything, including the branch where the
	// keyword *is* present, and that ordering is the whole point. sshd rejects
	// a file with a syntax error as a unit — it does not skip the bad line and
	// keep the good ones — so on such a host neither a value that is in the
	// file nor a value that is absent from it describes what sshd is running.
	if len(cfg.SyntaxErrors) > 0 {
		return syntaxError(cfg, keyword)
	}
	d, ok := cfg.Effective(keyword)
	if !ok {
		if len(cfg.UnresolvedIncludes) > 0 {
			return unresolvedInclude(cfg, keyword)
		}
		return onAbsent(cfg)
	}
	return onValue(cfg, d)
}

// syntaxError is the UNKNOWN for a configuration sshd would refuse to load.
//
// It is the unresolved-include argument applied one step earlier. There, the
// keyword might be set in a file we never saw; here, the file we did see is
// not the one in force, because sshd exits non-zero on it and keeps running
// whatever last parsed. A tool that reported the compiled-in default from
// these bytes would be describing a configuration that exists nowhere: not on
// disk, and not in the running daemon.
func syntaxError(cfg fact.SSHDConfig, keyword string) catalog.Outcome {
	first := cfg.SyntaxErrors[0]
	ev := make([]finding.Evidence, 0, len(cfg.SyntaxErrors))
	for _, l := range cfg.SyntaxErrors {
		ev = append(ev, finding.NewEvidence(l.File, l.Line,
			l.Text+"  ← keyword with no argument; sshd -t rejects this", ""))
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonParse,
		Subject:       keyword,
		Detail: fmt.Sprintf(
			"The effective value of %s cannot be determined: %s carries %d line(s) that sshd will not parse, the first at %s:%d (%q). sshd refuses a configuration file as a unit rather than skipping the bad line, so this file is not loaded — the daemon is running whatever configuration last parsed successfully, or is not running at all, and neither is visible from disk. Fix the syntax and re-scan; 'sshd -t' reports the same lines.",
			keyword, first.File, len(cfg.SyntaxErrors), first.File, first.Line, first.Text),
		Evidence: ev,
	}
}

// ---------------------------------------------------------------------------
// Match blocks that loosen a secure global setting
// ---------------------------------------------------------------------------

// loosenedInMatch returns the Match-scoped occurrences of keyword whose value
// is insecure by the check's own predicate.
//
// A Match block that *tightens* is not reported: the global value already
// governs everything the block does not match, and a stricter exception is not
// a finding. Only the loosening direction matters, and only when the global
// value is the secure one — otherwise the global FAIL already says everything
// there is to say.
func loosenedInMatch(cfg fact.SSHDConfig, keyword string, insecure func(string) bool) []fact.Directive {
	var out []fact.Directive
	for _, d := range cfg.AllOccurrences(keyword) {
		if d.InMatch && insecure(d.Value) {
			out = append(out, d)
		}
	}
	return out
}

// conditionalFail converts a would-be PASS into a FAIL one severity lower,
// because a Match block has reintroduced the insecure value for some subset of
// connections.
//
// Reporting PASS here would be false assurance: the insecure state is
// reachable. Reporting FAIL at the full severity would be false too, because
// the exposure is narrower than a global misconfiguration. One step down, with
// the Match criteria named in the detail, is the honest reading — and the
// criteria are quoted rather than judged, because "Match Address 127.0.0.1"
// and "Match Address 0.0.0.0/0" are the same syntax and utterly different
// risks, and only the operator knows which theirs is.
func conditionalFail(
	cfg fact.SSHDConfig,
	keyword string,
	globalDesc string,
	globalEv finding.Evidence,
	loosened []fact.Directive,
	base finding.Severity,
	consequence string,
) catalog.Outcome {
	scopes := make([]string, 0, len(loosened))
	ev := []finding.Evidence{globalEv}
	for _, d := range loosened {
		// The directive's own keyword, not the check's subject: SSHD-0007
		// reads two keywords, and "sets it to 0" would read as though the
		// block had changed ClientAliveInterval when it changed
		// ClientAliveCountMax.
		scopes = append(scopes, fmt.Sprintf("'Match %s' sets %s to %q at %s:%d",
			d.MatchCriteria, d.Keyword, d.Value, d.File, d.Line))
		ev = append(ev, finding.NewEvidence(d.File, d.Line,
			fmt.Sprintf("%s %s  (inside 'Match %s'; overrides the global value for matching connections)",
				d.Keyword, d.Value, d.MatchCriteria),
			cfg.Digests[d.File]))
	}

	return catalog.Outcome{
		Result:   finding.Fail,
		Severity: oneLower(base),
		Subject:  keyword,
		Detail: fmt.Sprintf(
			"%s is %s, but %d Match block(s) override it for a subset of connections: %s. %s The severity is one step below a global misconfiguration because the exposure is conditional — but it is reachable, so this is not a PASS.",
			keyword, globalDesc, len(loosened), strings.Join(scopes, "; "), consequence),
		Evidence: ev,
	}
}

// oneLower steps a severity down by one class. INFO is the floor.
func oneLower(s finding.Severity) finding.Severity {
	switch s {
	case finding.Critical:
		return finding.High
	case finding.High:
		return finding.Medium
	case finding.Medium:
		return finding.Low
	default:
		return finding.Info
	}
}
