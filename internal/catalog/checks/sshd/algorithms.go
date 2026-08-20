package sshd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// The algorithm-list checks and why they behave differently from the rest of
// the module.
//
// Every other check here encodes OpenSSH's built-in default and reports it
// when the keyword is absent. These three refuse to, and the refusal is the
// interesting part of the design.
//
// The effective Ciphers, MACs and KexAlgorithms lists are compiled into the
// sshd binary. They are long, they differ between OpenSSH releases — CBC modes
// left the default Ciphers list in 7.6, and the SHA-1 key exchanges left the
// default KexAlgorithms list in 8.2 — and they differ between distributions,
// because Red Hat's crypto-policies subsystem rewrites them at build and at
// runtime. Plumbline does not read the sshd binary's version: that needs
// `sshd -T`, which is an Exec through the seam and is deferred (BUILD-RUNBOOK
// WP-18 hazards).
//
// So when the keyword is absent, the honest answer is that we do not know what
// is enabled. That is UNKNOWN, not PASS. Reporting PASS would be asserting the
// contents of a list we never saw, on a version we never read — which is
// precisely the false assurance CLAUDE.md rule 3 exists to forbid, and it would
// be wrong on any host still running a pre-7.6 build.
//
// The same logic applies to the relative forms. sshd_config lets a value begin
// with '+' (append to the default), '-' (remove from the default) or '^' (place
// at the head of the default). In every one of those the effective list is
// "the built-in default, modified", so it inherits the same unknowability —
// with one asymmetry that matters: if a '+' or '^' form *adds* a weak
// algorithm, that algorithm is enabled regardless of what the default holds.
// A positive result survives incomplete knowledge; a negative one does not.
// It is the same asymmetry ADR-0014 records for the filesystem walk.

// algMode is the prefix character on a list value, if any.
type algMode byte

const (
	algAbsolute algMode = 0
	algAdd      algMode = '+'
	algRemove   algMode = '-'
	algHead     algMode = '^'
)

// algList is a parsed algorithm list directive.
type algList struct {
	Mode  algMode
	Items []string
}

// parseAlgList reads a comma-separated algorithm list, honouring the +, - and
// ^ prefixes sshd_config allows on the whole value.
func parseAlgList(v string) algList {
	s := strings.TrimSpace(v)
	out := algList{Mode: algAbsolute}
	if s == "" {
		return out
	}
	switch s[0] {
	case '+', '-', '^':
		out.Mode = algMode(s[0])
		s = s[1:]
	}
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out.Items = append(out.Items, item)
		}
	}
	return out
}

// weakness is one algorithm and why it is unacceptable.
type weakness struct {
	Name   string
	Reason string
}

// weakCiphers classifies a cipher name.
//
// The order of the tests is deliberate: 3des-cbc satisfies both the 3DES rule
// and the CBC rule, and the block-size problem is the one that decides how
// urgently it has to go.
func weakCipher(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "none":
		return "no encryption at all; the session is plaintext", true
	case strings.HasPrefix(n, "3des"):
		return "3DES has a 64-bit block, which makes it vulnerable to the Sweet32 birthday attack (CVE-2016-2183) on long-lived connections", true
	case strings.HasPrefix(n, "arcfour"):
		return "RC4 has a biased keystream and is prohibited for TLS by RFC 7465; it was removed from OpenSSH's defaults in 6.7", true
	case strings.HasPrefix(n, "blowfish"), strings.HasPrefix(n, "cast128"):
		return "a 64-bit block cipher, vulnerable to the same birthday bound as 3DES", true
	case strings.HasPrefix(n, "des-"), n == "des":
		return "single DES has a 56-bit key and is brute-forceable", true
	case strings.HasSuffix(n, "-cbc"), strings.Contains(n, "-cbc@"):
		return "CBC mode in SSH is vulnerable to the plaintext-recovery attack of CVE-2008-5161; OpenSSH removed CBC ciphers from its defaults in 7.6", true
	}
	return "", false
}

// weakMAC classifies a MAC name.
func weakMAC(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "none":
		return "no integrity protection at all; the session can be modified in transit", true
	case strings.Contains(n, "md5"):
		return "MD5 is collision-broken and has been unsuitable for authentication for two decades", true
	case strings.Contains(n, "sha1"):
		return "SHA-1 is collision-broken (SHAttered, 2017) and RFC 9142 deprecates it for SSH", true
	case strings.Contains(n, "umac-64"):
		return "a 64-bit authentication tag is short enough to forge with feasible work", true
	case strings.Contains(n, "-96"):
		return "the tag is truncated to 96 bits, which weakens forgery resistance for no useful saving", true
	}
	return "", false
}

// weakKex classifies a key-exchange name.
func weakKex(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "none":
		return "no key exchange; there is no shared secret to protect the session", true
	case strings.Contains(n, "group1-"), strings.Contains(n, "group1sha1"):
		return "the 1024-bit MODP group is within reach of a precomputation attack of the kind Logjam described, and a well-resourced adversary is assumed to have done it", true
	case strings.Contains(n, "rsa1024"):
		return "a 1024-bit RSA key exchange is below every current minimum", true
	case strings.Contains(n, "sha1"):
		return "SHA-1 is collision-broken and RFC 9142 deprecates it for SSH key exchange; OpenSSH removed these from its defaults in 8.2", true
	}
	return "", false
}

// algSpec drives the three algorithm-list checks.
type algSpec struct {
	Keyword string
	// What the list configures, for prose: "cipher", "MAC", "key exchange".
	Noun string
	// Weak classifies one algorithm name.
	Weak func(string) (string, bool)
	// Base is the check's BaseSeverity.
	Base finding.Severity
	// Consequence completes "…, so <Consequence>".
	Consequence string
	// Assurance completes the PASS detail.
	Assurance string
}

func (s algSpec) eval(fs *fact.Set) catalog.Outcome {
	// Ciphers, MACs and KexAlgorithms are not among the keywords sshd_config
	// permits inside a Match block, so there is no Match-loosening path here
	// and none is attempted. A directive found inside one would be rejected by
	// sshd at startup, and Effective() already excludes it.
	return evaluate(fs, s.Keyword,
		func(cfg fact.SSHDConfig) catalog.Outcome {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       s.Keyword,
				Detail: fmt.Sprintf(
					"%s is not configured, so the effective %s list is the one compiled into this host's sshd binary. That list differs between OpenSSH releases and is rewritten by some distributions' crypto policy, and Plumbline does not read the binary's version — so which algorithms are enabled cannot be determined from the configuration alone. Setting %s explicitly is both the remedy and the way to make this check answerable.",
					s.Keyword, s.Noun, s.Keyword),
				Evidence: []finding.Evidence{primaryEvidence(cfg, fmt.Sprintf(
					"%s not present in any parsed file; the built-in default list applies and is not readable from configuration",
					s.Keyword))},
			}
		},

		func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome {
			ev := []finding.Evidence{directiveEvidence(cfg, d)}
			list := parseAlgList(d.Value)

			if len(list.Items) == 0 {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonParse,
					Subject:       s.Keyword,
					Detail: fmt.Sprintf(
						"%s at %s:%d has a value this parser could not read as an algorithm list (%q); sshd would reject an empty list, so the running server may be using a different file.",
						s.Keyword, d.File, d.Line, d.Value),
					Evidence: ev,
				}
			}

			var found []weakness
			for _, item := range list.Items {
				if reason, weak := s.Weak(item); weak {
					found = append(found, weakness{Name: item, Reason: reason})
				}
			}
			sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })

			// One evidence entry per weak algorithm, so an auditor reading the
			// findings document gets the reason attached to the name rather
			// than having to parse it back out of the detail string.
			//
			// The names are deliberately not also collected into a slice here:
			// describeWeaknesses(found) renders them with their reasons in
			// every detail below, and Subject stays the keyword. Subject feeds
			// the fingerprint, and a fingerprint built from the set of weak
			// algorithms would change the moment an operator removed one of
			// them — silently detaching any suppression written against it
			// (DATA-MODEL.md 5.4).
			for _, w := range found {
				ev = append(ev, finding.NewEvidence(d.File, d.Line,
					fmt.Sprintf("%s: %s", w.Name, w.Reason), cfg.Digests[d.File]))
			}

			switch list.Mode {
			case algAdd, algHead:
				verb := "appends to"
				if list.Mode == algHead {
					verb = "places at the head of"
				}
				if len(found) > 0 {
					// Positive result: whatever the built-in default holds,
					// these were added to it, so they are enabled.
					return catalog.Outcome{
						Result:  finding.Fail,
						Subject: s.Keyword,
						Detail: fmt.Sprintf(
							"%s at %s:%d %s the built-in list, and %d of the %s(s) it adds are unacceptable: %s. This verdict does not depend on what the built-in default contains — these are enabled because this line enables them. %s",
							s.Keyword, d.File, d.Line, verb, len(found), s.Noun,
							describeWeaknesses(found), sentence(s.Consequence)),
						Evidence: ev,
					}
				}
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Subject:       s.Keyword,
					Detail: fmt.Sprintf(
						"%s at %s:%d %s the built-in list rather than replacing it. Nothing it adds is unacceptable, but the rest of the effective list is the default compiled into this host's sshd binary, which Plumbline cannot read — so the absence of a weak %s cannot be confirmed. Replace the relative form with an explicit list to make this answerable.",
						s.Keyword, d.File, d.Line, verb, s.Noun),
					Evidence: ev,
				}

			case algRemove:
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Subject:       s.Keyword,
					Detail: fmt.Sprintf(
						"%s at %s:%d removes %d entr(ies) from the built-in list rather than replacing it. Removal cannot introduce a weak %s, but what remains is the default compiled into this host's sshd binary, which Plumbline cannot read — so this is not evidence that no weak %s is enabled. Replace the relative form with an explicit list to make this answerable.",
						s.Keyword, d.File, d.Line, len(list.Items), s.Noun, s.Noun),
					Evidence: ev,
				}
			}

			// Absolute list: fully enumerated, so both verdicts are available.
			if len(found) > 0 {
				return catalog.Outcome{
					Result:  finding.Fail,
					Subject: s.Keyword,
					Detail: fmt.Sprintf(
						"%s at %s:%d enables %d unacceptable %s(s) of the %d listed: %s. %s",
						s.Keyword, d.File, d.Line, len(found), s.Noun, len(list.Items),
						describeWeaknesses(found), sentence(s.Consequence)),
					Evidence: ev,
				}
			}
			return catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"%s at %s:%d lists %d %s(s) explicitly (%s) and none of them is deprecated or broken; %s",
					s.Keyword, d.File, d.Line, len(list.Items), s.Noun,
					strings.Join(list.Items, ", "), s.Assurance),
				Evidence: ev,
			}
		})
}

// describeWeaknesses renders "name (reason); name (reason)".
func describeWeaknesses(in []weakness) string {
	parts := make([]string, 0, len(in))
	for _, w := range in {
		parts = append(parts, fmt.Sprintf("%s — %s", w.Name, w.Reason))
	}
	return strings.Join(parts, "; ")
}

// sentence renders a consequence clause — written to follow "so " everywhere
// else in this module — as a standalone sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
