// Package profile scopes an evaluation to a declared baseline.
//
// A server, a workstation and a hardened container are not the same host and
// should not share a posture denominator. A profile names the checks that
// apply, and everything outside it is reported as SKIPPED rather than silently
// dropped — the report still says what was not asked.
//
// Four rules, each because the obvious implementation gets it wrong.
//
// **A profile selects from the catalog; it never adds to it.** There is no way
// to define a check in a profile, and there never will be. A finding that
// exists only under one profile is a finding nobody else can reproduce, which
// is the opposite of what a baseline is for.
//
// **An excluded check is SKIPPED, never omitted and never NOT_APPLICABLE.**
// Omitting it would make a narrow profile look like a clean host. Calling it
// NOT_APPLICABLE would be a lie of a different kind: that state means the
// subject is not present on this machine, and "we chose not to ask" is a
// policy decision, not a fact about the host.
//
// **An excluded check leaves the posture denominator.** This is what the
// feature is for. A profile declares what applies, so the applicable set *is*
// the profile, and coverage measures against it.
//
// **A severity override changes the effective severity and never the base.**
// Both are reported, exactly as a context adjustment is, so an operator can
// always see that a number was moved and by how much.
//
// The built-in profiles are embedded JSON parsed by the same Parse this package
// gives to a user's file. A built-in that could not be parsed by the public
// parser would be a second format nobody documented.
package profile

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// Schema is the value the schema key must carry.
const Schema = "profile/v1"

// DefaultID is the profile in force when nobody asks for one: the whole
// catalog. It is a real profile rather than a nil check, so that "no --profile"
// and "--profile default" cannot diverge.
const DefaultID = "default"

//go:embed builtin/*.json
var builtinFS embed.FS

// Profile is a declared baseline.
type Profile struct {
	Schema      string `json:"schema"`
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// Included lists check-ID patterns. `*` matches any run of characters, so
	// "SSHD-*" is a module and "*" is the catalog. Required: a profile that
	// includes nothing is a typo, not a policy.
	Included []string `json:"included_checks"`

	// Excluded is applied after Included and wins. Patterns, same syntax.
	Excluded []string `json:"excluded_checks,omitempty"`

	// SeverityOverrides re-weights a check for this baseline. The key is a
	// check ID — never a pattern, because a severity applied to a module by
	// accident is a posture score nobody can explain.
	SeverityOverrides map[string]finding.Severity `json:"severity_overrides,omitempty"`

	// builtin records that this profile came from the binary rather than a
	// file, which is what `plumbline profiles` lists.
	builtin bool
}

// Builtin reports whether the profile is embedded in this binary.
func (p *Profile) Builtin() bool { return p != nil && p.builtin }

// Includes reports whether a check is in scope.
//
// Excluded is evaluated after Included and wins, so "everything in SSHD except
// the banner check" is two lines rather than an enumeration.
func (p *Profile) Includes(checkID string) bool {
	if p == nil {
		return true // no profile is the whole catalog
	}
	if !matchAny(p.Included, checkID) {
		return false
	}
	return !matchAny(p.Excluded, checkID)
}

// SeverityFor returns the severity this profile assigns a check, and whether it
// overrode the catalog's.
func (p *Profile) SeverityFor(checkID string) (finding.Severity, bool) {
	if p == nil || len(p.SeverityOverrides) == 0 {
		return "", false
	}
	s, ok := p.SeverityOverrides[checkID]
	return s, ok
}

// Name is the ID, or "default" for a nil profile.
func (p *Profile) Name() string {
	if p == nil {
		return DefaultID
	}
	return p.ID
}

// Count returns how many of the given check IDs this profile includes.
func (p *Profile) Count(ids []string) int {
	n := 0
	for _, id := range ids {
		if p.Includes(id) {
			n++
		}
	}
	return n
}

func matchAny(patterns []string, checkID string) bool {
	for _, pattern := range patterns {
		// path.Match is the stdlib glob. Check IDs contain no separator, so
		// its one quirk — `*` not crossing `/` — cannot bite here, and using
		// it avoids hand-rolling a matcher with its own bugs.
		if ok, err := path.Match(pattern, checkID); err == nil && ok {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

// Parse reads a profile file.
//
// Every error names what is wrong and where. A profile is hand-edited — that is
// the point of it — so the parser's job is to say what to fix.
func Parse(data []byte) (*Profile, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	// An unknown key is an error, not an ignored typo: "included_check"
	// silently parsing as an absent include list would scope a scan to nothing
	// and report a clean host.
	dec.DisallowUnknownFields()

	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("profile is not valid JSON: %w", err)
	}
	if p.Schema != Schema {
		return nil, fmt.Errorf("profile declares schema %q; this build understands %q", p.Schema, Schema)
	}
	if strings.TrimSpace(p.ID) == "" {
		return nil, fmt.Errorf("profile has no id")
	}
	if strings.TrimSpace(p.Title) == "" {
		return nil, fmt.Errorf("profile %q has no title; a baseline nobody can describe is one nobody should trust", p.ID)
	}
	if len(p.Included) == 0 {
		return nil, fmt.Errorf("profile %q includes no checks; use [\"*\"] for the whole catalog", p.ID)
	}
	for _, list := range [][]string{p.Included, p.Excluded} {
		for _, pattern := range list {
			if _, err := path.Match(pattern, "X-0000"); err != nil {
				return nil, fmt.Errorf("profile %q: %q is not a valid pattern: %w", p.ID, pattern, err)
			}
		}
	}
	for id, sev := range p.SeverityOverrides {
		if !validSeverity(sev) {
			return nil, fmt.Errorf("profile %q: severity_overrides[%s] is %q; want one of %s",
				p.ID, id, sev, strings.Join(severityNames(), ", "))
		}
		if strings.ContainsAny(id, "*?[") {
			return nil, fmt.Errorf("profile %q: severity_overrides[%s] looks like a pattern; "+
				"overrides name one check each, because a severity applied to a module by accident "+
				"is a posture score nobody can explain", p.ID, id)
		}
	}
	return &p, nil
}

func validSeverity(s finding.Severity) bool {
	switch s {
	case finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info:
		return true
	}
	return false
}

func severityNames() []string {
	return []string{
		string(finding.Critical), string(finding.High), string(finding.Medium),
		string(finding.Low), string(finding.Info),
	}
}

// ---------------------------------------------------------------------------
// the built-ins
// ---------------------------------------------------------------------------

// Builtin returns an embedded profile by ID.
func Builtin(id string) (*Profile, bool) {
	for _, p := range Builtins() {
		if p.ID == id {
			return p, true
		}
	}
	return nil, false
}

// Builtins returns every embedded profile, by ID.
//
// They are parsed on every call rather than cached in a package variable: the
// data is a few kilobytes, the parse is microseconds, and a mutable package
// global holding shared *Profile pointers is a data race waiting for the day
// something evaluates two hosts at once.
func Builtins() []*Profile {
	entries, err := fs.ReadDir(builtinFS, "builtin")
	if err != nil {
		// Unreachable: the directory is embedded at build time. A panic here
		// would be a build defect, and returning nothing silently would make
		// every profile lookup fail with a confusing message instead.
		return nil
	}
	var out []*Profile
	for _, e := range entries {
		data, err := builtinFS.ReadFile(path.Join("builtin", e.Name()))
		if err != nil {
			continue
		}
		p, err := Parse(data)
		if err != nil {
			// Also unreachable, and gated by TestEveryBuiltinParses so it
			// cannot become reachable without a test failing first.
			continue
		}
		p.builtin = true
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// "default" first; it is the one an operator is already using.
		if (out[i].ID == DefaultID) != (out[j].ID == DefaultID) {
			return out[i].ID == DefaultID
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// BuiltinIDs is the list `plumbline profiles` prints and an error message
// suggests.
func BuiltinIDs() []string {
	var out []string
	for _, p := range Builtins() {
		out = append(out, p.ID)
	}
	return out
}
