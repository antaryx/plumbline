// Package sshd collects the effective sshd server configuration.
//
// This is deliberately the first collector built. It is the hardest of the
// easy ones — Include directives, Match blocks, first-value-wins precedence
// and distro divergence all show up here — so building it first surfaces the
// difficulty at the start of the project rather than in month four.
//
// Semantics implemented, per sshd_config(5):
//
//   - the first obtained value for a keyword wins; later ones are ignored
//   - Include expands in place, at the point the directive appears
//   - directives after a Match line are conditional and do not contribute to
//     the global configuration until the next Match
//   - keywords are case-insensitive; values are not
//
// Not yet implemented (v0.1): evaluating Match predicates against a concrete
// user/address, and `sshd -T` cross-checking. Both are v0.2 work packages.
package sshd

import (
	"errors"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "sshd"

// DefaultConfigPath is where sshd looks unless built otherwise.
const DefaultConfigPath = "/etc/ssh/sshd_config"

// maxIncludeDepth bounds Include recursion. sshd itself limits nesting; we
// bound it so that a cyclic include cannot spin a root process.
const maxIncludeDepth = 8

// Collect reads the sshd configuration tree and returns the parsed fact.
//
// The returned error is non-nil only for conditions that should be recorded as
// a fact error. A missing sshd_config is not an error: it is the legitimate
// observation "sshd is not configured here", which makes every SSHD check
// NOT_APPLICABLE.
func Collect(s system.System) (fact.SSHDConfig, *fact.Error) {
	cfg := fact.SSHDConfig{}

	res, err := s.ReadFile(DefaultConfigPath, 0)
	switch {
	case errors.Is(err, system.ErrNotExist):
		cfg.Installed = false
		return cfg, nil
	case errors.Is(err, system.ErrPermission):
		return cfg, &fact.Error{
			Fact: fact.SSHDConfigID, Kind: fact.ErrPermission,
			Msg: "cannot read sshd configuration", Path: DefaultConfigPath,
		}
	case errors.Is(err, system.ErrNotRegular):
		return cfg, &fact.Error{
			Fact: fact.SSHDConfigID, Kind: fact.ErrParse,
			Msg: "sshd configuration path is not a regular file", Path: DefaultConfigPath,
		}
	case err != nil:
		return cfg, &fact.Error{
			Fact: fact.SSHDConfigID, Kind: fact.ErrInternal,
			Msg: err.Error(), Path: DefaultConfigPath,
		}
	}

	if res.Truncated {
		return cfg, &fact.Error{
			Fact: fact.SSHDConfigID, Kind: fact.ErrTruncated,
			Msg: "sshd configuration exceeded the read cap", Path: DefaultConfigPath,
		}
	}

	cfg.Installed = true
	p := &parser{sys: s, cfg: &cfg, seen: map[string]bool{}}
	p.parseFile(DefaultConfigPath, res.Data, 0)
	return cfg, nil
}

type parser struct {
	sys  system.System
	cfg  *fact.SSHDConfig
	seen map[string]bool // include-cycle guard
	// match tracks the Match block currently in scope, "" at global scope.
	match string
}

func (p *parser) parseFile(path string, data []byte, depth int) {
	p.cfg.Files = append(p.cfg.Files, path)
	p.seen[path] = true

	// Save and restore Match scope around an include: sshd applies Match
	// scope lexically, and an included file's trailing Match block does not
	// leak back into the parent. Getting this wrong silently mis-scopes every
	// directive after the include.
	outerMatch := p.match
	defer func() { p.match = outerMatch }()

	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		keyword, value := splitDirective(line)
		if keyword == "" {
			continue
		}

		switch strings.ToLower(keyword) {
		case "match":
			// "Match all" returns to unconditional scope.
			if strings.EqualFold(strings.TrimSpace(value), "all") {
				p.match = ""
			} else {
				p.match = value
			}
			continue

		case "include":
			p.expandInclude(value, depth)
			continue
		}

		p.cfg.Directives = append(p.cfg.Directives, fact.Directive{
			Keyword:       keyword,
			Value:         value,
			File:          path,
			Line:          i + 1,
			InMatch:       p.match != "",
			MatchCriteria: p.match,
		})
	}
}

func (p *parser) expandInclude(patterns string, depth int) {
	if depth >= maxIncludeDepth {
		p.cfg.UnresolvedIncludes = append(p.cfg.UnresolvedIncludes,
			patterns+" (include depth limit reached)")
		return
	}

	for _, pattern := range strings.Fields(patterns) {
		// sshd resolves a relative Include against /etc/ssh.
		if !strings.HasPrefix(pattern, "/") {
			pattern = "/etc/ssh/" + pattern
		}

		matches, err := p.sys.Glob(pattern)
		if err != nil || len(matches) == 0 {
			// An include matching nothing is legal in sshd and common in
			// stock configs, but a check whose keyword could have lived there
			// must not claim certainty. Recording it lets checks decide.
			p.cfg.UnresolvedIncludes = append(p.cfg.UnresolvedIncludes, pattern)
			continue
		}
		sort.Strings(matches) // sshd reads glob matches in lexical order

		for _, m := range matches {
			if p.seen[m] {
				continue // cycle
			}
			res, err := p.sys.ReadFile(m, 0)
			if err != nil || res.Truncated {
				p.cfg.UnresolvedIncludes = append(p.cfg.UnresolvedIncludes, m)
				continue
			}
			p.parseFile(m, res.Data, depth+1)
		}
	}
}

// splitDirective splits an sshd_config line into keyword and value. sshd
// accepts both "Keyword value" and "Keyword=value".
func splitDirective(line string) (string, string) {
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		keyword := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		// Strip a trailing comment only when preceded by whitespace; a '#'
		// inside a value (a banner path, say) is not a comment.
		if j := strings.Index(value, " #"); j >= 0 {
			value = strings.TrimSpace(value[:j])
		}
		return keyword, value
	}
	return strings.TrimSpace(line), ""
}
