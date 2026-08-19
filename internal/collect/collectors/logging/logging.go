// Package logging collects the rsyslog and journald configurations.
//
// Two facts, not one. A host may run rsyslog, journald, both or neither, the
// two have different files with different readabilities, and a single fact
// would let one absent daemon erase what is known about the other — the same
// reasoning as the three account-database facts in WP-17.
//
// **rsyslog has two configuration languages and this collector parses both.**
// The sysklogd-derived legacy format (`*.* @@host`), rsyslog's own `$Name
// value` directives, and RainerScript objects (`action(type="omfwd" ...)`) all
// appear in the same file on a stock Debian or RHEL host, frequently
// describing the same subsystem. A parser that understood only one of them
// would report a correctly-forwarding host as not forwarding, which is a false
// FAIL, or — worse — miss a permissive `$FileCreateMode` because it only read
// RainerScript. Which language a statement was written in is preserved into
// the fact, because a finding has to quote the operator's file back in the
// language it is actually written in.
package logging

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "logging"

// Well-known paths.
const (
	RsyslogPath      = "/etc/rsyslog.conf"
	RsyslogDropInDir = "/etc/rsyslog.d"
	JournaldPath     = "/etc/systemd/journald.conf"
	JournaldDropIns  = "/etc/systemd/journald.conf.d/*.conf"
	// JournalDir is what decides the meaning of Storage=auto, which is
	// journald's default: the journal is persistent when this directory
	// exists and volatile when it does not.
	JournalDir = "/var/log/journal"
)

// maxRead bounds one configuration file. A logging configuration is a few
// kilobytes; anything approaching this cap is not one, and must not be held in
// memory by a root process.
const maxRead = 4 << 20 // 4 MiB

// maxIncludeDepth bounds include recursion. rsyslog configurations include
// each other, and a self-including file is a loop that a depth limit
// terminates without needing to detect it.
const maxIncludeDepth = 8

// Collector implements collect.Collector for the logging configuration.
type Collector struct{}

// New returns the logging collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

func (Collector) Produces() []fact.ID { return []fact.ID{fact.RsyslogID, fact.JournaldID} }

// DependsOn is nil. Reading configuration files needs nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone. Both configurations are world-readable on every
// mainstream distribution; declaring CapRoot would make an unprivileged scan
// report the whole module as never collected when it could have answered every
// question.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: a bounded set of small text files, no walk, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds. Include expansion touches a directory of drop-ins;
// if that does not complete, the filesystem is not answering.
func (Collector) Timeout() time.Duration { return 10 * time.Second }

// Collect reads both configurations, recording each independently.
//
// Neither daemon's absence removes the other's observation, and there is no
// path here where one file's failure discards another's. The returned error
// stays nil for everything the collector could classify, which is everything:
// a read either succeeds, is refused, is absent, or fails for a reason worth
// recording verbatim.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	collectRsyslog(ctx, s, fs)

	// The deadline stopped us. Record what was gathered rather than returning
	// the context error: internal/collect.runner discards the partial facts of
	// a collector that errors while its context is done.
	//nolint:nilerr // error deliberately swallowed for graceful degradation; the rsyslog fact is already in the FactSet
	if err := ctx.Err(); err != nil {
		return nil
	}
	collectJournald(s, fs)
	return nil
}

// ---------------------------------------------------------------------------
// rsyslog
// ---------------------------------------------------------------------------

type rsyslogParser struct {
	sys  system.System
	cfg  fact.Rsyslog
	seen map[string]bool
}

func collectRsyslog(ctx context.Context, s system.System, fs *fact.Set) {
	p := &rsyslogParser{sys: s, seen: map[string]bool{}}
	p.cfg.Digests = map[string]string{}

	res, err := s.ReadFile(RsyslogPath, maxRead)
	switch {
	case err == nil:
		p.cfg.Installed = true
		p.cfg.Files = append(p.cfg.Files, RsyslogPath)
		p.cfg.Digests[RsyslogPath] = res.SHA256
		p.seen[RsyslogPath] = true
		p.parse(ctx, RsyslogPath, string(res.Data), 0)

	case errors.Is(err, system.ErrNotExist):
		// Not a failure. A host running only journald has no rsyslog.conf, and
		// the rsyslog checks are NOT_APPLICABLE rather than failing for the
		// absence of a daemon nobody installed.
		p.cfg.Installed = false

	case errors.Is(err, system.ErrPermission):
		fs.PutError(fact.Error{
			Fact: fact.RsyslogID, Kind: fact.ErrPermission,
			Msg: "permission denied; run as root to read this file", Path: RsyslogPath,
		})
		return

	default:
		fs.PutError(fact.Error{
			Fact: fact.RsyslogID, Kind: fact.ErrInternal, Msg: err.Error(), Path: RsyslogPath,
		})
		return
	}

	fs.Put(p.cfg)
}

// parse reads one rsyslog file, dispatching each statement to the syntax that
// produced it.
func (p *rsyslogParser) parse(ctx context.Context, file, data string, depth int) {
	lines := strings.Split(data, "\n")

	for i := 0; i < len(lines); i++ {
		if ctx.Err() != nil {
			return
		}
		raw := strings.TrimSuffix(lines[i], "\r")
		line := strings.TrimSpace(raw)
		lineNo := i + 1

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// RainerScript objects span lines. Accumulate until the parentheses
		// balance, because a real configuration writes an omfwd action across
		// four or five lines and a line-at-a-time parser sees none of it.
		if kind, ok := rainerScriptKind(line); ok {
			stmt, consumed := accumulate(lines, i)
			i += consumed
			p.addObject(kind, stmt, file, lineNo)
			if kind == "include" {
				p.followRainerInclude(ctx, stmt, depth)
			}
			continue
		}

		if strings.HasPrefix(line, "$") {
			p.addDirective(ctx, line, file, lineNo, depth)
			continue
		}

		p.addRule(line, file, lineNo)
	}
}

// rainerScriptKind reports whether a line opens a RainerScript statement.
//
// The keyword list is closed on purpose. Matching "any identifier followed by
// (" would swallow legacy selector lines whose action happens to contain a
// parenthesis, and rsyslog's own statement vocabulary is small and stable.
func rainerScriptKind(line string) (string, bool) {
	for _, kw := range []string{
		"action", "module", "global", "input", "template",
		"include", "ruleset", "parser", "timezone", "main_queue",
	} {
		if len(line) > len(kw) && strings.EqualFold(line[:len(kw)], kw) {
			rest := strings.TrimSpace(line[len(kw):])
			if strings.HasPrefix(rest, "(") {
				return kw, true
			}
		}
	}
	return "", false
}

// accumulate joins a statement that spans lines, returning the joined text and
// how many extra lines it consumed. Parentheses inside quoted strings do not
// count, because a template can legitimately contain one.
func accumulate(lines []string, start int) (string, int) {
	var b strings.Builder
	depth, inQuote := 0, false

	for i := start; i < len(lines); i++ {
		text := strings.TrimSuffix(lines[i], "\r")
		if i > start {
			b.WriteString(" ")
		}
		b.WriteString(strings.TrimSpace(text))

		for _, c := range text {
			switch {
			case c == '"':
				inQuote = !inQuote
			case inQuote:
			case c == '(':
				depth++
			case c == ')':
				depth--
			}
		}
		if depth <= 0 && i >= start {
			return b.String(), i - start
		}
	}
	// Unbalanced to end of file. Return what there is; the parameter parser
	// will simply find fewer parameters, and Malformed records the situation.
	return b.String(), len(lines) - 1 - start
}

func (p *rsyslogParser) addObject(kind, stmt, file string, line int) {
	p.cfg.Objects = append(p.cfg.Objects, fact.RsyslogObject{
		Kind:   strings.ToLower(kind),
		Params: parseParams(stmt),
		File:   file,
		Line:   line,
	})
}

// parseParams extracts name="value" pairs from a RainerScript statement.
//
// Names are lowercased because RainerScript treats them case-insensitively —
// `fileCreateMode`, `filecreatemode` and `FileCreateMode` are the same
// parameter, and a check comparing against one spelling would miss the others.
func parseParams(stmt string) map[string]string {
	out := map[string]string{}
	runes := []rune(stmt)

	for i := 0; i < len(runes); i++ {
		if runes[i] != '=' {
			continue
		}
		// Walk back over the name.
		j := i - 1
		for j >= 0 && (runes[j] == ' ' || runes[j] == '\t') {
			j--
		}
		end := j + 1
		for j >= 0 && (isNameRune(runes[j])) {
			j--
		}
		name := strings.ToLower(strings.TrimSpace(string(runes[j+1 : end])))
		if name == "" {
			continue
		}

		// Walk forward to the quoted value.
		k := i + 1
		for k < len(runes) && (runes[k] == ' ' || runes[k] == '\t') {
			k++
		}
		if k >= len(runes) || runes[k] != '"' {
			continue
		}
		k++
		start := k
		for k < len(runes) && runes[k] != '"' {
			k++
		}
		if k >= len(runes) {
			continue
		}
		out[name] = string(runes[start:k])
		i = k
	}
	return out
}

func isNameRune(r rune) bool {
	return r == '_' || r == '.' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// addDirective records a `$Name value` line, following $IncludeConfig.
func (p *rsyslogParser) addDirective(ctx context.Context, line, file string, lineNo, depth int) {
	body := strings.TrimPrefix(line, "$")
	name, value := body, ""
	if i := strings.IndexAny(body, " \t"); i >= 0 {
		name, value = body[:i], strings.TrimSpace(body[i+1:])
	}
	d := fact.RsyslogDirective{Name: name, Value: value, File: file, Line: lineNo}

	if strings.EqualFold(name, "IncludeConfig") {
		p.follow(ctx, value, depth)
		return
	}
	p.cfg.Directives = append(p.cfg.Directives, d)
}

// followRainerInclude handles `include(file="...")`.
func (p *rsyslogParser) followRainerInclude(ctx context.Context, stmt string, depth int) {
	params := parseParams(stmt)
	if pattern, ok := params["file"]; ok {
		p.follow(ctx, pattern, depth)
	}
}

// follow expands an include pattern and parses whatever it matches.
func (p *rsyslogParser) follow(ctx context.Context, pattern string, depth int) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	if depth >= maxIncludeDepth {
		p.cfg.UnresolvedIncludes = append(p.cfg.UnresolvedIncludes,
			pattern+" (include depth limit reached)")
		return
	}

	matches, err := p.sys.Glob(pattern)
	if err != nil || len(matches) == 0 {
		// An include that matched nothing is not the same as one that was
		// never written. A value a check is looking for may live in the file
		// this pattern was meant to reach.
		p.cfg.UnresolvedIncludes = append(p.cfg.UnresolvedIncludes, pattern)
		return
	}
	sort.Strings(matches)

	for _, m := range matches {
		if p.seen[m] {
			continue
		}
		p.seen[m] = true

		res, err := p.sys.ReadFile(m, maxRead)
		if err != nil {
			p.cfg.UnresolvedIncludes = append(p.cfg.UnresolvedIncludes, m+" ("+err.Error()+")")
			continue
		}
		p.cfg.Files = append(p.cfg.Files, m)
		p.cfg.Digests[m] = res.SHA256
		p.parse(ctx, m, string(res.Data), depth+1)
	}
}

// addRule records a legacy selector/action line.
func (p *rsyslogParser) addRule(line, file string, lineNo int) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		p.cfg.Malformed = append(p.cfg.Malformed,
			fact.RsyslogDirective{Name: "unparsed", Value: line, File: file, Line: lineNo})
		return
	}
	selector := strings.TrimSpace(line[:i])
	action := strings.TrimSpace(line[i:])

	// A selector names facilities and priorities. Requiring a "." or a "*"
	// keeps stray text out of the rule list rather than recording it as a
	// forwarding destination that does not exist.
	if !strings.Contains(selector, ".") && !strings.Contains(selector, "*") {
		p.cfg.Malformed = append(p.cfg.Malformed,
			fact.RsyslogDirective{Name: "unparsed", Value: line, File: file, Line: lineNo})
		return
	}
	p.cfg.Rules = append(p.cfg.Rules, fact.RsyslogRule{
		Selector: selector, Action: action, File: file, Line: lineNo,
	})
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

func collectJournald(s system.System, fs *fact.Set) {
	j := fact.Journald{Digests: map[string]string{}}

	// The main file first, then drop-ins in lexical order. systemd reads them
	// in that order and **later settings override earlier ones** — the
	// opposite of sshd_config, and the reason fact.Journald.Effective returns
	// the last match rather than the first.
	files := []string{JournaldPath}

	matches, err := s.Glob(JournaldDropIns)
	if err != nil {
		j.UnresolvedIncludes = append(j.UnresolvedIncludes, JournaldDropIns)
	} else {
		sort.Strings(matches)
		files = append(files, matches...)
	}

	for _, f := range files {
		res, err := s.ReadFile(f, maxRead)
		switch {
		case err == nil:
		case errors.Is(err, system.ErrNotExist):
			continue
		case errors.Is(err, system.ErrPermission):
			if f == JournaldPath {
				fs.PutError(fact.Error{
					Fact: fact.JournaldID, Kind: fact.ErrPermission,
					Msg: "permission denied; run as root to read this file", Path: f,
				})
				return
			}
			j.UnresolvedIncludes = append(j.UnresolvedIncludes, f+" (permission denied)")
			continue
		default:
			j.UnresolvedIncludes = append(j.UnresolvedIncludes, f+" ("+err.Error()+")")
			continue
		}

		j.Installed = true
		j.Files = append(j.Files, f)
		j.Digests[f] = res.SHA256
		parseJournald(&j, f, string(res.Data))
	}

	j.PersistentDirPath = JournalDir
	j.PersistentDirState = statState(s, JournalDir)
	// journald is part of systemd and is running on any host that has it,
	// whether or not anyone wrote a configuration file. The directory's
	// presence is therefore evidence of the daemon as much as the file is.
	if j.PersistentDirState == fact.JournalDirPresent {
		j.Installed = true
	}

	fs.Put(j)
}

// parseJournald reads a systemd unit-style INI file.
func parseJournald(j *fact.Journald, file, data string) {
	section := ""

	for n, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		lineNo := n + 1

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}

		i := strings.Index(line, "=")
		if i < 0 {
			j.Malformed = append(j.Malformed,
				fact.JournaldSetting{Value: line, File: file, Line: lineNo, Section: section})
			continue
		}
		j.Settings = append(j.Settings, fact.JournaldSetting{
			Key:     strings.TrimSpace(line[:i]),
			Value:   strings.TrimSpace(line[i+1:]),
			File:    file,
			Line:    lineNo,
			Section: section,
		})
	}
}

// statState classifies the journal directory's presence.
//
// A refused stat and an odd failure collapse to the same state because they
// lead to the same verdict: the meaning of Storage=auto is undetermined either
// way, and inventing a distinction the checks cannot act on would be surface
// area for nothing.
func statState(s system.System, path string) fact.JournalDirState {
	_, err := s.Stat(path)
	switch {
	case err == nil:
		return fact.JournalDirPresent
	case errors.Is(err, system.ErrNotExist):
		return fact.JournalDirAbsent
	default:
		return fact.JournalDirUnknown
	}
}
