// Package auth collects the PAM stack and the /etc/security files that
// complete it.
//
// PAM is the only place on a Linux host where "how do we decide this person is
// who they say" is actually written down. /etc/shadow holds the hashes and
// sshd_config decides what may be offered over the network, but the rules —
// how long a password must be, how many failures lock the account, whether an
// empty password is accepted at all — live here and nowhere else.
//
// Three things make it awkward to read, and all three are handled rather than
// assumed away:
//
//  1. **Two distribution layouts.** Red Hat keeps the shared rules in
//     system-auth and password-auth; Debian keeps them in common-auth,
//     common-account, common-password and common-session and pulls them into
//     each service with @include. A collector that knew one family would
//     report "no password quality is enforced" on every host of the other.
//
//  2. **Three include directives with different scopes.** `@include <file>`
//     inlines the whole file, every type at once, and exists only in pam.d.
//     `<type> include <file>` pulls in that one type's lines. `<type> substack
//     <file>` does the same and scopes jumps. Confusing the first two either
//     drops three quarters of a Debian host's rules or imports password rules
//     into the auth stack.
//
//  3. **The primary files are symlinks on Red Hat.** /etc/pam.d/system-auth
//     points at system-auth-ac, or into /etc/authselect, on every stock
//     install. The seam's ReadFile opens with O_NOFOLLOW and correctly refuses
//     a symlink, so the collector resolves the chain explicitly with Readlink
//     — one observed hop at a time, bounded, each recorded — and reads the
//     regular file at the end. See ADR-0017 and the note on followLinks below.
//
// No password hash, no user name and no authentication token passes through
// here: the files hold policy, not credentials. What the collector does not do
// is simulate PAM's control flow. That would mean implementing the bracketed
// `[success=1 default=ignore]` jump semantics, and a stack simulator that is
// subtly wrong produces confident verdicts about which module actually runs.
// The fact records what is written; the checks assert presence and arguments
// and say plainly where control flow could defeat them.
package auth

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "auth"

// Well-known paths.
const (
	PAMDir = "/etc/pam.d"
	// PwQualityPath trips gosec's hardcoded-credential heuristic on the "Pw"
	// in its name. It is the path to a policy file — minimum lengths and
	// character-class requirements — and this collector reads no credential of
	// any kind; TestNoPasswordMaterialReachesTheFact asserts that.
	PwQualityPath = "/etc/security/pwquality.conf" //nolint:gosec // G101: a path to a policy file, not a credential
	FaillockPath  = "/etc/security/faillock.conf"
)

// services are the stacks probed, in a fixed record order covering both
// distribution families plus the three entry points that matter most.
//
// Both families' names are always attempted. Which ones exist is what
// fact.PAM.Layout() reads, and probing only the family we guessed at would
// have made the guess unfalsifiable.
func services() []string {
	return []string{
		// Red Hat: the shared stacks.
		"system-auth", "password-auth",
		// Debian: the shared stacks.
		"common-auth", "common-account", "common-password", "common-session",
		// Entry points, on both. They mostly include the above, but a host
		// that has diverged has diverged here.
		"sshd", "login", "passwd", "su",
	}
}

const (
	// maxRead bounds one PAM file. These are tens of lines; anything near this
	// is not a PAM configuration.
	maxRead = 1 << 20 // 1 MiB
	// maxIncludeDepth bounds include recursion. PAM files include each other
	// freely and a self-including file is a loop that a depth limit terminates
	// without needing to detect it.
	maxIncludeDepth = 8
)

// Collector implements collect.Collector for the PAM configuration.
type Collector struct{}

// New returns the auth collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

func (Collector) Produces() []fact.ID { return []fact.ID{fact.PAMID} }

// DependsOn is nil.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone. /etc/pam.d and /etc/security are world-readable on
// every mainstream distribution — they have to be, because every setuid
// program that authenticates reads them as the calling user. Declaring CapRoot
// would make an unprivileged scan report the whole module as never collected
// when it can answer every question the module asks.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: a bounded set of small text files, no walk, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds. Include expansion touches a dozen small files.
func (Collector) Timeout() time.Duration { return 10 * time.Second }

// Collect reads the stacks and the two /etc/security files.
//
// It returns nil in every case. A file is present, absent, refused, or broken
// in a way worth recording verbatim, and all four are observations about the
// host rather than failures of the collector.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	p := fact.PAM{Digests: map[string]string{}}

	// Probe the directory first so that "PAM is not installed" and "we were
	// not allowed to look" stay distinguishable. Everything below depends on
	// which of the two this is, and a collector that inferred absence from a
	// series of failed reads would report a host with no PAM whenever it was
	// run without privilege.
	switch _, err := s.Stat(PAMDir); {
	case err == nil:
		p.Installed, p.DirState = true, fact.FilePresent
	case errors.Is(err, system.ErrNotExist):
		p.DirState = fact.FileAbsent
		fs.Put(p)
		return nil
	case errors.Is(err, system.ErrPermission):
		// Installed stays true: something is there, we could not look at it,
		// and treating that as absence would turn an unprivileged scan into a
		// report that this host does not authenticate anybody.
		p.Installed, p.DirState = true, fact.FileDenied
		p.DirMsg = "permission denied; a parent directory refuses traversal"
		fs.Put(p)
		return nil
	default:
		p.Installed, p.DirState = true, fact.FileError
		p.DirMsg = err.Error()
		fs.Put(p)
		return nil
	}

	c := &collector{sys: s, pam: &p}
	for _, name := range services() {
		// The deadline stopped us. Record what was gathered rather than
		// returning the context error: internal/collect.runner discards the
		// partial facts of a collector that errors while its context is done.
		//nolint:nilerr // error deliberately swallowed for graceful degradation; the stacks already collected are kept in the FactSet
		if err := ctx.Err(); err != nil {
			fs.Put(p)
			return nil
		}
		p.Services = append(p.Services, c.readService(ctx, name))
	}

	p.PwQuality = c.readSettings(PwQualityPath)
	p.Faillock = c.readSettings(FaillockPath)

	fs.Put(p)
	return nil
}

type collector struct {
	sys system.System
	pam *fact.PAM
}

// readService resolves one service stack, expanding includes in place.
func (c *collector) readService(ctx context.Context, name string) fact.PAMService {
	svc := fact.PAMService{Name: name, Path: path.Join(PAMDir, name)}

	real, data, err := c.read(svc.Path)
	switch {
	case err == nil:
		svc.State = fact.FilePresent
		if real != svc.Path {
			svc.ResolvedPath = real
		}
	case errors.Is(err, system.ErrNotExist):
		svc.State = fact.FileAbsent
		return svc
	case errors.Is(err, system.ErrPermission):
		svc.State, svc.Msg = fact.FileDenied, "permission denied"
		return svc
	default:
		svc.State, svc.Msg = fact.FileError, err.Error()
		return svc
	}

	c.parse(ctx, &svc, real, data, "", 0, map[string]bool{real: true})
	return svc
}

// parse reads one file into a stack, following includes.
//
// scope is the management group an `include`/`substack` restricted us to, or
// "" when everything applies. It is what keeps `auth include common-password`
// from importing password rules into the auth stack.
func (c *collector) parse(ctx context.Context, svc *fact.PAMService, file, data string, scope fact.PAMType, depth int, seen map[string]bool) {
	lines := strings.Split(data, "\n")

	for i := 0; i < len(lines); i++ {
		if ctx.Err() != nil {
			return
		}
		raw, consumed := joinContinuations(lines, i)
		i += consumed
		lineNo := i + 1 - consumed

		stmt := strings.TrimSpace(stripComment(raw))
		if stmt == "" {
			continue
		}

		// @include is Debian's whole-file directive: not scoped to a type, and
		// the reason a Debian sshd stack is four lines long and still enforces
		// everything.
		if rest, ok := cutPrefix(stmt, "@include"); ok {
			c.follow(ctx, svc, "@include", "", strings.TrimSpace(rest), file, lineNo, depth, seen)
			continue
		}

		line, ok := parseRule(stmt)
		if !ok {
			continue
		}
		line.File, line.Line, line.Depth = file, lineNo, depth

		// `<type> include <file>` and `<type> substack <file>` pull in only
		// that type's rules. Both are recorded as includes rather than as
		// rules: the module field of such a line is a filename, not a module.
		switch strings.ToLower(line.Control) {
		case "include", "substack":
			// A nested include inside a type-scoped one stays scoped to the
			// outer type. PAM cannot widen an include's scope from inside it,
			// and treating the inner directive's own type as authoritative
			// would import rules the outer include never asked for.
			inner := line.Type
			if scope != "" {
				inner = scope
			}
			c.follow(ctx, svc, strings.ToLower(line.Control), inner, line.Module, file, lineNo, depth, seen)
			continue
		}

		if scope != "" && line.Type != scope {
			continue
		}
		svc.Lines = append(svc.Lines, line)
	}
}

// follow expands one include directive.
func (c *collector) follow(ctx context.Context, svc *fact.PAMService, directive string, scope fact.PAMType, target, from string, lineNo, depth int, seen map[string]bool) {
	inc := fact.PAMInclude{
		Directive: directive, Type: scope, Target: target,
		File: from, Line: lineNo,
	}

	if target == "" {
		inc.Reason = "the directive names no file"
		svc.Unresolved = append(svc.Unresolved, inc)
		return
	}
	// A bare name is relative to /etc/pam.d; an absolute path is used as
	// written, which is how a site that keeps its stacks elsewhere writes it.
	inc.Path = target
	if !path.IsAbs(target) {
		inc.Path = path.Join(PAMDir, target)
	}

	if depth >= maxIncludeDepth {
		inc.Reason = "include nesting exceeded the depth limit"
		svc.Unresolved = append(svc.Unresolved, inc)
		return
	}

	real, data, err := c.read(inc.Path)
	if err != nil {
		switch {
		case errors.Is(err, system.ErrNotExist):
			// The classic broken stack: a package removed, a file renamed, a
			// hand-edited include with a typo. PAM logs it and the rules the
			// operator believes are in force are simply not there.
			inc.Reason = "the file does not exist"
		case errors.Is(err, system.ErrPermission):
			inc.Reason = "permission denied"
		default:
			inc.Reason = err.Error()
		}
		svc.Unresolved = append(svc.Unresolved, inc)
		return
	}

	// A file already on this path is a cycle. Recording it as unresolved keeps
	// the stack honestly marked incomplete rather than silently truncated: the
	// rules past the loop were never read, and a check must not conclude a
	// module is absent from a stack that stopped early.
	if seen[real] {
		inc.Reason = "include cycle; the file is already on this stack"
		svc.Unresolved = append(svc.Unresolved, inc)
		return
	}
	seen[real] = true
	defer delete(seen, real)

	c.parse(ctx, svc, real, data, scope, depth+1, seen)
}

// read resolves a path through any symlink chain and reads the regular file at
// the end, returning the real path so evidence cites what an operator edits.
//
// The chain is walked by collect.ResolveLinks, one observed hop at a time and
// bounded, which is what keeps the O_NOFOLLOW protection intact while making
// Red Hat's /etc/pam.d/system-auth — a symlink on every stock install —
// readable at all. Without it the module reports UNKNOWN on the entire Red Hat
// family. The reasoning is on ResolveLinks; the final open here still refuses
// a symlink, a FIFO or a device.
func (c *collector) read(p string) (string, string, error) {
	real, err := collect.ResolveLinks(c.sys, p)
	if err != nil {
		return real, "", err
	}

	res, err := c.sys.ReadFile(real, maxRead)
	if err != nil {
		return real, "", err
	}
	// One funnel for every PAM file this collector reads — the stacks, the
	// symlink targets, pwquality.conf, faillock.conf — so the gate cannot be
	// forgotten at one of them. A PAM file that is not text is the most
	// dangerous of the lot: pam_unix's absence from a stack is what AUTH-0004
	// reads as "no rule accepts an empty password", and concluding that from
	// bytes libpam would refuse to load is a PASS invented out of nothing.
	if why := collect.NotText(res.Data); why != "" {
		return real, "", fmt.Errorf("%w: %s", errMalformed, why)
	}
	c.pam.Digests[real] = res.SHA256
	return real, string(res.Data), nil
}

// errMalformed marks a PAM file that was read and is not text. It is a
// package-local sentinel rather than a system error because it describes the
// contents rather than the read, and every caller already has a branch for an
// error it does not otherwise recognise.
var errMalformed = errors.New("not a text configuration file")

// readSettings reads a key=value file from /etc/security.
func (c *collector) readSettings(p string) fact.SettingsFile {
	f := fact.SettingsFile{Path: p}

	real, data, err := c.read(p)
	switch {
	case err == nil:
		f.State = fact.FilePresent
	case errors.Is(err, system.ErrNotExist):
		f.State = fact.FileAbsent
		return f
	case errors.Is(err, system.ErrPermission):
		f.State, f.Msg = fact.FileDenied, "permission denied"
		return f
	default:
		f.State, f.Msg = fact.FileError, err.Error()
		return f
	}

	for i, raw := range strings.Split(data, "\n") {
		l := strings.TrimSpace(stripComment(raw))
		if l == "" {
			continue
		}
		key, val := l, ""
		if idx := strings.Index(l, "="); idx >= 0 {
			key, val = strings.TrimSpace(l[:idx]), strings.TrimSpace(l[idx+1:])
		}
		if key == "" {
			continue
		}
		f.Settings = append(f.Settings, fact.PwQualitySetting{
			Key: key, Value: val, File: real, Line: i + 1,
		})
	}
	return f
}

// ---------------------------------------------------------------------------
// line parsing
// ---------------------------------------------------------------------------

// parseRule splits one PAM rule into its four parts.
//
// The control field is why this cannot be strings.Fields. PAM allows a
// bracketed control expression — `[success=1 default=ignore]` — which contains
// spaces, and Debian's common-password uses exactly that form for the
// pam_unix.so line that sets the password hash. A naive split reads
// "[success=1" as the control and "default=ignore]" as the module name, so the
// hashing check would find no pam_unix.so at all and report UNKNOWN on a stock
// Debian host.
func parseRule(stmt string) (fact.PAMLine, bool) {
	var l fact.PAMLine
	rest := stmt

	typ, rest, ok := nextField(rest)
	if !ok {
		return l, false
	}
	if strings.HasPrefix(typ, "-") {
		l.Optional, typ = true, typ[1:]
	}
	switch strings.ToLower(typ) {
	case "auth", "account", "password", "session":
		l.Type = fact.PAMType(strings.ToLower(typ))
	default:
		// Not a rule: a `@include` handled elsewhere, or a stray line.
		return l, false
	}

	if strings.HasPrefix(strings.TrimSpace(rest), "[") {
		rest = strings.TrimSpace(rest)
		end := strings.Index(rest, "]")
		if end < 0 {
			return l, false
		}
		l.Control, rest = rest[:end+1], rest[end+1:]
	} else {
		l.Control, rest, ok = nextField(rest)
		if !ok {
			return l, false
		}
	}

	l.Module, rest, ok = nextField(rest)
	if !ok {
		return l, false
	}
	l.Args = strings.Fields(rest)
	return l, true
}

// nextField returns the first whitespace-delimited token and the remainder.
func nextField(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", false
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:], true
	}
	return s, "", true
}

// joinContinuations folds a backslash-continued rule into one statement,
// returning how many extra lines it consumed. PAM supports the continuation
// and long pam_pwquality argument lists routinely use it.
func joinContinuations(lines []string, i int) (string, int) {
	out := strings.TrimSuffix(lines[i], "\r")
	consumed := 0
	for strings.HasSuffix(strings.TrimRight(out, " \t"), `\`) && i+consumed+1 < len(lines) {
		out = strings.TrimRight(out, " \t")
		out = out[:len(out)-1]
		consumed++
		out += " " + strings.TrimSpace(strings.TrimSuffix(lines[i+consumed], "\r"))
	}
	return out, consumed
}

// stripComment removes a trailing comment.
func stripComment(l string) string {
	if i := strings.Index(l, "#"); i >= 0 {
		return l[:i]
	}
	return l
}

// cutPrefix reports whether s begins with the given directive as a whole word.
func cutPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	rest := s[len(prefix):]
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	return rest, true
}
