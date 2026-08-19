// Package users collects the local account databases: /etc/passwd,
// /etc/shadow and /etc/group.
//
// This is the module where an unprivileged scan stops being a theoretical
// concern. /etc/passwd and /etc/group are world-readable; /etc/shadow is not.
// A scan running as a normal user gets two of the three, and the collector's
// job is to say exactly that — passwd and group as facts, shadow as a typed
// fact error naming the path and the reason — rather than failing as a unit.
//
// Failing as a unit would be the easy implementation and the wrong one. Every
// check that only needs passwd would resolve to UNKNOWN because a file it
// never wanted was unreadable, an operator would see fifteen unknowns where
// three were warranted, and the three that mattered would be invisible among
// them.
//
// **/etc/shadow's bytes never enter the bundle.** The exclusion is enforced at
// the seam, in internal/collect.IsCredentialFile, not here — a collector that
// had to remember would one day forget. See docs/adr/0015-account-data-in-bundles.md.
package users

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "users"

// Paths of the three databases.
const (
	PasswdPath = "/etc/passwd"
	ShadowPath = "/etc/shadow"
	GroupPath  = "/etc/group"
)

// maxRead bounds one database. A very large site has tens of thousands of
// local accounts, which is a few megabytes; anything approaching this cap is
// not an account database and must not be held in memory by a root process.
const maxRead = 16 << 20 // 16 MiB

// Collector implements collect.Collector for the local account databases.
type Collector struct{}

// New returns the users collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

// Produces names all three facts, so that a failure this collector never got
// to report — a timeout, a panic — is recorded against each of them rather
// than against a collector name no check has heard of.
func (Collector) Produces() []fact.ID {
	return []fact.ID{fact.PasswdID, fact.ShadowID, fact.GroupID}
}

// DependsOn is nil. Reading three files needs nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone, and here the reasoning is load-bearing rather than
// conventional.
//
// Declaring CapRoot would make an unprivileged scan skip this collector
// outright and report that all three facts were never collected — including
// the two that are world-readable and that it could have read perfectly well.
// Running it means an unprivileged scan produces real passwd and group facts,
// every check over them returns a real verdict, and only the shadow-dependent
// checks resolve to UNKNOWN, each naming the file and the reason.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: three line-oriented files, no walk, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is five seconds. Three files of bounded size on local storage; if
// this does not complete, the path is on a filesystem that is not answering,
// and an audit that hangs on /etc/passwd is worse than one that records why it
// stopped.
func (Collector) Timeout() time.Duration { return 5 * time.Second }

// Collect reads the three databases, recording each independently.
//
// Each file gets its own fact or its own fact error. There is no path through
// this function where one file's failure removes another file's observation,
// and the returned error stays nil for everything the collector was able to
// classify — which is everything, because a read either succeeds, is refused,
// is absent, or fails for a reason worth recording verbatim.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	collectPasswd(s, fs)

	// Returning nil rather than ctx.Err() on a deadline is load-bearing, not an
	// oversight. internal/collect.runner treats a collector that returns an
	// error while its context is done as a timeout and **discards its partial
	// facts** — so returning the context error here would throw away the passwd
	// fact this function has already gathered, which is precisely the graceful
	// degradation this collector exists to provide. Returning nil takes the
	// runner's merge path, the facts collected so far survive, and the runner
	// records the deadline itself.
	//nolint:nilerr // error deliberately swallowed for graceful degradation; the facts already collected are kept in the FactSet
	if err := ctx.Err(); err != nil {
		return nil
	}
	collectShadow(s, fs)

	//nolint:nilerr // as above: returning the context error would discard the passwd and shadow facts
	if err := ctx.Err(); err != nil {
		return nil
	}
	collectGroup(s, fs)
	return nil
}

// readDatabase reads one file, translating every failure into the typed fact
// error a check will map to an UNKNOWN reason code.
func readDatabase(s system.System, id fact.ID, path string) (system.ReadResult, *fact.Error) {
	res, err := s.ReadFile(path, maxRead)
	switch {
	case err == nil:
	case errors.Is(err, system.ErrPermission):
		// The expected outcome for /etc/shadow on an unprivileged scan. It is
		// an observation about what this scan could see, not a malfunction.
		return res, &fact.Error{
			Fact: id, Kind: fact.ErrPermission,
			Msg: "permission denied; run as root to read this file", Path: path,
		}
	case errors.Is(err, system.ErrNotExist):
		return res, &fact.Error{
			Fact: id, Kind: fact.ErrNotCollected,
			Msg: "file does not exist on this host", Path: path,
		}
	case errors.Is(err, system.ErrNotRegular):
		return res, &fact.Error{
			Fact: id, Kind: fact.ErrParse,
			Msg: "path is not a regular file", Path: path,
		}
	default:
		return res, &fact.Error{
			Fact: id, Kind: fact.ErrInternal, Msg: err.Error(), Path: path,
		}
	}

	if res.Truncated {
		// A partly-read account database is the worst possible input: every
		// negative assertion over it ("no account has an empty password")
		// would be a claim about accounts we never saw.
		return res, &fact.Error{
			Fact: id, Kind: fact.ErrTruncated,
			Msg: "file exceeded the read cap; the account list is incomplete", Path: path,
		}
	}
	return res, nil
}

func collectPasswd(s system.System, fs *fact.Set) {
	res, ferr := readDatabase(s, fact.PasswdID, PasswdPath)
	if ferr != nil {
		fs.PutError(*ferr)
		return
	}

	p := fact.Passwd{Path: PasswdPath, Digest: res.SHA256}
	for n, raw := range splitLines(string(res.Data)) {
		line := strings.TrimSuffix(raw, "\r")
		if skippable(line) {
			continue
		}

		// NIS/LDAP compatibility lines are not accounts. glibc still honours
		// them, and the accounts they import are not in this file at all.
		if first := strings.SplitN(line, ":", 2)[0]; strings.HasPrefix(first, "+") || strings.HasPrefix(first, "-") {
			p.CompatEntries = append(p.CompatEntries, fact.CompatEntry{Spec: first, Line: n + 1})
			continue
		}

		f := strings.Split(line, ":")
		if len(f) < 7 {
			p.Malformed = append(p.Malformed, n+1)
			continue
		}
		uid, uidErr := strconv.ParseUint(f[2], 10, 32)
		gid, gidErr := strconv.ParseUint(f[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			p.Malformed = append(p.Malformed, n+1)
			continue
		}
		p.Entries = append(p.Entries, fact.PasswdEntry{
			Name:  f[0],
			UID:   uint32(uid),
			GID:   uint32(gid),
			Home:  f[5],
			Shell: f[6],
			Line:  n + 1,
		})
	}
	fs.Put(p)
}

func collectShadow(s system.System, fs *fact.Set) {
	res, ferr := readDatabase(s, fact.ShadowID, ShadowPath)
	if ferr != nil {
		fs.PutError(*ferr)
		return
	}

	sh := fact.Shadow{Path: ShadowPath}
	for n, raw := range splitLines(string(res.Data)) {
		line := strings.TrimSuffix(raw, "\r")
		if skippable(line) {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 2 {
			sh.Malformed = append(sh.Malformed, n+1)
			continue
		}
		// f[1] is the crypt field. It is classified here and discarded; the
		// hash itself is never copied into the fact, so it cannot reach a
		// bundle, a renderer or a log line.
		alg, locked, empty := fact.AlgorithmFor(f[1])
		sh.Entries = append(sh.Entries, fact.ShadowEntry{
			Name:      f[0],
			Empty:     empty,
			Locked:    locked,
			Algorithm: alg,
			Line:      n + 1,
			MinDays:   optionalInt(f, 3),
			MaxDays:   optionalInt(f, 4),
		})
	}
	fs.Put(sh)
}

func collectGroup(s system.System, fs *fact.Set) {
	res, ferr := readDatabase(s, fact.GroupID, GroupPath)
	if ferr != nil {
		fs.PutError(*ferr)
		return
	}

	g := fact.Group{Path: GroupPath, Digest: res.SHA256}
	for n, raw := range splitLines(string(res.Data)) {
		line := strings.TrimSuffix(raw, "\r")
		if skippable(line) {
			continue
		}
		// /etc/group carries the same NIS compatibility syntax as /etc/passwd,
		// with the same consequence: the groups it imports are not in this
		// file, so nothing may be concluded absent from it.
		if first := strings.SplitN(line, ":", 2)[0]; strings.HasPrefix(first, "+") || strings.HasPrefix(first, "-") {
			g.CompatEntries = append(g.CompatEntries, fact.CompatEntry{Spec: first, Line: n + 1})
			continue
		}

		f := strings.Split(line, ":")
		if len(f) < 4 {
			g.Malformed = append(g.Malformed, n+1)
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			g.Malformed = append(g.Malformed, n+1)
			continue
		}
		var members []string
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		g.Entries = append(g.Entries, fact.GroupEntry{
			Name:    f[0],
			GID:     uint32(gid),
			Members: members,
			Line:    n + 1,
		})
	}
	fs.Put(g)
}

// optionalInt reads a shadow aging field, returning nil when the field is
// absent or empty.
//
// nil is not zero and the difference decides a verdict: an empty MaxDays means
// "no maximum", while a MaxDays of 0 means "must be changed every day". A
// parser that returned 0 for an empty field would report the most permissive
// setting in the file as the strictest one available.
//
// A field that is present but not a number is also nil. It is not a valid
// aging value, and inventing one from it would be a fabricated policy.
func optionalInt(fields []string, i int) *int {
	if i >= len(fields) {
		return nil
	}
	raw := strings.TrimSpace(fields[i])
	if raw == "" {
		return nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return nil
	}
	return &n
}

// splitLines splits on newline without dropping a trailing empty line's index,
// so reported line numbers match what an operator sees in an editor.
func splitLines(data string) []string { return strings.Split(data, "\n") }

// skippable reports whether a line carries no entry. Blank lines and comments
// are both legal in these files; nsswitch-managed hosts accumulate them.
func skippable(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}
