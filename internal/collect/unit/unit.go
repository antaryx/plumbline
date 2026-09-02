// Package unit assembles a systemd unit from the files on disk, the way
// systemd would, and hands back the directives a collector asked for.
//
// It exists because "read a unit file" is not what systemd does. A running
// unit is a vendor file found by searching four directories in precedence
// order, with every drop-in in every <unit>.d directory layered on top in an
// order that is neither the search order nor the directory order. Both of
// those rules move verdicts rather than details:
//
//   - **First found wins, across all four roots.** An admin unit in /etc
//     replaces the vendor one entirely; it does not merge with it.
//   - **A drop-in's basename is its identity.** 50-hardening.conf in /etc
//     causes 50-hardening.conf in /usr/lib to be discarded *entirely*, which
//     is how an administrator neutralises a vendor drop-in without editing a
//     file they do not own. Applying the loser would report a setting that is
//     not in force.
//   - **Survivors apply in lexical order by filename, across all directories
//     together**, so 10-foo.conf from /usr/lib is applied before 20-bar.conf
//     from /etc even though /etc outranks /usr/lib as a directory.
//
// The first consumer of this was the Docker collector, whose CONTAINERS-0006
// is one of the two Critical checks in the catalog: on an exposed host and on
// a safe one the vendor docker.service is byte-identical, and the whole of the
// difference is a .conf in a .d directory. The second is the SERVICES
// collector's sandboxing audit. A second implementation of these rules would
// be a second set of answers, agreeing today and drifting later, so there is
// one.
//
// # What it does not do
//
// **It reads only the directives it was asked for.** Request.Directives is not
// a convenience filter, it is the privacy boundary: a directive whose name is
// not in the list is discarded during the parse and never held. That is what
// keeps Environment= and EnvironmentFile= — where a fleet's proxy credentials
// live — out of memory and out of any fact built from the result, structurally
// rather than by the caller remembering.
//
// **It does not interpret values.** A directive's value comes back as the text
// after the "=", joined across continuation lines and otherwise untouched. How
// to read it is the caller's business, and so is what to do about it: the
// Docker collector splits its ExecStart into arguments and scrubs the values
// of log options out of them before anything reaches a fact, and nothing about
// that belongs here.
//
// **Nothing is expanded.** Environment=, EnvironmentFile= and systemd's %
// specifiers are not read, so a $VARIABLE survives as text. Resolving one
// means reading the file the secrets are in.
//
// # How the bytes are read
//
// Fragments go through the seam's ReadOpaque, so their contents never reach a
// bundle's evidence store. What travels is the digest and whatever the caller
// keeps. See docs/PRIVACY.md.
package unit

import (
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// The unit search directories, in systemd's precedence order, highest first.
//
// LegacyVendorDir is /lib/systemd/system. On a usr-merged distribution it is
// the same directory as VendorDir reached through a symlink, and on a pre-merge
// one it is the only one that exists. Both are probed and the duplicate is
// detected by inode rather than by guessing which layout the host uses.
const (
	AdminDir        = "/etc/systemd/system"
	RuntimeDir      = "/run/systemd/system"
	VendorDir       = "/usr/lib/systemd/system"
	LegacyVendorDir = "/lib/systemd/system"
)

// Roots returns the search directories in precedence order.
func Roots() []string {
	return []string{AdminDir, RuntimeDir, VendorDir, LegacyVendorDir}
}

const (
	// MaxRead bounds one fragment. A unit file is a few kilobytes; anything
	// approaching this is not a unit and should not be held in memory in a
	// root process.
	MaxRead = 1 << 20 // 1 MiB
	// MaxDropIns bounds a .d listing.
	MaxDropIns = 1024
	// MaxLinkHops bounds a symlink chain. `systemctl link` writes one hop and
	// a mask writes one; more than a few is a loop or an attempt at one.
	MaxLinkHops = 4
)

// Request says which unit to assemble and which of its directives to keep.
type Request struct {
	// Name is the unit, with its suffix: "docker.service".
	Name string
	// Section is the one section read, without brackets: "Service". Directives
	// outside it are discarded.
	Section string
	// Directives are the names to keep, matched exactly. **systemd directive
	// names are case sensitive** — execstart= is not a directive and is a unit
	// systemd would refuse to load — so they are compared as written rather
	// than folded.
	//
	// Everything not named here is discarded during the parse. See the package
	// doc: this is the privacy boundary, not a convenience.
	Directives []string
}

// Directive is one assignment that survived the filter, with where it came
// from.
type Directive struct {
	Name string
	// Value is the text after the "=", trimmed, with continuation lines
	// joined. Empty is meaningful: for a list-valued setting it resets the
	// list, and for a scalar one it restores the default.
	Value string
	// Origin is the fragment it was read from, and Line the 1-based line in
	// that fragment — the first physical line, when the assignment was
	// continued — so evidence points somewhere an operator can open.
	Origin string
	Line   int
}

// Unit is an assembled unit: what became of every file, and the directives
// asked for, in systemd's application order.
type Unit struct {
	Name      string
	State     fact.UnitState
	Path      string
	Digest    string
	Msg       string
	Fragments []fact.UnitFragment
	// Directives are in application order: the unit file's first, then each
	// applied drop-in's, drop-ins in lexical order by filename. Every
	// occurrence is kept, because which one wins depends on the setting and is
	// the caller's decision. See List and Last.
	Directives []Directive
}

// Judgeable reports whether the directives may be read as the unit's
// configuration. False for every state in which some part was not seen.
func (u Unit) Judgeable() bool { return u.State == fact.UnitPresent }

// Complete reports whether every fragment that would have contributed was
// actually read.
//
// It is separate from State because the failure it describes is partial: the
// unit itself can read perfectly while a drop-in beside it is unreadable, and
// a drop-in is precisely where an operator puts the setting that changes the
// answer.
func (u Unit) Complete() bool { return len(u.Incomplete()) == 0 }

// Incomplete returns the fragments that were not read, shadowed ones excluded.
func (u Unit) Incomplete() []fact.UnitFragment {
	return fact.IncompleteFragments(u.Fragments)
}

// List applies systemd's list-valued fold to one directive: a non-empty
// assignment appends and an empty one clears everything before it.
//
// That is why every documented Docker override begins with a bare `ExecStart=`
// — without it the drop-in adds a second command line rather than replacing
// the first.
func (u Unit) List(name string) []Directive {
	var out []Directive
	for _, d := range u.Directives {
		if d.Name != name {
			continue
		}
		if d.Value == "" {
			out = nil
			continue
		}
		out = append(out, d)
	}
	return out
}

// Last applies systemd's scalar fold: the final assignment wins, and an empty
// one restores the default, which is reported as "not set" rather than as an
// empty value.
func (u Unit) Last(name string) (Directive, bool) {
	var (
		found Directive
		ok    bool
	)
	for _, d := range u.Directives {
		if d.Name != name {
			continue
		}
		if d.Value == "" {
			// systemd reads a bare assignment as "forget what was said
			// before", so the default is in force and nothing here decides it.
			found, ok = Directive{}, false
			continue
		}
		found, ok = d, true
	}
	return found, ok
}

// Assemble finds the unit, layers its drop-ins, and returns the directives
// asked for.
func Assemble(s system.System, req Request) Unit {
	u := Unit{Name: req.Name}

	unitPath, found, refused := findUnit(s, req.Name)
	// A higher-precedence location we were not allowed to look in could hold a
	// unit file that replaces the one below it entirely. Recording it is what
	// makes Complete() false, so a caller drawing a conclusion from an absence
	// says it could not see everything rather than asserting the absence.
	u.Fragments = append(u.Fragments, refused...)
	if !found {
		// No unit file anywhere. Drop-ins alone start nothing — systemd will
		// not assemble a unit that has no unit file — so there is nothing
		// further to read and nothing to layer them onto.
		u.State = fact.UnitAbsent
		// Path names where a package would have installed one, so a reader is
		// told what was looked for rather than only that nothing was found.
		u.Path = path.Join(VendorDir, req.Name)
		u.Msg = "no " + req.Name + " in any systemd unit directory"
		return u
	}

	u.Path = unitPath
	frag, data := readFragment(s, unitPath, fact.FragmentUnit)
	u.Fragments = append(u.Fragments, frag)
	u.Digest = frag.Digest
	u.State = frag.State
	u.Msg = frag.Msg

	if frag.State != fact.UnitPresent {
		// Masked, denied, or unreadable. The drop-ins are not read: on a
		// masked unit they are irrelevant, and on an unreadable one the base
		// they modify is already unknown, so reading them would produce a
		// configuration assembled from something nobody saw.
		return u
	}

	u.Directives = parse(data, unitPath, req)
	applyDropIns(s, &u, req)
	return u
}

// findUnit returns the highest-precedence unit file that exists, and the
// locations it was not allowed to look in.
//
// A path that cannot be stat'ed does not stop the probe: a refused stat on one
// of four guesses must not stop the other three from answering, and on a host
// where /etc/systemd/system cannot be traversed the vendor unit is still the
// best available answer. But it is not a silent skip either. A unit file in a
// higher-precedence directory *replaces* the one below it rather than merging
// with it, so a location we could not examine may hold a file that changes
// everything — and the refusals come back so Assemble can record them, which
// is what makes Unit.Complete false and stops a caller reporting an absence it
// did not establish.
//
// ErrNotExist is not a refusal and is not reported: nothing is there, which is
// an answer rather than a gap.
func findUnit(s system.System, name string) (unitPath string, found bool, refused []fact.UnitFragment) {
	for _, root := range Roots() {
		p := path.Join(root, name)
		_, err := s.Stat(p)
		switch {
		case err == nil:
			return p, true, refused
		case errors.Is(err, system.ErrNotExist):
			continue
		}
		refused = append(refused, fact.UnitFragment{
			Path:  p,
			Kind:  fact.FragmentUnit,
			State: StateFor(err),
			Msg:   "this location could not be examined, and a unit file here would replace the one that was read",
		})
	}
	return "", false, refused
}

// applyDropIns layers every drop-in systemd would apply.
func applyDropIns(s system.System, u *Unit, req Request) {
	type candidate struct{ name, path string }

	var winners []candidate
	seenName := make(map[string]string) // basename -> winning path
	seenDir := make(map[[2]uint64]bool) // dev+ino -> already listed

	for _, root := range Roots() {
		dir := path.Join(root, req.Name+".d")

		fi, err := s.Stat(dir)
		if err != nil {
			if errors.Is(err, system.ErrNotExist) {
				continue
			}
			u.Fragments = append(u.Fragments, fact.UnitFragment{
				Path:  dir,
				Kind:  fact.FragmentDropInDir,
				State: StateFor(err),
				Msg:   "the drop-in directory could not be examined, so a drop-in in it may be unaccounted for",
			})
			continue
		}
		if !fi.IsDir {
			continue
		}
		// /lib/systemd/system and /usr/lib/systemd/system are one directory on
		// a usr-merged host. Listing it twice would make every drop-in in it
		// shadow itself, which is harmless for the fold and confusing in the
		// evidence.
		if fi.Ino != 0 {
			key := [2]uint64{fi.Dev, fi.Ino}
			if seenDir[key] {
				continue
			}
			seenDir[key] = true
		}

		res, err := s.ReadDir(dir, MaxDropIns)
		if err != nil {
			u.Fragments = append(u.Fragments, fact.UnitFragment{
				Path:  dir,
				Kind:  fact.FragmentDropInDir,
				State: StateFor(err),
				Msg:   "the drop-in directory could not be listed, so a drop-in in it may be unaccounted for",
			})
			continue
		}
		if res.Truncated {
			u.Fragments = append(u.Fragments, fact.UnitFragment{
				Path:  dir,
				Kind:  fact.FragmentDropInDir,
				State: fact.UnitTruncated,
				Msg:   "the drop-in directory listing hit the entry cap, so nothing may be concluded from what is missing from it",
			})
		}

		for _, e := range res.Entries {
			name := path.Base(e.Path)
			if !strings.HasSuffix(name, ".conf") || e.IsDir {
				continue
			}
			if won, dup := seenName[name]; dup {
				u.Fragments = append(u.Fragments, fact.UnitFragment{
					Path:       e.Path,
					Kind:       fact.FragmentDropIn,
					State:      fact.UnitPresent,
					Shadowed:   true,
					ShadowedBy: won,
					Msg:        "systemd ignores this file: a higher-precedence directory holds a drop-in of the same name",
				})
				continue
			}
			seenName[name] = e.Path
			winners = append(winners, candidate{name: name, path: e.Path})
		}
	}

	// Lexical by filename across all roots, which is systemd's order and not
	// the order the roots were walked in.
	sort.Slice(winners, func(i, j int) bool { return winners[i].name < winners[j].name })

	for _, w := range winners {
		frag, data := readFragment(s, w.path, fact.FragmentDropIn)
		u.Fragments = append(u.Fragments, frag)
		if frag.State != fact.UnitPresent {
			// Recorded and not applied. Unit.Complete is what a caller
			// consults before reading an absence as a fact.
			continue
		}
		u.Directives = append(u.Directives, parse(data, w.path, req)...)
	}
}

// readFragment reads one unit file or drop-in, following symlinks by hand.
//
// The seam opens with O_NOFOLLOW, so a symlinked unit — which is what
// `systemctl link` writes, and what a mask writes — comes back as
// ErrNotRegular rather than as its target. Following it here, one hop at a
// time and back through the seam, is what keeps --root governing where the
// read lands; a seam that resolved links itself would have dereferenced them
// against the real host.
func readFragment(s system.System, p string, kind fact.UnitFragmentKind) (fact.UnitFragment, []byte) {
	f := fact.UnitFragment{Path: p, Kind: kind}

	target := p
	for hop := 0; ; hop++ {
		fi, err := s.Stat(target)
		if err != nil {
			f.State, f.Msg = StateFor(err), errMsg(err)
			return f, nil
		}
		if !fi.IsSymlink {
			if !fi.IsRegular {
				f.State = fact.UnitNotRegular
				f.Msg = "the path is neither a regular file nor a link to one"
				return f, nil
			}
			break
		}
		if hop >= MaxLinkHops {
			f.State = fact.UnitNotRegular
			f.Msg = "the symlink chain is too long to follow, which is a loop or an attempt at one"
			return f, nil
		}

		dest, err := s.Readlink(target)
		if err != nil {
			f.State, f.Msg = StateFor(err), errMsg(err)
			return f, nil
		}
		target = resolveLink(target, dest)
		f.Resolved = target

		// `systemctl mask` replaces the unit with a link to /dev/null, and
		// systemd then refuses to start it at all. Whatever the vendor unit
		// underneath says is not in force, so it must not be read as though it
		// were.
		if target == "/dev/null" {
			f.State = fact.UnitMasked
			f.Msg = "the unit is masked: it is a symbolic link to /dev/null, so systemd will not start it"
			return f, nil
		}
	}

	res, err := s.ReadOpaque(target, MaxRead)
	if err != nil {
		f.State, f.Msg = StateFor(err), errMsg(err)
		return f, nil
	}
	f.Digest = res.SHA256
	if res.Truncated {
		f.State = fact.UnitTruncated
		f.Msg = "the file exceeded the read cap, so directives past the cut were not read"
		return f, res.Data
	}
	if why := collect.NotText(res.Data); why != "" {
		// A regular file that is not text. Not UnitNotRegular: the inode is
		// exactly what it claimed to be, and saying otherwise would send an
		// operator looking for a socket or a directory at the path.
		f.State = fact.UnitError
		f.Msg = why
		return f, nil
	}

	f.State = fact.UnitPresent
	return f, res.Data
}

// resolveLink makes a link target absolute against the link's own directory.
// A relative target read as absolute names a completely different file.
func resolveLink(link, dest string) string {
	if path.IsAbs(dest) {
		return path.Clean(dest)
	}
	return path.Clean(path.Join(path.Dir(link), dest))
}

// StateFor maps a seam error onto the state a fragment should carry.
func StateFor(err error) fact.UnitState {
	switch {
	case errors.Is(err, system.ErrPermission):
		return fact.UnitDenied
	case errors.Is(err, system.ErrNotExist):
		return fact.UnitAbsent
	case errors.Is(err, system.ErrNotRegular), errors.Is(err, system.ErrNotSymlink):
		return fact.UnitNotRegular
	default:
		return fact.UnitError
	}
}

func errMsg(err error) string {
	if errors.Is(err, system.ErrPermission) {
		return "the file exists and could not be read"
	}
	return err.Error()
}

// parse returns the requested directives from one fragment, in file order.
//
// Only req.Section is read, and within it only the names req.Directives lists.
// Everything else is discarded here rather than filtered later, which is what
// keeps an Environment= assignment from existing in memory at all.
func parse(data []byte, origin string, req Request) []Directive {
	var out []Directive

	wanted := make(map[string]bool, len(req.Directives))
	for _, n := range req.Directives {
		wanted[n] = true
	}

	section := ""
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		first := i + 1
		raw := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(raw)

		// A comment continues too, and a continuation of a comment is still a
		// comment. Consuming it here is what stops the second physical line of
		// a commented-out directive from being read as a live one.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			for continues(raw) && i+1 < len(lines) {
				i++
				raw = strings.TrimRight(lines[i], "\r")
			}
			continue
		}

		// Join a continued assignment into one logical line, separated by a
		// single space. The backslash goes and so does the whitespace on
		// either side of it: the value of a scalar directive is the text
		// itself, so "A=real \" + "   continued" has to read as "real
		// continued" rather than carrying the layout of the file into the
		// fact. For a list-valued directive it makes no difference, because
		// the caller splits on whitespace anyway.
		for continues(raw) && i+1 < len(lines) {
			raw = strings.TrimRight(raw, " \t")
			raw = strings.TrimRight(raw[:len(raw)-1], " \t") + " "
			i++
			raw += strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		}

		stmt := strings.TrimSpace(raw)
		if strings.HasPrefix(stmt, "[") && strings.HasSuffix(stmt, "]") {
			section = stmt[1 : len(stmt)-1]
			continue
		}
		if section != req.Section {
			continue
		}
		key, value, ok := strings.Cut(stmt, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !wanted[key] {
			continue
		}
		out = append(out, Directive{
			Name:   key,
			Value:  strings.TrimSpace(value),
			Origin: origin,
			Line:   first,
		})
	}
	return out
}

// continues reports whether a physical line is joined to the next one.
//
// The test counts trailing backslashes rather than looking at the last one,
// because `\\` is an escaped backslash and ends the line, while `\\\` is an
// escaped backslash followed by a continuation.
func continues(s string) bool {
	s = strings.TrimRight(s, " \t\r")
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}
