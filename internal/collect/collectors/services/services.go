// Package services recovers systemd's enablement state from the filesystem.
//
// Plumbline never talks to dbus and never runs systemctl, so "is this service
// enabled" has to be answered from what is on disk. Fortunately that is where
// the answer actually lives: `systemctl enable foo.service` is not a database
// write and sets no flag inside the unit file. It reads the unit's [Install]
// section and creates a symlink
//
//	/etc/systemd/system/multi-user.target.wants/foo.service
//	    -> /usr/lib/systemd/system/foo.service
//
// `disable` removes that symlink, and `mask` replaces the unit file itself
// with a link to /dev/null. Enablement *is* the symlink. Reading the .wants
// and .requires directories recovers exactly the state systemctl would report,
// with no daemon and no privilege.
//
// What this cannot recover, and does not pretend to:
//
//   - Whether a unit is *running*. That is `is-active`, it is a property of
//     the live process table, and no file on disk records it. Nothing in this
//     module claims it.
//   - Whether a *static* unit will be pulled in. A unit with no [Install]
//     section cannot be enabled and has no symlink; it starts because some
//     other unit names it in Wants= or Requires=. Determining that means
//     parsing the whole unit graph, which is a different work package.
//   - What a preset would do at next boot. Presets apply when a package is
//     installed, not at boot, so the symlinks on disk already reflect them.
//
// # Unit bodies, and the rule for reading one
//
// This collector reads no unit file contents at all. Every check built on
// services.units asks whether a unit is enabled and who may edit it, never
// what it runs — and a unit body is operator data. ExecStart is a command
// line, Environment= routinely carries credentials, and collecting either for
// checks that never look at them would put all of it in a travelling bundle.
//
// **systemd.go in this package does read unit bodies**, and so does the
// CONTAINERS collector. That is an exception with a shape rather than an
// abandonment of the rule, and the shape is what makes it safe to have twice:
//
//   - **A named list, never a walk.** fact.SandboxTargets is three units and
//     CONTAINERS reads one. Nothing enumerates the units on the host and opens
//     what it finds, so the bytes read are bounded by a constant in the source
//     rather than by what somebody installed.
//   - **A directive allowlist enforced during the parse.** unit.Assemble is
//     given the names to keep and discards everything else as it goes, so an
//     Environment= assignment is never held in memory, let alone recorded.
//     That is structural: a caller cannot forget to filter, because there is
//     nothing to filter afterwards.
//   - **ReadOpaque, so the bytes are not evidence.** collect.recordingSystem
//     puts everything read through ReadFile into the bundle's evidence store.
//     Unit fragments go through the opaque path instead, so what travels is a
//     digest an auditor reproduces on the host and the handful of directive
//     values a check actually reads.
//   - **Values are recorded only where a check reads them.** The sandboxing
//     fact keeps three enum-ish settings; CONTAINERS keeps a command line and
//     scrubs the log-option values out of it first.
//
// Read in bulk, none of that holds. A collector that opened every unit on the
// host would be carrying every ExecStart and every Environment= on it, and no
// allowlist would help because the point of such a collector is not knowing
// in advance what it will find. docs/PRIVACY.md states the exception in the
// terms a bundle's reader needs.
package services

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "services"

// Search directories, in systemd's own precedence order: highest first.
const (
	AdminDir   = "/etc/systemd/system"
	RuntimeDir = "/run/systemd/system"
	VendorDir  = "/usr/lib/systemd/system"
	// LegacyVendorDir is /lib/systemd/system. On a usr-merged distribution it
	// is the same directory as VendorDir reached through a symlink, and on a
	// pre-merge one it is the only one that exists. Both are probed and the
	// duplicate is detected by inode rather than by guessing which layout the
	// host uses.
	LegacyVendorDir = "/lib/systemd/system"
)

type searchRoot struct {
	path   string
	origin fact.UnitOrigin
}

// roots is every directory probed, in record order. Fixed rather than sorted
// at use, so the fact is deterministic and every detail string built from it
// reads the same way on every run.
func roots() []searchRoot {
	return []searchRoot{
		{AdminDir, fact.OriginAdmin},
		{RuntimeDir, fact.OriginRuntime},
		{VendorDir, fact.OriginVendor},
		{LegacyVendorDir, fact.OriginVendor},
	}
}

// Collector implements collect.Collector for systemd unit enablement.
type Collector struct{}

// New returns the services collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

func (Collector) Produces() []fact.ID { return []fact.ID{fact.ServicesID} }

// DependsOn is nil. Listing directories needs nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone.
//
// Unit directories are world-readable on every distribution — they have to be,
// because systemd --user and every unprivileged `systemctl status` reads them.
// Declaring CapRoot would make an unprivileged scan skip the collector and
// report the whole module as never collected, when in fact it can answer every
// question the module asks. Where a listing genuinely is refused, that one
// directory records DirDenied and only the checks reading it degrade.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap. Four directory listings plus their .wants subdirectories: no
// recursive walk, no file contents, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds. A fat distribution ships some hundreds of unit files
// and a few dozen .wants directories; ten seconds is far beyond what local
// storage needs and short enough that an unresponsive filesystem is recorded
// rather than waited on.
func (Collector) Timeout() time.Duration { return 10 * time.Second }

// maxDirEntries caps a single unit-directory listing.
//
// It is well above what any distribution ships — a fully loaded server is in
// the high hundreds — and far below the seam's global default, because these
// directories are writable by root alone and an entry count in the tens of
// thousands is not a fat install, it is something wrong. Exceeding it sets
// Truncated, which invalidates every conclusion about absence drawn from that
// directory and nothing else.
const maxDirEntries = 5000

// Collect walks the unit directories and records the enablement topology.
//
// It returns nil in every case. There is no failure here that is not itself an
// observation about the host — a directory is present, absent, refused, or
// broken in a way worth recording verbatim — and all four belong in the fact
// rather than in an error that would discard everything gathered beside them.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	sv := fact.Services{}
	seen := map[[2]uint64]string{} // dev+ino -> the path already listed

	for _, r := range roots() {
		// The deadline stopped us. Record what was gathered rather than
		// returning the context error: internal/collect.runner discards the
		// partial facts of a collector that errors while its context is done,
		// which would throw away every directory already listed.
		//nolint:nilerr // error deliberately swallowed for graceful degradation; the records already collected are kept in the FactSet
		if err := ctx.Err(); err != nil {
			finish(&sv)
			fs.Put(sv)
			return nil
		}
		scanRoot(s, r, &sv, seen)
	}

	finish(&sv)
	fs.Put(sv)
	return nil
}

// finish sorts the collected slices and derives Systemd.
func finish(sv *fact.Services) {
	sort.Slice(sv.Units, func(i, j int) bool { return sv.Units[i].Path < sv.Units[j].Path })
	sort.Slice(sv.Links, func(i, j int) bool { return sv.Links[i].Path < sv.Links[j].Path })

	// Systemd is derived rather than probed because there is no single file
	// whose presence means "this host runs systemd" across distributions. A
	// directory we were refused counts as present: we could not read it, but
	// something is there, and treating a refusal as absence would turn an
	// unprivileged scan into a report that the host has no init system.
	for _, d := range sv.Dirs {
		if d.State == fact.DirRead || d.State == fact.DirDenied {
			sv.Systemd = true
			return
		}
	}
}

// scanRoot lists one search directory and everything it implies.
func scanRoot(s system.System, r searchRoot, sv *fact.Services, seen map[[2]uint64]string) {
	rec := fact.SearchDir{Path: r.path, Origin: r.origin}

	fi, err := s.Stat(r.path)
	switch {
	case err == nil:
		rec.Mode, rec.UID, rec.GID = uint32(fi.Mode), fi.UID, fi.GID
	case errors.Is(err, system.ErrNotExist):
		rec.State = fact.DirAbsent
		sv.Dirs = append(sv.Dirs, rec)
		return
	case errors.Is(err, system.ErrPermission):
		rec.State = fact.DirDenied
		rec.Msg = "permission denied; a parent directory refuses traversal"
		sv.Dirs = append(sv.Dirs, rec)
		return
	default:
		rec.State = fact.DirError
		rec.Msg = err.Error()
		sv.Dirs = append(sv.Dirs, rec)
		return
	}

	// /lib/systemd/system and /usr/lib/systemd/system are one directory on a
	// usr-merged host and two on a pre-merge one. Comparing inode identity
	// settles which, rather than hardcoding an assumption about the layout
	// that would double-count every vendor unit on half the distributions in
	// service. Identity of zero means the seam did not record one, in which
	// case the safe move is to list it: a duplicate record is a cosmetic fault
	// and a missed directory is a wrong verdict.
	id := [2]uint64{fi.Dev, fi.Ino}
	if id != [2]uint64{} {
		if first, dup := seen[id]; dup {
			rec.State = fact.DirAlias
			rec.Msg = "the same directory as " + first + "; listed once"
			sv.Dirs = append(sv.Dirs, rec)
			return
		}
		seen[id] = r.path
	}

	listing, err := s.ReadDir(r.path, maxDirEntries)
	if err != nil {
		switch {
		case errors.Is(err, system.ErrPermission):
			rec.State, rec.Msg = fact.DirDenied, "permission denied"
		case errors.Is(err, system.ErrNotExist):
			rec.State = fact.DirAbsent
		default:
			rec.State, rec.Msg = fact.DirError, err.Error()
		}
		sv.Dirs = append(sv.Dirs, rec)
		return
	}
	rec.State, rec.Truncated = fact.DirRead, listing.Truncated
	sv.Dirs = append(sv.Dirs, rec)

	for _, e := range listing.Entries {
		name := path.Base(e.Path)
		switch {
		case e.IsDir && wantsKind(name) != "":
			scanWants(s, e, r.origin, sv)
		case fact.IsUnitName(name):
			sv.Units = append(sv.Units, unitFile(s, e, name, r.origin))
		}
		// Anything else — a README, an editor backup, a .d drop-in directory —
		// is not a unit and systemd ignores it, so it is not recorded. A
		// drop-in changes a unit's behaviour but never its enablement, which
		// is the only question this module asks.
	}
}

// wantsKind classifies a directory name, returning "" when it is neither a
// .wants nor a .requires directory.
func wantsKind(name string) fact.LinkKind {
	switch {
	case strings.HasSuffix(name, ".wants"):
		return fact.LinkWants
	case strings.HasSuffix(name, ".requires"):
		return fact.LinkRequires
	default:
		return ""
	}
}

// scanWants lists one .wants or .requires directory and records its links.
func scanWants(s system.System, dir system.FileInfo, origin fact.UnitOrigin, sv *fact.Services) {
	name := path.Base(dir.Path)
	kind := wantsKind(name)
	target := strings.TrimSuffix(name, "."+string(kind))

	rec := fact.SearchDir{
		Path: dir.Path, Origin: origin,
		Mode: uint32(dir.Mode), UID: dir.UID, GID: dir.GID,
	}

	listing, err := s.ReadDir(dir.Path, maxDirEntries)
	if err != nil {
		switch {
		case errors.Is(err, system.ErrPermission):
			rec.State, rec.Msg = fact.DirDenied, "permission denied"
		case errors.Is(err, system.ErrNotExist):
			rec.State = fact.DirAbsent
		default:
			rec.State, rec.Msg = fact.DirError, err.Error()
		}
		sv.Dirs = append(sv.Dirs, rec)
		return
	}
	rec.State, rec.Truncated = fact.DirRead, listing.Truncated
	sv.Dirs = append(sv.Dirs, rec)

	for _, e := range listing.Entries {
		unit := path.Base(e.Path)
		if !fact.IsUnitName(unit) {
			continue
		}
		sv.Links = append(sv.Links, enablementLink(s, e, unit, target, kind, origin))
	}
}

// enablementLink turns one entry in a .wants directory into a record.
func enablementLink(s system.System, e system.FileInfo, unit, target string, kind fact.LinkKind, origin fact.UnitOrigin) fact.UnitLink {
	l := fact.UnitLink{
		Path: e.Path, Unit: unit, Target: target, Kind: kind, Origin: origin,
	}

	if !e.IsSymlink {
		// A real unit file dropped straight into a .wants directory. systemd
		// accepts it and the unit is enabled; there is no link to follow and
		// nothing to dangle, so the entry resolves to itself.
		l.Dest = ""
		l.Resolved = e.Path
		l.DestState = fact.DestPresent
		return l
	}

	dest, err := s.Readlink(e.Path)
	if err != nil {
		l.DestState = fact.DestUnknown
		l.Msg = "link target could not be read: " + err.Error()
		return l
	}
	l.Dest = dest
	l.Resolved = resolve(e.Path, dest)
	l.DestState, l.Msg = destState(s, l.Resolved)
	return l
}

// resolve makes a link target absolute against the link's own directory.
//
// systemctl always writes an absolute target, but an administrator running
// `ln -s ../foo.service .` does not, and a relative target read as absolute
// names a completely different file. The result stays inside the simulated
// filesystem: it is handed back through the seam, so --root still governs what
// is looked at, which is why the seam does not resolve links itself.
func resolve(link, dest string) string {
	if path.IsAbs(dest) {
		return path.Clean(dest)
	}
	return path.Clean(path.Join(path.Dir(link), dest))
}

// destState says whether a resolved link target exists.
func destState(s system.System, target string) (fact.DestState, string) {
	if _, err := s.Stat(target); err != nil {
		switch {
		case errors.Is(err, system.ErrNotExist):
			return fact.DestDangling, ""
		case errors.Is(err, system.ErrPermission):
			return fact.DestUnknown, "target could not be stat'ed: permission denied"
		default:
			return fact.DestUnknown, "target could not be stat'ed: " + err.Error()
		}
	}
	return fact.DestPresent, ""
}

// unitFile turns one unit-file entry into a record, following it if it is a
// symlink — which is how a mask (a link to /dev/null) and an alias are told
// apart from an ordinary unit file.
func unitFile(s system.System, e system.FileInfo, name string, origin fact.UnitOrigin) fact.UnitFile {
	u := fact.UnitFile{
		Name: name, Path: e.Path, Origin: origin,
		Mode: uint32(e.Mode), UID: e.UID, GID: e.GID,
		IsSymlink: e.IsSymlink,
	}
	if !e.IsSymlink {
		return u
	}
	dest, err := s.Readlink(e.Path)
	if err != nil {
		// A unit file that is a symlink to somewhere we cannot read is not a
		// unit whose state is known: it could be a mask, an alias, or a
		// redirection into a directory somebody else controls.
		u.DestErr = err.Error()
		return u
	}
	u.Dest = dest
	u.DestResolved = resolve(e.Path, dest)
	return u
}
