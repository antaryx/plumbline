package fact

import (
	"sort"
	"strings"
)

// ServicesID names the systemd unit-enablement fact.
const ServicesID ID = "services.units"

// UnitSuffixes are the unit types this module records. A path that does not
// end in one of them is not a unit and is ignored, which is what keeps a
// README or a backup file in /etc/systemd/system out of the fact.
var UnitSuffixes = []string{
	".service", ".socket", ".timer", ".target",
	".path", ".mount", ".automount", ".slice", ".swap",
}

// IsUnitName reports whether a filename names a systemd unit.
func IsUnitName(name string) bool {
	for _, suf := range UnitSuffixes {
		if strings.HasSuffix(name, suf) && len(name) > len(suf) {
			return true
		}
	}
	return false
}

// UnitOrigin says which of systemd's three unit trees a record came from.
//
// The order is systemd's own precedence, highest first: an admin unit file in
// /etc shadows a runtime one in /run, which shadows the vendor's in /usr/lib.
// It is the whole mechanism behind masking — /etc/systemd/system/foo.service
// pointing at /dev/null is how an administrator overrides a vendor unit they
// cannot delete — so a record that did not say where it was found could not
// answer whether one file wins over another.
type UnitOrigin string

const (
	// OriginAdmin is /etc/systemd/system: what an administrator configured.
	OriginAdmin UnitOrigin = "admin"
	// OriginRuntime is /run/systemd/system: transient, gone at reboot.
	OriginRuntime UnitOrigin = "runtime"
	// OriginVendor is /usr/lib/systemd/system (or /lib): what a package shipped.
	OriginVendor UnitOrigin = "vendor"
)

// DirState is what the collector was able to observe about one search
// directory. It exists for the reason CronPathState does: "the directory is
// not there" and "we were not allowed to look" produce opposite verdicts, and
// a boolean would have collapsed them into a guess.
type DirState string

const (
	// DirRead: listed successfully.
	DirRead DirState = "read"
	// DirAbsent: does not exist. For /etc/systemd/system this usually means
	// the host does not run systemd at all.
	DirAbsent DirState = "absent"
	// DirDenied: permission denied. Nothing may be concluded about its
	// contents, and in particular nothing may be concluded about *absence*.
	DirDenied DirState = "denied"
	// DirError: the listing failed for a reason worth recording verbatim.
	DirError DirState = "error"
	// DirAlias: this path is the same directory as one already listed, proved
	// by inode identity rather than assumed. /lib/systemd/system and
	// /usr/lib/systemd/system are one directory on a usr-merged host and two
	// on a pre-merge one; recording the duplicate rather than dropping it
	// keeps the fact honest about what was probed, and keeps every unit under
	// it from being counted twice.
	DirAlias DirState = "alias"
)

// SearchDir is one directory the collector looked in.
//
// Truncated is carried separately from State because a listing that was cut
// short was still read: everything it returned is true, and only conclusions
// about what is *not* there are invalidated. That asymmetry is ADR-0014, and
// it is why a check consults Incomplete before drawing a negative conclusion
// and never before drawing a positive one.
type SearchDir struct {
	Path      string     `json:"path"`
	Origin    UnitOrigin `json:"origin"`
	State     DirState   `json:"state"`
	Truncated bool       `json:"truncated,omitempty"`
	Msg       string     `json:"msg,omitempty"`

	// Mode, UID and GID are meaningful only when State is DirRead. See
	// ADR-0016: uid 0 is a legitimate value, so it cannot double as "not
	// recorded", and a check must gate on State before reading them.
	Mode uint32 `json:"mode,omitempty"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}

// Usable reports whether this directory's listing may be relied on to say that
// something is absent from it.
func (d SearchDir) Usable() bool { return d.State == DirRead && !d.Truncated }

// UnitFile is a unit file found in one of the search directories.
//
// It carries no file *contents*. Every check in this module asks whether a
// unit is enabled and who may edit it, not what it runs. A unit file's body is
// operator data — ExecStart command lines, Environment= assignments that
// routinely hold credentials — and collecting it would put all of that into a
// bundle designed to travel, for checks that never read it. The same reasoning
// as ADR-0015 and the CRON collector.
type UnitFile struct {
	Name   string     `json:"name"` // "sshd.service"
	Path   string     `json:"path"` // "/usr/lib/systemd/system/sshd.service"
	Origin UnitOrigin `json:"origin"`

	// Mode, UID and GID are meaningful only because the entry was observed:
	// it came out of a directory listing that succeeded. See ADR-0016 — uid 0
	// is a legitimate value and cannot double as "not recorded", which is why
	// nothing here is populated from a failed stat.
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`

	// Dest is the link target as written, for a unit file that is itself a
	// symlink. Empty when the entry is a regular file.
	Dest string `json:"dest,omitempty"`
	// DestResolved is Dest made absolute against the unit file's own
	// directory. Masking is decided from this rather than from Dest, because a
	// link written by hand as ../../../dev/null is the same mask systemctl
	// writes as /dev/null and must not read as an ordinary unit file.
	DestResolved string `json:"dest_resolved,omitempty"`
	// DestErr records why Dest could not be read, when the entry is a symlink
	// and Readlink failed. A symlink whose target is unknown is not a unit
	// whose state is known.
	DestErr string `json:"dest_err,omitempty"`
	// IsSymlink distinguishes a mask or an alias from a real unit file.
	IsSymlink bool `json:"is_symlink,omitempty"`
}

// Masked reports whether this unit file is the /dev/null override systemd
// calls a mask.
//
// Masking is absolute in a way disabling is not: a masked unit cannot be
// started by anything, including another unit that Requires= it, and including
// an administrator typing systemctl start. That is why it outranks an
// enablement symlink rather than merely competing with one.
func (u UnitFile) Masked() bool { return u.IsSymlink && u.DestResolved == "/dev/null" }

// LinkKind is which dependency a .wants or .requires directory expresses.
type LinkKind string

const (
	// LinkWants is a .wants directory: a soft dependency. The target starts
	// the unit, and carries on if it fails.
	LinkWants LinkKind = "wants"
	// LinkRequires is a .requires directory: a hard dependency. If the unit
	// fails, the target fails with it.
	LinkRequires LinkKind = "requires"
)

// UnitLink is one enablement symlink.
//
// This is what `systemctl enable` actually does, and it is the only durable
// on-disk record that an administrator turned a service on. There is no
// database and no flag inside the unit file: enablement *is* a symlink from
// <target>.wants/ to the unit, and reading those directories is how the state
// is recovered without dbus.
type UnitLink struct {
	// Path is the link itself,
	// e.g. /etc/systemd/system/multi-user.target.wants/telnet.socket.
	Path string `json:"path"`
	// Unit is the link's filename, which is the unit being enabled.
	Unit string `json:"unit"`
	// Target is the unit the dependency was installed into, derived from the
	// directory name: "multi-user.target" from "multi-user.target.wants".
	Target string     `json:"target"`
	Kind   LinkKind   `json:"kind"`
	Origin UnitOrigin `json:"origin"`

	// Dest is the target as written — absolute on anything systemctl created,
	// possibly relative on something an administrator made by hand.
	Dest string `json:"dest,omitempty"`
	// Resolved is Dest made absolute against the link's own directory. It is
	// the path to check for existence, and it is computed in the collector
	// because a check may not know what a path separator is.
	Resolved string `json:"resolved,omitempty"`
	// DestState says whether Resolved names a unit file that exists.
	DestState DestState `json:"dest_state"`
	// Msg carries the reason for a DestUnknown.
	Msg string `json:"msg,omitempty"`
}

// DestState is what the collector found at the other end of an enablement
// symlink.
type DestState string

const (
	// DestPresent: the link resolves to a file that exists.
	DestPresent DestState = "present"
	// DestDangling: the link resolves to nothing. systemd logs "Unit not
	// found" at boot and carries on; the operator believes the service is
	// enabled and it never starts.
	DestDangling DestState = "dangling"
	// DestUnknown: the link's target could not be read, or the path it names
	// could not be stat'ed. Nothing may be concluded about it either way.
	DestUnknown DestState = "unknown"
)

// UnitStatus is the resolved enablement state of one unit name.
//
// Four states, and the distinction between the last two matters: "installed
// but not enabled" and "not installed at all" both mean the unit will not
// start, but they are different remediations and different amounts of attack
// surface, and only one of them is stable across a package upgrade.
type UnitStatus string

const (
	// StatusEnabled: an enablement symlink exists and nothing masks the unit.
	StatusEnabled UnitStatus = "enabled"
	// StatusMasked: the highest-precedence unit file points at /dev/null. The
	// unit cannot be started by anything, enablement symlink or not.
	StatusMasked UnitStatus = "masked"
	// StatusNotEnabled: a unit file exists but no enablement symlink does.
	StatusNotEnabled UnitStatus = "not-enabled"
	// StatusAbsent: neither a unit file nor an enablement symlink was found.
	// The software is not installed.
	StatusAbsent UnitStatus = "absent"
)

// Services is the collected systemd enablement topology.
type Services struct {
	// Dirs are every directory probed, in the collector's fixed order, so the
	// fact is deterministic without anything downstream having to sort.
	Dirs []SearchDir `json:"dirs"`
	// Units are the unit files found, sorted by path.
	Units []UnitFile `json:"units"`
	// Links are the enablement symlinks found, sorted by path.
	Links []UnitLink `json:"links"`

	// Systemd reports whether any unit directory exists at all. When false the
	// module's checks are NOT_APPLICABLE: "telnet.socket is not enabled" is
	// not a sentence about a host running OpenRC or SysVinit, it is a sentence
	// with no subject. A directory we were refused counts as present — we
	// could not read it, but something is there.
	Systemd bool `json:"systemd"`
}

func (Services) FactID() ID       { return ServicesID }
func (Services) FactVersion() int { return 1 }

// UnitFiles returns every unit file recorded for one unit name, in precedence
// order: admin, then runtime, then vendor.
func (s Services) UnitFiles(name string) []UnitFile {
	var out []UnitFile
	for _, u := range s.Units {
		if u.Name == name {
			out = append(out, u)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return originRank(out[i].Origin) < originRank(out[j].Origin)
	})
	return out
}

func originRank(o UnitOrigin) int {
	switch o {
	case OriginAdmin:
		return 0
	case OriginRuntime:
		return 1
	default:
		return 2
	}
}

// Effective returns the unit file systemd would actually load for a name: the
// one from the highest-precedence directory it appears in.
func (s Services) Effective(name string) (UnitFile, bool) {
	files := s.UnitFiles(name)
	if len(files) == 0 {
		return UnitFile{}, false
	}
	return files[0], true
}

// LinksTo returns the enablement symlinks naming one unit, sorted by path.
func (s Services) LinksTo(name string) []UnitLink {
	var out []UnitLink
	for _, l := range s.Links {
		if l.Unit == name {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Status resolves one unit name to its enablement state.
//
// Masking is tested before enablement, not after, because that is systemd's
// own order: a masked unit does not start even with a .wants symlink pointing
// at it, and reporting "enabled" for a unit that cannot run would be a wrong
// verdict in the direction that matters — a live service where there is none.
func (s Services) Status(name string) UnitStatus {
	if u, ok := s.Effective(name); ok && u.Masked() {
		return StatusMasked
	}
	if len(s.LinksTo(name)) > 0 {
		return StatusEnabled
	}
	if _, ok := s.Effective(name); ok {
		return StatusNotEnabled
	}
	return StatusAbsent
}

// AnyEnabled returns the names, from the set given, whose status is enabled.
// Order follows the argument list so a detail string built from it is stable.
func (s Services) AnyEnabled(names ...string) []string {
	var out []string
	for _, n := range names {
		if s.Status(n) == StatusEnabled {
			out = append(out, n)
		}
	}
	return out
}

// Incomplete returns the search directories whose listing may not be relied on
// to prove that a unit is absent, sorted by path.
//
// A check calls this before concluding that nothing is enabled, and never
// before concluding that something is. That asymmetry is the whole of
// ADR-0014: a directory we could not read might hold the enablement symlink
// that decides the verdict, but it cannot unmake one we already found.
func (s Services) Incomplete() []SearchDir {
	var out []SearchDir
	for _, d := range s.Dirs {
		if d.State == DirDenied || d.State == DirError || d.Truncated {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Complete reports whether every directory probed was fully listed.
func (s Services) Complete() bool { return len(s.Incomplete()) == 0 }

// Dangling returns the enablement symlinks that resolve to nothing, sorted by
// path.
func (s Services) Dangling() []UnitLink {
	var out []UnitLink
	for _, l := range s.Links {
		if l.DestState == DestDangling {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Unresolved returns the enablement symlinks whose target could not be read,
// sorted by path. They are the reason a Dangling()-based PASS may be UNKNOWN.
func (s Services) Unresolved() []UnitLink {
	var out []UnitLink
	for _, l := range s.Links {
		if l.DestState == DestUnknown {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
