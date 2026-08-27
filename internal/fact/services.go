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

// ---------------------------------------------------------------------------
// services.hardening
// ---------------------------------------------------------------------------

// ServiceHardeningID names the systemd service sandboxing fact.
const ServiceHardeningID ID = "services.hardening"

// SandboxTargets are the units whose sandboxing is read, in record order.
//
// It is a fixed list rather than every unit on the host, and both halves of
// that are deliberate. Reading every unit means reading every unit *body*,
// which is the thing services.units exists in order not to do — a bundle would
// then carry every ExecStart and every Environment= on the machine. A named
// list keeps the exception to that rule small enough to state in
// docs/PRIVACY.md.
//
// The three here are the starting set and not a claim to be the right one.
// They are long-lived root daemons that exist on almost every host, which
// makes them comparable across a fleet; extending the list is a work package
// with a fixture per addition, not a constant to grow casually.
var SandboxTargets = []string{
	"cron.service",
	"systemd-journald.service",
	"dbus.service",
}

// ServiceSandbox is one unit's sandboxing directives, as written.
//
// The fields are a subset chosen for the checks that read them, which is the
// rule every collector in the tree follows: what is not read is not recorded,
// so a unit's ExecStart, its Environment= and everything else in it are absent
// from this fact by construction rather than by filtering afterwards.
type ServiceSandbox struct {
	// Unit is the unit name looked for, e.g. "cron.service".
	Unit string `json:"unit"`
	// State is what became of the unit file. The directive fields below are
	// meaningful only when it is UnitPresent.
	State UnitState `json:"state"`
	// Path is the unit file that won, or where one was looked for when none
	// did.
	Path   string `json:"path,omitempty"`
	Digest string `json:"digest,omitempty"`
	Msg    string `json:"msg,omitempty"`
	// Fragments is every file that contributed or was meant to, in systemd's
	// application order.
	Fragments []UnitFragment `json:"fragments,omitempty"`

	// NoNewPrivileges is the no_new_privs bit, which stops any process in the
	// unit from gaining privileges through a setuid binary or file
	// capabilities — and which, once set, cannot be unset by the process or
	// any of its children.
	//
	// **A pointer, because nil and false are different findings.** Its default
	// is off, so an unset directive and an explicit "no" leave the same
	// posture — but they are different acts, and an operator who wrote
	// NoNewPrivileges=no did so for a reason worth asking about before it is
	// changed. See OptBool.
	NoNewPrivileges *bool `json:"no_new_privileges,omitempty"`

	// ProtectSystem mounts /usr and the boot loader read-only ("yes"), adds
	// /etc ("full"), or makes the whole filesystem read-only except /dev,
	// /proc and /sys ("strict"). Empty means the directive was not set, whose
	// effect is "no", and the value is kept as written because the three
	// levels are not interchangeable.
	ProtectSystem string `json:"protect_system,omitempty"`

	// ProtectHome makes /home, /root and /run/user inaccessible ("yes"),
	// read-only ("read-only"), or replaces them with empty tmpfs mounts
	// ("tmpfs"). Empty means unset, whose effect is "no".
	ProtectHome string `json:"protect_home,omitempty"`

	// Malformed names the directives whose values systemd would refuse to
	// parse, e.g. NoNewPrivileges=maybe.
	//
	// It is recorded because systemd's response is to log a warning and
	// *ignore the assignment*, leaving the previous value or the default in
	// force — so the effective posture is the unhardened one while the file
	// says otherwise. An operator reading "NoNewPrivileges is not set" about a
	// unit where they can see the line needs to be told which of the two is
	// true. Names only: a value systemd rejected is still operator text.
	Malformed []string `json:"malformed,omitempty"`
}

// Judgeable reports whether the directive fields may be read as the unit's
// configuration.
func (s ServiceSandbox) Judgeable() bool { return s.State == UnitPresent }

// Installed reports whether the unit exists on this host at all.
//
// Masked counts as installed and is deliberately not judgeable: the unit file
// is there, systemd refuses to start it, and its sandboxing is not a statement
// about anything running.
func (s ServiceSandbox) Installed() bool { return s.State != UnitAbsent }

// Incomplete returns the fragments that were not read, shadowed ones excluded.
func (s ServiceSandbox) Incomplete() []UnitFragment {
	return IncompleteFragments(s.Fragments)
}

// ServiceHardening is the sandboxing of the units in SandboxTargets.
//
// It is a separate fact from services.units, which records enablement and
// reads no unit bodies at all. The split is what keeps that promise legible:
// one fact is built from symlinks and directory listings, the other opens a
// named handful of unit files and keeps three directives out of them.
type ServiceHardening struct {
	// Systemd reports whether any unit directory exists. When false the checks
	// are NOT_APPLICABLE: "cron.service does not set NoNewPrivileges" is not a
	// sentence about a host running OpenRC.
	Systemd bool `json:"systemd"`
	// Services are the units looked for, in SandboxTargets order, including
	// the ones that are not installed.
	Services []ServiceSandbox `json:"services"`
}

func (ServiceHardening) FactID() ID       { return ServiceHardeningID }
func (ServiceHardening) FactVersion() int { return 1 }

// Installed returns the units that exist on this host.
func (h ServiceHardening) Installed() []ServiceSandbox {
	var out []ServiceSandbox
	for _, s := range h.Services {
		if s.Installed() {
			out = append(out, s)
		}
	}
	return out
}

// Judgeable returns the units whose directives may be read.
func (h ServiceHardening) Judgeable() []ServiceSandbox {
	var out []ServiceSandbox
	for _, s := range h.Services {
		if s.Judgeable() {
			out = append(out, s)
		}
	}
	return out
}

// Unreadable returns the units that are installed and could not be read in
// full — the unit file itself, or a drop-in beside it.
//
// Masked units are excluded: systemd will not start one, so what its file says
// is not a gap in this scan's knowledge of the host.
func (h ServiceHardening) Unreadable() []ServiceSandbox {
	var out []ServiceSandbox
	for _, s := range h.Services {
		if !s.Installed() || s.State == UnitMasked {
			continue
		}
		if s.State != UnitPresent || len(s.Incomplete()) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// ParseSystemdBool reads a systemd boolean, returning the value and whether it
// parsed.
//
// It is systemd's own grammar from parse_boolean(3), which is wider than the
// yes/no most documentation shows and is not uniformly case-insensitive:
//
//	true:  1  yes  y  true  t  on
//	false: 0  no   n  false f  off
//
// **"1" and "0" are compared exactly and every word is compared
// case-insensitively**, which is what systemd does and is the sort of asymmetry
// a re-implementation invents a rule for. Writing our own — folding everything,
// or accepting only yes/no — would mean disagreeing with the host about what
// its own configuration says, in one direction or the other, on the units
// where somebody wrote "True".
//
// Anything else does not parse, and **is emphatically not false**. systemd logs
// a warning and *ignores the assignment*, leaving the previous value or the
// compiled-in default in force, so a unit whose only NoNewPrivileges= line
// reads "maybe" is running with the setting off while its file appears to say
// otherwise.
//
// It lives here rather than in the collector because a check may not import a
// collector package — the purity rule in CONTRIBUTING.md — and both sides need
// it: the collector to record an effective value, and SERVICES-0007 to read
// the boolean half of ProtectSystem's grammar. One grammar, one
// implementation.
func ParseSystemdBool(v string) (value, ok bool) {
	switch v {
	case "1":
		return true, true
	case "0":
		return false, true
	}
	switch asciiLower(v) {
	case "yes", "y", "true", "t", "on":
		return true, true
	case "no", "n", "false", "f", "off":
		return false, true
	}
	return false, false
}

// asciiLower folds ASCII only. systemd compares with strcaseeq, which is
// locale-independent ASCII folding; unicode's would differ on a Turkish locale
// for exactly the letters "t" and "on" contain.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// ProtectSystemLevel is the effective ProtectSystem setting, as systemd
// resolves it.
//
// The four levels are cumulative and are not interchangeable, which is why the
// fact records the value as written and this reads it rather than the other way
// round.
type ProtectSystemLevel string

const (
	// ProtectNo is the default: the service may write anywhere its
	// credentials allow.
	ProtectNo ProtectSystemLevel = "no"
	// ProtectYes mounts /usr and the boot loader directories read-only.
	ProtectYes ProtectSystemLevel = "yes"
	// ProtectFull adds /etc, so a compromised daemon cannot rewrite the
	// host's configuration either.
	ProtectFull ProtectSystemLevel = "full"
	// ProtectStrict makes the whole filesystem hierarchy read-only apart from
	// /dev, /proc and /sys, and is what a daemon with an explicit
	// ReadWritePaths list should use.
	ProtectStrict ProtectSystemLevel = "strict"
)

// ParseProtectSystem reads a ProtectSystem value, returning the level and
// whether it parsed.
//
// **The grammar is a superset of the booleans**, and in systemd's own order:
// it tries parse_boolean first and falls back to the enum, so "true", "1" and
// "on" are all ProtectYes and "off" is ProtectNo. A build that accepted only
// yes/no/full/strict would report a host that wrote "ProtectSystem=true" as
// having set nothing — a failure against a service that is in fact protected.
func ParseProtectSystem(v string) (ProtectSystemLevel, bool) {
	if on, ok := ParseSystemdBool(v); ok {
		if on {
			return ProtectYes, true
		}
		return ProtectNo, true
	}
	switch asciiLower(v) {
	case "full":
		return ProtectFull, true
	case "strict":
		return ProtectStrict, true
	}
	return ProtectNo, false
}

// SystemProtection returns the effective ProtectSystem level for a unit.
//
// An unset directive is ProtectNo, which is systemd's default and the whole
// reason this check exists: a service that says nothing may write to /usr.
//
// The reading lives on the fact rather than in the collector so that a bundle
// recorded today is re-read by a later build's understanding of the grammar,
// which is the promise DATA-MODEL.md §6.1 makes. The collector records what the
// file said; this decides what it means.
func (s ServiceSandbox) SystemProtection() ProtectSystemLevel {
	if s.ProtectSystem == "" {
		return ProtectNo
	}
	level, _ := ParseProtectSystem(s.ProtectSystem)
	return level
}

// Protected reports whether the unit's ProtectSystem is at least ProtectYes,
// which is SERVICES-0007's bar.
func (s ServiceSandbox) Protected() bool { return s.SystemProtection() != ProtectNo }
