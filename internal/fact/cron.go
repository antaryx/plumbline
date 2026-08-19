package fact

import (
	"io/fs"
	"sort"
)

// CronID names the cron file-metadata fact.
const CronID ID = "cron.files"

// CronPathState is what the collector was able to observe about one path.
//
// The four states exist because a check has to tell them apart. "The file is
// not there" and "we were not allowed to look" produce opposite verdicts —
// NOT_APPLICABLE or FAIL for the first, UNKNOWN for the second — and a single
// boolean would have collapsed them into a guess.
type CronPathState string

const (
	// CronObserved: the path exists and its metadata was read.
	CronObserved CronPathState = "observed"
	// CronAbsent: the path does not exist. For cron.allow this is itself the
	// finding; for /etc/crontab it usually means cron is not installed.
	CronAbsent CronPathState = "absent"
	// CronDenied: the path could not be stat'ed for want of privilege. Nothing
	// may be concluded about its mode or its owner.
	CronDenied CronPathState = "denied"
	// CronError: the stat failed for a reason worth recording verbatim.
	CronError CronPathState = "error"
)

// CronPath is one path's ownership and permissions.
//
// Mode is the whole fs.FileMode, type bits included, because a check that
// asserts "/etc/cron.d is a directory owned by root" needs to know it is still
// a directory. A symlink where a directory is expected is a redirection an
// attacker controls, and it is invisible if only the permission bits survive.
type CronPath struct {
	Path  string        `json:"path"`
	State CronPathState `json:"state"`

	Mode fs.FileMode `json:"mode,omitempty"`
	// UID and GID are the numeric owner. They are meaningful only when State
	// is CronObserved: uid 0 is a legitimate value, so it cannot double as
	// "not recorded", and a check must gate on State before reading them.
	// See docs/adr/0016-fileinfo-ownership-seam.md.
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`

	IsDir     bool `json:"is_dir,omitempty"`
	IsRegular bool `json:"is_regular,omitempty"`
	IsSymlink bool `json:"is_symlink,omitempty"`

	// Msg carries the reason for CronDenied or CronError.
	Msg string `json:"msg,omitempty"`
}

// Perm returns the permission bits alone.
func (p CronPath) Perm() fs.FileMode { return p.Mode.Perm() }

// GroupOrOtherWritable reports whether anyone but the owner may write the path.
//
// This is the proposition the escalation checks rest on. A cron file or drop-in
// directory that a non-root account can write is arbitrary code execution as
// root on a schedule, which is why it outranks every other property here.
func (p CronPath) GroupOrOtherWritable() bool { return p.Mode.Perm()&0o022 != 0 }

// GroupOrOtherReadable reports whether anyone but the owner may read the path.
func (p CronPath) GroupOrOtherReadable() bool { return p.Mode.Perm()&0o044 != 0 }

// RootOwned reports whether the path is owned by uid 0 and gid 0.
func (p CronPath) RootOwned() bool { return p.UID == 0 && p.GID == 0 }

// Cron is the collected metadata for the system cron paths.
//
// It carries no file *contents*. Nothing in this module reads a crontab: the
// checks here are about who may write the schedule, not about what the schedule
// says. A crontab's contents are operator data — command lines, paths, and
// often credentials passed as arguments — and collecting them would put all of
// that into a bundle for a set of checks that do not read it.
type Cron struct {
	// Paths are in the collector's declared order, which is fixed, so the fact
	// is deterministic without anything downstream having to sort. A slice
	// rather than a map for the same reason: ranging over a map is randomised,
	// and a check that forgot to sort would produce a different detail string
	// on every run.
	Paths []CronPath `json:"paths"`

	// Installed reports whether any of the standard cron paths exists at all.
	// When false the module's checks are NOT_APPLICABLE rather than FAIL:
	// a host with no cron has not satisfied "the crontab is owned by root", it
	// has removed the subject of the sentence.
	Installed bool `json:"installed"`
}

func (Cron) FactID() ID       { return CronID }
func (Cron) FactVersion() int { return 1 }

// Get returns one path's record.
func (c Cron) Get(path string) (CronPath, bool) {
	for _, p := range c.Paths {
		if p.Path == path {
			return p, true
		}
	}
	return CronPath{}, false
}

// Select returns the records for the named paths, in the order asked for,
// skipping any the collector did not probe.
func (c Cron) Select(paths ...string) []CronPath {
	out := make([]CronPath, 0, len(paths))
	for _, want := range paths {
		if p, ok := c.Get(want); ok {
			out = append(out, p)
		}
	}
	return out
}

// Unreadable returns the records the collector could not stat, sorted by path.
//
// A check calls this before drawing any negative conclusion: a path whose
// metadata was refused could be the one violating the rule, and reporting PASS
// over the paths that happened to be readable is the false assurance CLAUDE.md
// rule 3 forbids.
func (c Cron) Unreadable(paths ...CronPath) []CronPath {
	var out []CronPath
	for _, p := range paths {
		if p.State == CronDenied || p.State == CronError {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
