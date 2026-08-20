package fact

import (
	"path"
	"sort"
	"strings"
)

// MountsID names the mount table fact.
const MountsID ID = "fs.mounts"

// Mount is one entry from the kernel's mount table.
type Mount struct {
	Point  string `json:"point"`
	FSType string `json:"fstype"`

	// Options are this mount's own options — nodev, nosuid, noexec, ro. They
	// are what a bind mount can differ in, and they are what the hardening
	// checks ask about.
	Options []string `json:"options,omitempty"`
	// SuperOpts belong to the filesystem itself and are shared by every mount
	// of it. Kept separate because mountinfo reports them separately and
	// conflating the two answers a different question while looking correct.
	SuperOpts []string `json:"super_opts,omitempty"`
}

// Has reports whether this mount carries a flag option.
func (m Mount) Has(option string) bool {
	for _, o := range m.Options {
		if o == option {
			return true
		}
	}
	return false
}

// Missing returns the named options this mount does not carry, in the order
// asked for so a detail string built from it is stable.
func (m Mount) Missing(options ...string) []string {
	var out []string
	for _, o := range options {
		if !m.Has(o) {
			out = append(out, o)
		}
	}
	return out
}

// Mounts is the kernel's mount table as one fact.
//
// It is produced by the shared filesystem walker rather than by a collector of
// its own, because the walk already reads /proc/self/mountinfo to apply its
// filesystem-type skip list. Two reads of the same kernel table could disagree
// and the disagreement would be invisible; one read, shared, cannot.
type Mounts struct {
	// Entries are in mountinfo order, which is mount order.
	Entries []Mount `json:"entries"`

	// Known is false when the table could not be read or came back truncated.
	//
	// It is the single most important field here. An unknown table must never
	// be treated as an empty one: "/tmp is not a separate mount" and "we could
	// not find out what /tmp is" produce opposite verdicts, and the first is a
	// finding while the second is UNKNOWN. Every check reading this fact gates
	// on it before concluding anything from an absence.
	Known bool `json:"known"`
}

func (Mounts) FactID() ID       { return MountsID }
func (Mounts) FactVersion() int { return 1 }

// At returns the mount at exactly this point.
//
// The last matching entry wins: mountinfo is in mount order, so a path mounted
// over more than once resolves through the most recent one.
func (m Mounts) At(point string) (Mount, bool) {
	want := path.Clean(point)
	var found Mount
	var ok bool
	for _, e := range m.Entries {
		if e.Point == want {
			found, ok = e, true
		}
	}
	return found, ok
}

// Governing returns the mount whose point is the longest prefix of path — the
// filesystem a file at that path actually lives on.
//
// A host where /tmp is not its own mount still has a /tmp, governed by whatever
// / is mounted with. A check that only looked for an exact mount would report
// such a host as having no /tmp at all, when what it has is a /tmp with none of
// the isolation a separate mount provides.
func (m Mounts) Governing(p string) (Mount, bool) {
	want := path.Clean(p)
	var best Mount
	var ok bool
	for _, e := range m.Entries {
		if e.Point == want || strings.HasPrefix(want, strings.TrimSuffix(e.Point, "/")+"/") {
			if !ok || len(e.Point) >= len(best.Point) {
				best, ok = e, true
			}
		}
	}
	return best, ok
}

// Points returns every mount point, sorted, for a finding's evidence.
func (m Mounts) Points() []string {
	out := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		out = append(out, e.Point)
	}
	sort.Strings(out)
	return out
}
