package fact

import (
	"io/fs"
	"sort"
	"strings"
)

// FSFactPrefix is the namespace every shared-walker fact lives in. An interest
// named "suid" produces the fact "fs.suid".
const FSFactPrefix = "fs."

// FSFactID returns the fact ID for a walker interest name.
//
// One fact per interest rather than one fact holding every match, because a
// check requiring fs.suid must not resolve to UNKNOWN merely because an
// unrelated interest overflowed its cap. Facts are the unit of ignorance in
// this design, so they have to be the unit of truncation too.
func FSFactID(interest string) ID { return ID(FSFactPrefix + interest) }

// TruncationReason names why a walk stopped short. It is recorded rather than
// summarised because "we ran out of time" and "we ran out of inodes" lead an
// operator to different remedies, and a check that reports UNKNOWN has to be
// able to say which one it was.
type TruncationReason string

const (
	// TruncDepth means the walk refused to descend past its depth limit.
	TruncDepth TruncationReason = "depth_limit"
	// TruncInodes means the walk reached its global inode budget.
	TruncInodes TruncationReason = "inode_limit"
	// TruncDeadline means the walk ran out of wall-clock budget, either its
	// own or the collector context's.
	TruncDeadline TruncationReason = "wall_clock"
	// TruncDirListing means a directory listing came back incomplete: the
	// seam's entry cap fired, or an entry could not be stat'ed. Either way
	// something in that directory was never seen.
	TruncDirListing TruncationReason = "dir_listing"
	// TruncUnreadable means a directory could not be opened at all —
	// typically permission denied on an unprivileged scan.
	TruncUnreadable TruncationReason = "unreadable_dir"
	// TruncMountsUnknown means the mount table could not be read, so the
	// fstype skip list could not be applied. It is only recorded when the walk
	// was permitted to cross filesystem boundaries; without that permission the
	// device check alone keeps the walk on one filesystem.
	TruncMountsUnknown TruncationReason = "mounts_unknown"
	// TruncMaxHits means this interest hit its own MaxHits cap. Unlike the
	// others it is per-interest: it truncates one fact and leaves the rest of
	// the walk, and every other fact, complete.
	TruncMaxHits TruncationReason = "max_hits"
	// TruncMaxKeys means an aggregating tally reached its keyspace cap and
	// discarded a key it had never seen before. Like TruncMaxHits it is
	// per-fact rather than per-walk.
	//
	// It is a separate reason from TruncMaxHits because the two mean opposite
	// things about how much was examined. A row cap means the walk stopped
	// *recording* after N matches; a key cap means the walk kept counting
	// every inode it met and only stopped admitting new buckets. An operator
	// raising the wrong limit fixes neither.
	TruncMaxKeys TruncationReason = "max_keys"
)

// FSRow is one inode a walker interest matched.
//
// It is a trimmed copy of system.FileInfo rather than the type itself, because
// a check may not import internal/system (CLAUDE.md rule 2) and would
// therefore have no way to read a field typed from that package. Everything
// here is plain data that survives a bundle round trip.
type FSRow struct {
	Path      string      `json:"path"`
	Mode      fs.FileMode `json:"mode"`
	UID       uint32      `json:"uid"`
	GID       uint32      `json:"gid"`
	Size      int64       `json:"size"`
	IsDir     bool        `json:"is_dir"`
	IsRegular bool        `json:"is_regular"`
	IsSymlink bool        `json:"is_symlink"`
}

// FSMatches is what one walker interest observed during the single traversal.
//
// The type is generic over interests on purpose: FactID is derived from
// Interest, so fs.suid and fs.world_writable are the same Go type carrying
// different names. A module gets a new fact by registering a new interest, not
// by writing a new fact type.
type FSMatches struct {
	// Interest is the registered interest name. FactID is derived from it.
	Interest string `json:"interest"`
	// Roots are the paths the traversal started from, in walk order.
	Roots []string `json:"roots"`
	// Rows are the matches, sorted by path so that two collections of an
	// unchanged host produce byte-identical facts.
	Rows []FSRow `json:"rows"`

	// Truncated means something was not looked at. It is the entire point of
	// this type: see Complete for the rule that governs what a check may
	// conclude from it.
	Truncated bool `json:"truncated"`
	// TruncationReasons are sorted and deduplicated.
	TruncationReasons []TruncationReason `json:"truncation_reasons,omitempty"`
	// Overflow counts matches this interest discarded after reaching MaxHits.
	// Overflow > 0 always implies Truncated: the cap is a limit on what was
	// recorded, and a recorded absence beyond it means nothing.
	Overflow int `json:"overflow"`

	// InodesVisited is how many inodes the whole traversal examined, not how
	// many this interest matched. It is shared across every fact the walk
	// produced and is what proves the tree was visited once.
	InodesVisited int `json:"inodes_visited"`
}

func (m FSMatches) FactID() ID     { return FSFactID(m.Interest) }
func (FSMatches) FactVersion() int { return 1 }

// Complete reports whether absence may be concluded from this fact.
//
// This is the asymmetric truncation rule, mechanised so that a check cannot
// forget it (BUILD-RUNBOOK-v0.2.md, WP-15):
//
//	A truncated walk can invalidate a negative result. It can never
//	invalidate a positive one.
//
// A SUID binary the walk found is a SUID binary that exists, so a check
// reporting it returns FAIL whether or not the walk finished — Rows is always
// trustworthy. "There are no SUID binaries outside the allowlist" is a claim
// about everything that was never examined, so over a partial walk it is not
// PASS but UNKNOWN(source_truncated).
//
// A check asserting absence must therefore gate on Complete before it may
// return PASS. Returning PASS from a partial walk converts "we stopped
// looking" into "there is nothing there", which is the single failure mode
// this project exists to prevent.
func (m FSMatches) Complete() bool { return !m.Truncated && m.Overflow == 0 }

// MarkTruncated records reason, keeping TruncationReasons sorted and unique.
func (m *FSMatches) MarkTruncated(reason TruncationReason) {
	m.Truncated = true
	for _, r := range m.TruncationReasons {
		if r == reason {
			return
		}
	}
	m.TruncationReasons = append(m.TruncationReasons, reason)
	sort.Slice(m.TruncationReasons, func(i, j int) bool {
		return m.TruncationReasons[i] < m.TruncationReasons[j]
	})
}

// TruncationSummary renders the reasons for a finding's detail text. It
// returns "" when the fact is complete.
func (m FSMatches) TruncationSummary() string {
	if !m.Truncated {
		return ""
	}
	parts := make([]string, 0, len(m.TruncationReasons))
	for _, r := range m.TruncationReasons {
		parts = append(parts, string(r))
	}
	if len(parts) == 0 {
		return "unspecified"
	}
	return strings.Join(parts, ", ")
}
