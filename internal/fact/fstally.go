package fact

import (
	"sort"
	"strings"
)

// FSTallyPrefix is the namespace every aggregating walker fact lives in. A
// tally named "owner_uid" produces the fact "fs.tally.owner_uid".
//
// It is a longer prefix than FSFactPrefix and it deliberately sits *inside*
// it, because a tally is a filesystem observation like any other. The two are
// nonetheless distinct fact IDs carrying distinct Go types, and anything
// resolving a fact ID to a decoder has to test this prefix before the shorter
// one — see internal/bundle.decoderFor. An interest can never collide with a
// tally, because Interest.validate rejects a name containing ".".
const FSTallyPrefix = "fs.tally."

// FSTallyFactID returns the fact ID for a walker tally name.
func FSTallyFactID(tally string) ID { return ID(FSTallyPrefix + tally) }

// FSBucket is one key a tally observed, with how many inodes fell into it and
// one of them by name.
//
// The exemplar is what makes a tally actionable rather than merely numeric.
// "uid 12345 owns 431 inodes" tells an operator there is a problem; "…the
// first of them is /var/lib/oldapp/db.sqlite" tells them where to look. It is
// the first inode in walk order, and walk order is deterministic, so the same
// unchanged host produces the same exemplar every time.
type FSBucket struct {
	Key   uint64 `json:"key"`
	Count int    `json:"count"`
	// Example is the first inode in walk order that fell into this bucket.
	Example FSRow `json:"example"`
}

// FSTally is what one aggregating walker tally observed during the single
// traversal.
//
// It exists because FSMatches cannot answer a question whose subject is
// *every* inode. FSMatches records rows — the first MaxHits inodes satisfying
// a pure predicate — which answers "show me the setuid binaries" and cannot
// answer "does every uid on this filesystem resolve to an account". The second
// question needs a join against a fact that does not exist when the predicate
// is registered, and recording every owned inode so the join could happen
// afterwards would overflow the row cap on any host that has users.
//
// A tally folds instead of recording. Memory is bounded by the number of
// **distinct keys**, not by the number of inodes: the thousandth file owned by
// uid 12345 costs one increment and no allocation. That is the whole trick,
// and it is why a tally can cover a ten-million-inode filesystem inside a
// budget that a row-recording interest would exhaust in its first directory.
//
// The keyspace is still capped, because "distinct uids" is bounded by the
// account database on an honest host and by nothing at all on a hostile one.
// A cap that fires is recorded as truncation, and truncation means the same
// thing here as everywhere else in this package — see Complete.
type FSTally struct {
	// Tally is the registered tally name. FactID is derived from it.
	Tally string `json:"tally"`
	// Roots are the paths the traversal started from, in walk order.
	Roots []string `json:"roots"`
	// Buckets are the keys observed, sorted by key so that two collections of
	// an unchanged host produce byte-identical facts.
	Buckets []FSBucket `json:"buckets"`

	// Truncated means something was not looked at, or some key was not
	// recorded. See Complete.
	Truncated bool `json:"truncated"`
	// TruncationReasons are sorted and deduplicated.
	TruncationReasons []TruncationReason `json:"truncation_reasons,omitempty"`
	// KeysDropped counts distinct keys discarded after the keyspace cap fired.
	// It is the tally's analogue of FSMatches.Overflow and implies Truncated
	// for the same reason: a key that was never recorded may have been the one
	// the check was looking for.
	KeysDropped int `json:"keys_dropped"`

	// InodesTallied is how many inodes this tally actually folded, which is
	// not the same as InodesVisited: a tally whose Key declines an inode never
	// counts it.
	InodesTallied int `json:"inodes_tallied"`
	// InodesVisited is how many inodes the whole traversal examined, shared
	// across every fact the walk produced.
	InodesVisited int `json:"inodes_visited"`
}

func (t FSTally) FactID() ID     { return FSTallyFactID(t.Tally) }
func (FSTally) FactVersion() int { return 1 }

// Complete reports whether absence may be concluded from this tally.
//
// The asymmetric truncation rule, unchanged from FSMatches.Complete: a
// truncated walk can invalidate a negative result and can never invalidate a
// positive one. A key the tally recorded is a key that exists on the
// filesystem, so a check reporting it stands whether or not the walk finished.
// "Every key here resolves to an account" is a claim about keys that were
// never recorded, so over a partial walk it is UNKNOWN, not PASS.
func (t FSTally) Complete() bool { return !t.Truncated && t.KeysDropped == 0 }

// Bucket returns the bucket for key.
func (t FSTally) Bucket(key uint64) (FSBucket, bool) {
	// Buckets are sorted by key, so this is a binary search rather than a
	// scan. A tally may hold thousands of keys and a check asks it once per
	// key it is comparing against.
	n := sort.Search(len(t.Buckets), func(i int) bool { return t.Buckets[i].Key >= key })
	if n < len(t.Buckets) && t.Buckets[n].Key == key {
		return t.Buckets[n], true
	}
	return FSBucket{}, false
}

// Keys returns every key observed, sorted.
func (t FSTally) Keys() []uint64 {
	out := make([]uint64, 0, len(t.Buckets))
	for _, b := range t.Buckets {
		out = append(out, b.Key)
	}
	return out
}

// Total is how many inodes fell into any bucket. It equals InodesTallied on a
// tally that dropped no keys and is smaller on one that did.
func (t FSTally) Total() int {
	n := 0
	for _, b := range t.Buckets {
		n += b.Count
	}
	return n
}

// MarkTruncated records reason, keeping TruncationReasons sorted and unique.
func (t *FSTally) MarkTruncated(reason TruncationReason) {
	t.Truncated = true
	for _, r := range t.TruncationReasons {
		if r == reason {
			return
		}
	}
	t.TruncationReasons = append(t.TruncationReasons, reason)
	sort.Slice(t.TruncationReasons, func(i, j int) bool {
		return t.TruncationReasons[i] < t.TruncationReasons[j]
	})
}

// TruncationSummary renders the reasons for a finding's detail text. It
// returns "" when the tally is complete.
func (t FSTally) TruncationSummary() string {
	if !t.Truncated {
		return ""
	}
	parts := make([]string, 0, len(t.TruncationReasons))
	for _, r := range t.TruncationReasons {
		parts = append(parts, string(r))
	}
	if len(parts) == 0 {
		return "unspecified"
	}
	return strings.Join(parts, ", ")
}
