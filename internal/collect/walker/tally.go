package walker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// DefaultMaxKeys caps the distinct keys one tally may hold when it does not
// set its own.
//
// The number is chosen from the memory arithmetic rather than from taste. A
// bucket costs its key, its count and one exemplar row — call it 200 bytes
// with the path — so 16,384 keys is about 3 MB, which is the same order as the
// 20,000 rows DefaultMaxHits already permits one interest. The difference is
// what that budget buys: an interest's 20,000 rows cover the first 20,000
// matching inodes and nothing after them, while a tally's 16,384 keys cover
// **every inode on the filesystem**, because the ten-millionth file owned by a
// known uid costs one increment and no allocation.
//
// 16,384 distinct owners is more than any host has accounts. A host that
// exceeds it is either enormous and directory-joined — in which case the local
// files were never the whole answer anyway — or is generating owners, which is
// itself worth knowing and is what the truncation marker says.
const DefaultMaxKeys = 16_384

// Tally is one consumer's standing *aggregate* question about the filesystem,
// registered before the walk and folded during it.
//
// It is the second kind of interest, and it exists because the first kind
// cannot answer a question whose subject is every inode. An Interest records
// rows: which inodes matched a pure predicate, up to a cap. That answers "show
// me the setuid binaries". It cannot answer "does every uid on disk resolve to
// an account", for two independent reasons:
//
//   - Match is pure and is evaluated at registration time, before any fact
//     exists, so it cannot join against /etc/passwd; and
//   - deferring the join by recording every owned inode would overflow the row
//     cap in the first populated directory of any host that has users.
//
// A Tally folds rather than records. It maps each inode to a key, counts the
// keys, keeps one exemplar per key, and hands the check a bounded structure it
// can join against facts that exist by then. The join happens where facts
// live; the walk stays a walk.
type Tally struct {
	// Name is the fact suffix this tally produces: "owner_uid" becomes
	// fs.tally.owner_uid.
	Name string

	// Key buckets one inode, and reports whether this tally counts it at all.
	//
	// It must be pure and it must be fast, for the reason Interest.Match must
	// be: it runs once per inode per tally on a filesystem that may hold ten
	// million of them. It sees every inode the walk reaches, including
	// symlinks, FIFOs, sockets and device nodes — a symlink owned by a uid
	// that resolves to nothing is exactly as much of a finding as a regular
	// file is.
	//
	// The bool is the tally's analogue of Match. Returning false means this
	// inode is outside the question, which is not the same as bucketing it
	// into a zero key: a tally that had to invent a key for every inode it did
	// not care about would report a bucket that is an artefact of the tally
	// rather than an observation about the host.
	Key func(system.FileInfo) (key uint64, ok bool)

	// MaxKeys caps the distinct keys this tally may hold. Overflow is recorded
	// as a count and a truncation marker on this tally's fact alone. Zero or
	// negative means DefaultMaxKeys.
	//
	// Note what is *not* capped: the counts. Once a key is admitted it counts
	// without bound and without allocating, so a cap that never fires means a
	// fact that describes the whole filesystem exactly.
	MaxKeys int
}

// validate rejects a tally that could not produce a usable fact.
func (t Tally) validate() error {
	switch {
	case t.Name == "":
		return fmt.Errorf("tally has an empty name")
	case strings.ContainsAny(t.Name, "./ \t"):
		return fmt.Errorf("tally name %q contains a separator; it becomes the fact ID %s", t.Name, fact.FSTallyFactID(t.Name))
	case t.Key == nil:
		return fmt.Errorf("tally %q has no Key", t.Name)
	}
	return nil
}

// maxKeys resolves the effective cap.
func (t Tally) maxKeys() int {
	if t.MaxKeys <= 0 {
		return DefaultMaxKeys
	}
	return t.MaxKeys
}

// RegisterTally adds an aggregating tally to the shared walk.
//
// It panics on a duplicate name or on registration after the set has been
// read, for the reason Register does: a consumer that arrives late would
// otherwise get a fact that silently does not exist, and a crash on the first
// test run is cheaper than a scan that quietly answered fewer questions than
// it was asked.
func RegisterTally(t Tally) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if sealed {
		panic(fmt.Sprintf("walker: tally %q registered after the interest set was read; registration must happen at init, before the walk is planned", t.Name))
	}
	if err := t.validate(); err != nil {
		panic("walker: " + err.Error())
	}
	for _, have := range tallyRegistry {
		if have.Name == t.Name {
			panic(fmt.Sprintf("walker: duplicate tally %q", t.Name))
		}
	}
	tallyRegistry = append(tallyRegistry, t)
}

// Tallies returns the registered tallies, sorted by name, and seals the
// registry against further registration.
func Tallies() []Tally {
	registryMu.Lock()
	defer registryMu.Unlock()

	sealed = true
	out := append([]Tally(nil), tallyRegistry...)
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// tallyState accumulates one tally during one walk.
//
// The map is the whole memory story: it holds one entry per distinct key and
// nothing per inode, so its size is bounded by maxKeys regardless of how large
// the filesystem is.
type tallyState struct {
	buckets map[uint64]*bucket
	tallied int
	dropped int
	max     int
}

// bucket is one key's running count and its exemplar.
type bucket struct {
	count   int
	example fact.FSRow
}

func newTallyState(t Tally) *tallyState {
	return &tallyState{buckets: map[uint64]*bucket{}, max: t.maxKeys()}
}

// fold counts one inode. It reports whether the keyspace cap had to discard a
// key, which the caller records as truncation on this tally alone.
func (ts *tallyState) fold(key uint64, fi system.FileInfo) (dropped bool) {
	ts.tallied++
	if b, ok := ts.buckets[key]; ok {
		// The common path, and the one that makes a tally affordable: an
		// existing key costs an increment and allocates nothing.
		b.count++
		return false
	}
	if len(ts.buckets) >= ts.max {
		ts.dropped++
		return true
	}
	ts.buckets[key] = &bucket{count: 1, example: DefaultRow(fi)}
	return false
}

// asFact renders the accumulated state, sorted by key so the fact is
// byte-identical across two collections of an unchanged host.
func (ts *tallyState) asFact(out *fact.FSTally) {
	out.Buckets = make([]fact.FSBucket, 0, len(ts.buckets))
	for key, b := range ts.buckets {
		out.Buckets = append(out.Buckets, fact.FSBucket{Key: key, Count: b.count, Example: b.example})
	}
	sort.Slice(out.Buckets, func(a, b int) bool { return out.Buckets[a].Key < out.Buckets[b].Key })
	out.InodesTallied = ts.tallied
	out.KeysDropped = ts.dropped
}
