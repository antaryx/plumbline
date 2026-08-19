// Package walker performs the single filesystem traversal of a scan.
//
// Nine modules of the v0.2 catalog want to know something about the
// filesystem — SUID binaries, world-writable files, unowned files, sticky-bit
// directories. Nine independent walks of a production host is the design
// mistake this package exists to prevent, so consumers register *interest
// predicates* up front and the walker evaluates every one of them per inode in
// one pass (ARCHITECTURE.md §3.2, BUILD-RUNBOOK-v0.2.md WP-15).
//
// The traversal is hostile-input territory by definition: it reaches paths
// nobody named, on filesystems nobody chose, on a host that may be actively
// trying to stop it. Hence the rules below, none of which are optional:
//
//   - never follow a symlink, and never open anything that is not a directory
//     — opening an unprivileged user's FIFO as root hangs the scanner forever
//   - never cross a filesystem boundary unless explicitly told to
//   - never descend into a filesystem type on the skip list, because a dead
//     NFS server blocks in uninterruptible kernel sleep where no timeout of
//     ours can reach it
//   - terminate on cycles by identity, not by giving up at a depth limit
//   - bound depth, inode count and wall clock, and say so when a bound fires
//
// The last of those is the one that decides whether this package is useful or
// dangerous. See fact.FSMatches.Complete for the asymmetric truncation rule
// that governs what a check may conclude from a partial walk.
package walker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier. The collector is "fswalk"; the facts it
// writes are "fs.<interest>".
const ID = "fswalk"

// Defaults for the traversal's bounds.
//
// Every one of them is a policy number, and every one of them exists because
// the alternative is a root process that does not come back. They are
// deliberately generous: a bound that fires on an ordinary host produces
// UNKNOWN findings, and an auditor who sees UNKNOWN on a healthy machine stops
// believing the tool.
const (
	// DefaultMaxDepth is how deep the walk descends. A legitimate system tree
	// is nowhere near this deep; a generated or malicious one is deeper.
	DefaultMaxDepth = 64

	// DefaultMaxInodes is the global inode budget across the whole traversal.
	// A large server holds a few million inodes on its root filesystem, so
	// this completes on real hosts and still bounds the pathological case.
	DefaultMaxInodes = 3_000_000

	// DefaultMaxHits caps one interest's recorded rows when it does not set
	// its own. There is deliberately no "unlimited": the rows live in memory
	// in a root-privileged process and then in a bundle on disk, and an
	// interest that matches every inode on the host would exhaust both.
	DefaultMaxHits = 20_000

	// DefaultBudget is the walk's own wall-clock limit.
	//
	// It is shorter than Timeout on purpose. The runner discards the partial
	// output of a collector it had to abandon, which is right for a collector
	// that cannot describe its own incompleteness — but this one can. Stopping
	// voluntarily inside our own budget means the facts are written with a
	// truncation marker and survive; being killed by the runner's deadline
	// means everything the walk found is thrown away, including the SUID
	// binary it did find. The gap between the two numbers is what buys the
	// time to write the facts out.
	DefaultBudget = 4 * time.Minute

	// DefaultTimeout is the collector's declared budget, enforced by the
	// runner. See DefaultBudget for why it is the larger of the two.
	DefaultTimeout = 5 * time.Minute
)

// clockCheckEvery is how many inodes may pass between wall-clock checks.
// Calling Now once per inode would put a syscall in the hot loop of a walk
// over millions of them; leaving it to the per-directory check alone would let
// a single enormous directory overrun the budget.
const clockCheckEvery = 4096

// Interest is one consumer's standing question about the filesystem,
// registered before the walk and answered during it.
type Interest struct {
	// Name is the fact suffix this interest produces: "suid" becomes fs.suid.
	Name string

	// Match decides whether this inode is interesting. It must be pure, and it
	// must be fast: it runs once per inode on a filesystem that may hold ten
	// million of them, once for every registered interest.
	//
	// Match sees every inode the walk reaches, including symlinks, FIFOs,
	// sockets and device nodes. That is deliberate — a world-writable socket
	// is a real finding — and it is safe, because the walker only ever stats
	// them. Nothing here is ever opened.
	Match func(system.FileInfo) bool

	// Row extracts what the fact should record. Called only when Match passed.
	// Nil means DefaultRow.
	Row func(system.FileInfo) fact.FSRow

	// MaxHits caps the rows this interest may produce. Overflow is recorded as
	// a count and a truncation marker on this interest's fact alone, never
	// silently dropped and never allowed to affect another interest's fact.
	// Zero or negative means DefaultMaxHits.
	MaxHits int
}

// DefaultRow records the inode as-is. It is what an interest gets when it does
// not need to shape the row itself, which is most of them.
func DefaultRow(fi system.FileInfo) fact.FSRow {
	return fact.FSRow{
		Path:      fi.Path,
		Mode:      fi.Mode,
		UID:       fi.UID,
		GID:       fi.GID,
		Size:      fi.Size,
		IsDir:     fi.IsDir,
		IsRegular: fi.IsRegular,
		IsSymlink: fi.IsSymlink,
	}
}

// validate rejects an interest that could not produce a usable fact.
func (i Interest) validate() error {
	switch {
	case i.Name == "":
		return fmt.Errorf("interest has an empty name")
	case strings.ContainsAny(i.Name, "./ \t"):
		return fmt.Errorf("interest name %q contains a separator; it becomes the fact ID %s", i.Name, fact.FSFactID(i.Name))
	case i.Match == nil:
		return fmt.Errorf("interest %q has no Match", i.Name)
	}
	return nil
}

// maxHits resolves the effective cap.
func (i Interest) maxHits() int {
	if i.MaxHits <= 0 {
		return DefaultMaxHits
	}
	return i.MaxHits
}

// row resolves the effective row extractor.
func (i Interest) row(fi system.FileInfo) fact.FSRow {
	if i.Row == nil {
		return DefaultRow(fi)
	}
	return i.Row(fi)
}

// The registry of interests.
//
// Registration happens from package init, the same way collectors register
// themselves, so a wiring mistake panics on the first test run rather than
// producing a scan that quietly answered fewer questions than it was asked.
var (
	registryMu sync.Mutex
	registry   []Interest
	sealed     bool
)

// Register adds an interest to the shared walk.
//
// It panics rather than returning an error, and it panics if the walk has
// already begun. A consumer that arrives late is a programming error of the
// same class as a collector dependency cycle: the alternative is a second
// traversal, or a fact that silently does not exist, and both are worse than a
// crash on the first run.
func Register(i Interest) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if sealed {
		panic(fmt.Sprintf("walker: interest %q registered after the interest set was read; registration must happen at init, before the walk is planned", i.Name))
	}
	if err := i.validate(); err != nil {
		panic("walker: " + err.Error())
	}
	for _, have := range registry {
		if have.Name == i.Name {
			panic(fmt.Sprintf("walker: duplicate interest %q", i.Name))
		}
	}
	registry = append(registry, i)
}

// Interests returns the registered interests, sorted by name, and seals the
// registry against further registration.
func Interests() []Interest {
	registryMu.Lock()
	defer registryMu.Unlock()

	sealed = true
	out := append([]Interest(nil), registry...)
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// resetRegistry restores the registry to empty and unsealed. Tests only: the
// package-level registry is process-wide state, and a test that registers an
// interest would otherwise leak it into every later test in the binary.
func resetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = nil
	sealed = false
}

// Config is one traversal's parameters.
type Config struct {
	// Interests are the questions this walk answers. Required.
	Interests []Interest

	// Roots are the paths to start from. Empty means []string{"/"}.
	Roots []string

	// CrossFS permits the walk to descend across filesystem boundaries. It is
	// off by default and is only ever turned on explicitly: crossing means
	// walking whatever an operator happened to mount, which on a real host
	// includes network filesystems and other people's removable media.
	CrossFS bool

	// MaxDepth, MaxInodes, Budget bound the walk. Zero means the Default.
	MaxDepth  int
	MaxInodes int
	Budget    time.Duration

	// MaxDirEntries is passed to ReadDir. Zero means the seam's default.
	MaxDirEntries int

	// Now is the clock the wall-clock budget is measured against. Nil means
	// time.Now. The collector passes system.Now so that a fixture with a
	// frozen clock never spuriously times out, and tests pass a clock they
	// control so that the budget test asserts the budget rather than the speed
	// of the machine running it.
	Now func() time.Time
}

func (c Config) roots() []string {
	if len(c.Roots) == 0 {
		return []string{"/"}
	}
	return c.Roots
}

func (c Config) maxDepth() int {
	if c.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return c.MaxDepth
}

func (c Config) maxInodes() int {
	if c.MaxInodes <= 0 {
		return DefaultMaxInodes
	}
	return c.MaxInodes
}

func (c Config) budget() time.Duration {
	if c.Budget <= 0 {
		return DefaultBudget
	}
	return c.Budget
}

func (c Config) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// Result is what one traversal observed.
type Result struct {
	// Facts holds one fact per interest, sorted by interest name.
	Facts []fact.FSMatches

	// Mounts is the kernel's mount table, which the walk reads anyway to apply
	// its filesystem-type skip list. It is carried out rather than re-read by
	// a collector of its own: two reads of the same kernel table could
	// disagree, and the disagreement would be invisible.
	Mounts fact.Mounts

	// InodesVisited counts every inode the walk examined, across all roots.
	InodesVisited int
	// DirsVisited counts directories actually listed. It is what proves the
	// tree was traversed once rather than once per interest.
	DirsVisited int
	// CyclesBroken counts directories skipped because their device and inode
	// had already been visited: bind mounts, and any other way a tree can
	// contain itself.
	CyclesBroken int
	// BoundariesDeclined counts directories not descended into because they
	// were on another filesystem or on a skipped filesystem type. These are
	// scope, not truncation; see walkState.truncate.
	BoundariesDeclined int
}

// walkState carries the mutable state of one traversal.
type walkState struct {
	cfg      Config
	sys      system.System
	mounts   mountTable
	deadline time.Time

	// out is the accumulating fact per interest, in Interests order.
	out []fact.FSMatches
	// hits counts rows recorded per interest, to compare against MaxHits.
	hits []int

	// visited is the device+inode set. It is what makes a bind-mount cycle
	// terminate for the right reason: a depth limit also stops an infinite
	// walk, but it reports the host as truncated when the host is merely
	// misconfigured, and it cannot tell a loop from a legitimately deep tree
	// (ADR-0012).
	visited map[devIno]bool

	res  Result
	stop bool // a global limit fired; unwind
}

// devIno identifies an inode uniquely within a running kernel.
type devIno struct {
	dev uint64
	ino uint64
}

// identified reports whether a FileInfo carries a usable identity. Zero means
// "not recorded" per ADR-0012, and an unidentified directory cannot be entered
// into the cycle set — the depth limit is the backstop for that case.
func identified(fi system.FileInfo) bool { return fi.Dev != 0 || fi.Ino != 0 }

// Walk performs one traversal and returns one fact per interest.
//
// It returns an error only for a caller mistake — no interests, an invalid
// interest. Everything the filesystem does to it is recorded in the facts,
// because "the walk could not finish" is an observation a check needs, not a
// failure that should discard the observations already made.
func Walk(ctx context.Context, s system.System, cfg Config) (Result, error) {
	if len(cfg.Interests) == 0 {
		return Result{}, fmt.Errorf("walker: Walk called with no interests")
	}
	for _, i := range cfg.Interests {
		if err := i.validate(); err != nil {
			return Result{}, fmt.Errorf("walker: %w", err)
		}
	}

	st := &walkState{
		cfg:     cfg,
		sys:     s,
		mounts:  readMountTable(s),
		visited: map[devIno]bool{},
		out:     make([]fact.FSMatches, len(cfg.Interests)),
		hits:    make([]int, len(cfg.Interests)),
	}
	st.deadline = cfg.now().Add(cfg.budget())

	roots := cfg.roots()
	for n, i := range cfg.Interests {
		st.out[n] = fact.FSMatches{
			Interest: i.Name,
			Roots:    append([]string(nil), roots...),
		}
	}

	// A mount table we could not read means the fstype skip list cannot be
	// applied. With CrossFS off that is survivable: the device check alone
	// keeps the walk on the filesystem it started on, and that filesystem is
	// not a dead NFS server, because we are running on it. With CrossFS on it
	// is not survivable, so the walk declines to cross and says why rather
	// than stepping blindly into whatever is mounted.
	if !st.mounts.known && cfg.CrossFS {
		st.cfg.CrossFS = false
		st.truncateAll(fact.TruncMountsUnknown)
	}

	for _, root := range roots {
		st.walkRoot(ctx, root)
		if st.stop {
			break
		}
	}

	st.finish()
	return st.res, nil
}

// walkRoot traverses one root, depth first, in sorted path order.
//
// The frontier is an explicit stack rather than recursion: the depth limit
// bounds it, but a bound that is enforced by the size of the goroutine stack
// is a crash rather than a truncation marker, and this process is root.
func (st *walkState) walkRoot(ctx context.Context, root string) {
	fi, err := st.sys.Stat(root)
	if err != nil {
		// We were asked to examine this root and could not. Nothing may be
		// concluded about what it does or does not contain.
		st.truncateAll(fact.TruncUnreadable)
		return
	}
	if !fi.IsDir || fi.IsSymlink {
		// A root that is not a directory is still an inode worth offering to
		// the interests, but there is nothing to descend into.
		st.offer(fi)
		return
	}

	rootDev := fi.Dev
	if !st.offer(fi) {
		return
	}

	// Each frame carries the FileInfo the parent listing already produced, so
	// a directory is stat'ed once rather than twice. On a walk over millions
	// of inodes the second stat is not a micro-optimisation, it is a doubling.
	type frame struct {
		fi    system.FileInfo
		depth int
	}
	stack := []frame{{fi: fi, depth: 0}}

	for len(stack) > 0 && !st.stop {
		if st.overBudget(ctx) {
			return
		}

		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Cycle detection happens on entry, rather than at push time, so that
		// it covers the root as well as everything below it.
		if identified(f.fi) {
			id := devIno{dev: f.fi.Dev, ino: f.fi.Ino}
			if st.visited[id] {
				// Already enumerated under another path. Skipping it is not
				// truncation: everything inside it has been seen, so absence
				// is still safe to conclude. It is deduplication that happens
				// to also terminate the walk.
				st.res.CyclesBroken++
				continue
			}
			st.visited[id] = true
		}

		listing, err := st.sys.ReadDir(f.fi.Path, st.cfg.MaxDirEntries)
		if err != nil {
			// Typically permission denied. We do not know what is in this
			// directory, so no interest may claim it is empty of anything.
			st.truncateAll(fact.TruncUnreadable)
			continue
		}
		st.res.DirsVisited++
		if listing.Truncated {
			// The seam's entry cap fired, or an entry could not be stat'ed.
			// Either way something in this directory was never seen.
			st.truncateAll(fact.TruncDirListing)
		}

		entries := append([]system.FileInfo(nil), listing.Entries...)
		sort.Slice(entries, func(a, b int) bool { return entries[a].Path < entries[b].Path })

		// Children are pushed in reverse so they pop in sorted order. Walk
		// order has to be deterministic: MaxHits keeps the first N rows it
		// meets, so an unstable order would mean an unstable fact.
		var children []frame
		for _, e := range entries {
			if st.overBudgetSampled(ctx) {
				return
			}
			if !st.offer(e) {
				return // inode budget exhausted
			}

			if !e.IsDir || e.IsSymlink {
				// Symlinks are never followed and nothing that is not a
				// directory is ever opened. Both were already offered to the
				// interests above, which is how a FIFO is recorded as
				// non-regular without anybody opening it.
				continue
			}
			if f.depth+1 > st.cfg.maxDepth() {
				st.truncateAll(fact.TruncDepth)
				continue
			}
			if st.declineBoundary(e, rootDev) {
				continue
			}
			children = append(children, frame{fi: e, depth: f.depth + 1})
		}
		for n := len(children) - 1; n >= 0; n-- {
			stack = append(stack, children[n])
		}
	}
}

// declineBoundary reports whether dir is outside this walk's declared scope,
// counting it if so.
//
// A boundary decision is scope, not truncation, and the difference is
// deliberate. A truncation marker means "we intended to look and could not",
// which is what forces a check asserting absence to UNKNOWN. A boundary means
// "this was never in scope", which the fact states plainly in Roots. Marking
// scope as truncation would make every ordinary host with a separate /home
// report UNKNOWN for every filesystem check, and an UNKNOWN that fires
// everywhere is an UNKNOWN nobody reads.
func (st *walkState) declineBoundary(dir system.FileInfo, rootDev uint64) bool {
	if !st.cfg.CrossFS && dir.Dev != 0 && rootDev != 0 && dir.Dev != rootDev {
		st.res.BoundariesDeclined++
		return true
	}
	if fstype, ok := st.mounts.fstypeAt(dir.Path); ok && SkippedFSType(fstype) {
		// Checked even when the device says we would not have crossed anyway:
		// this is the rule that keeps the walk out of a hung NFS mount, and it
		// must not depend on another rule happening to fire first.
		st.res.BoundariesDeclined++
		return true
	}
	return false
}

// offer presents one inode to every interest. It returns false when the global
// inode budget is exhausted, which stops the whole traversal.
func (st *walkState) offer(fi system.FileInfo) bool {
	if st.res.InodesVisited >= st.cfg.maxInodes() {
		st.truncateAll(fact.TruncInodes)
		st.stop = true
		return false
	}
	st.res.InodesVisited++

	for n, i := range st.cfg.Interests {
		if !i.Match(fi) {
			continue
		}
		if st.hits[n] >= i.maxHits() {
			// This interest has recorded all it may. Its own fact says so and
			// counts what it dropped; every other interest carries on
			// unaffected, which is why there is one fact per interest.
			st.out[n].Overflow++
			st.out[n].MarkTruncated(fact.TruncMaxHits)
			continue
		}
		st.out[n].Rows = append(st.out[n].Rows, i.row(fi))
		st.hits[n]++
	}
	return true
}

// overBudget reports whether the walk must stop, marking every fact if it
// must. It is the only place the wall clock and the context are consulted, and
// it is called once per directory.
func (st *walkState) overBudget(ctx context.Context) bool {
	if st.stop {
		return true
	}
	if err := ctx.Err(); err != nil {
		// The runner's deadline, not ours. Stop and return the partial facts
		// with a marker rather than being abandoned with them unwritten.
		st.truncateAll(fact.TruncDeadline)
		st.stop = true
		return true
	}
	if !st.cfg.now().Before(st.deadline) {
		st.truncateAll(fact.TruncDeadline)
		st.stop = true
		return true
	}
	return false
}

// overBudgetSampled is overBudget for the per-entry loop, which runs once per
// inode. Consulting the clock that often would put a syscall in the hot path
// of a walk over ten million of them; consulting it only per directory would
// let one enormous directory overrun the budget without a single check. It is
// sampled instead, which bounds the overrun to the time it takes to stat
// clockCheckEvery entries.
func (st *walkState) overBudgetSampled(ctx context.Context) bool {
	if st.stop {
		return true
	}
	if st.res.InodesVisited%clockCheckEvery != 0 {
		return false
	}
	return st.overBudget(ctx)
}

// truncateAll marks every fact this walk is producing.
//
// A limit that fires is a property of the traversal, so it lands on every
// fact the traversal produced. MaxHits is the one exception and is applied in
// offer, because it is a property of one interest.
func (st *walkState) truncateAll(reason fact.TruncationReason) {
	for n := range st.out {
		st.out[n].MarkTruncated(reason)
	}
}

// finish sorts each fact's rows and stamps the shared counters.
func (st *walkState) finish() {
	for n := range st.out {
		rows := st.out[n].Rows
		sort.Slice(rows, func(a, b int) bool { return rows[a].Path < rows[b].Path })
		st.out[n].InodesVisited = st.res.InodesVisited
	}
	st.res.Facts = st.out
	st.res.Mounts = st.mounts.asFact()
}

// Collector is the fswalk collector: the shared traversal, wired into the
// collection runner.
type Collector struct {
	cfg Config
}

// New returns the fswalk collector with default bounds.
func New() Collector { return Collector{} }

// NewWithConfig returns the collector with non-default bounds. Interests are
// always taken from the registry and any set here are ignored; there is one
// walk and one set of consumers, and letting a caller substitute them would be
// a second walk wearing the first one's name.
func NewWithConfig(cfg Config) Collector {
	cfg.Interests = nil
	return Collector{cfg: cfg}
}

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

// Produces names one fact per registered interest, so that a walk that timed
// out or panicked is recorded against the facts the checks will actually look
// for rather than against a collector name they have never heard of.
func (Collector) Produces() []fact.ID {
	in := Interests()
	out := make([]fact.ID, 0, len(in)+1)
	for _, i := range in {
		out = append(out, fact.FSFactID(i.Name))
	}
	// The mount table is published whether or not any interest was registered,
	// so it is named here unconditionally.
	return append(out, fact.MountsID)
}

// DependsOn is nil. The walk needs nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone, for the reason the sshd collector is: declaring CapRoot
// would make an unprivileged scan skip the walk entirely and report only that
// it was skipped. Running it means each unreadable directory is recorded as
// what it is, and the facts carry a truncation marker that pushes every
// absence claim to UNKNOWN. That is a specific, actionable answer instead of a
// blanket one.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Expensive, which is what makes the runner serialise this against
// every other expensive collector. That is the entire scheduling mechanism;
// there is deliberately no second one.
func (Collector) Cost() collect.Cost { return collect.Expensive }

// Timeout is the runner-enforced budget. It exceeds the walk's own wall-clock
// budget on purpose — see DefaultBudget.
func (c Collector) Timeout() time.Duration {
	if c.cfg.Budget > 0 {
		return c.cfg.Budget + time.Minute
	}
	return DefaultTimeout
}

// Collect performs the one traversal and writes one fact per interest.
//
// It returns nil after a walk that ran out of time, rather than the context
// error, and that is load bearing: the runner discards the partial output of a
// collector that returns an error under a fired deadline, which is correct for
// collectors that cannot describe their own incompleteness. This one can. The
// facts it writes carry the truncation marker, so a check asserting absence
// resolves to UNKNOWN(source_truncated) while a check reporting something the
// walk actually found still gets to report it.
func (c Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	cfg := c.cfg
	cfg.Interests = Interests()
	if cfg.Now == nil {
		cfg.Now = s.Now
	}

	if len(cfg.Interests) == 0 {
		// No module registered an interest, so there is no tree to walk:
		// traversing a filesystem to answer no questions is pure cost on the
		// host being audited.
		//
		// The mount table is still read and still published. It is not a
		// product of the traversal — the walk reads it to decide where *not*
		// to descend — and making it conditional on some unrelated module
		// having registered an interest would mean the FILESYS mount checks
		// resolved to UNKNOWN for a reason that has nothing to do with the
		// host. A fact that silently depends on another module's wiring is
		// the kind of gap that survives review.
		fs.Put(readMountTable(s).asFact())
		return nil
	}

	res, err := Walk(ctx, s, cfg)
	if err != nil {
		return err
	}
	for _, f := range res.Facts {
		fs.Put(f)
	}
	fs.Put(res.Mounts)
	return nil
}
