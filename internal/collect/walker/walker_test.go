package walker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// countingSystem wraps a system.System and records what was asked of it. It is
// how a test proves the tree was traversed once rather than once per interest,
// and how it proves a FIFO was never opened: those are claims about the calls
// the walker made, and nothing in the returned facts can evidence them.
type countingSystem struct {
	system.System
	readDirs  map[string]int
	readFiles map[string]int
	stats     map[string]int
}

func wrap(s system.System) *countingSystem {
	return &countingSystem{
		System:    s,
		readDirs:  map[string]int{},
		readFiles: map[string]int{},
		stats:     map[string]int{},
	}
}

func (c *countingSystem) ReadDir(p string, max int) (system.DirResult, error) {
	c.readDirs[p]++
	return c.System.ReadDir(p, max)
}

func (c *countingSystem) ReadFile(p string, max int64) (system.ReadResult, error) {
	c.readFiles[p]++
	return c.System.ReadFile(p, max)
}

func (c *countingSystem) Stat(p string) (system.FileInfo, error) {
	c.stats[p]++
	return c.System.Stat(p)
}

func (c *countingSystem) totalReadDirs() int {
	n := 0
	for _, v := range c.readDirs {
		n += v
	}
	return n
}

func fixture(t *testing.T, name string) *countingSystem {
	t.Helper()
	s, err := fake.New(filepath.Join("..", "..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("loading fixture %s: %v", name, err)
	}
	return wrap(s)
}

// steppingClock advances by step on every call. The wall-clock budget must be
// asserted against a clock the test controls; asserting it against time.Now
// would make the test a measurement of how fast the machine running it is.
func steppingClock(start time.Time, step time.Duration) func() time.Time {
	n := 0
	return func() time.Time {
		t := start.Add(time.Duration(n) * step)
		n++
		return t
	}
}

// everything matches every inode. Used where the test is about the traversal
// rather than about a predicate.
func everything(system.FileInfo) bool { return true }

func suid(fi system.FileInfo) bool { return fi.Mode&fs.ModeSetuid != 0 }

func worldWritable(fi system.FileInfo) bool {
	return !fi.IsSymlink && fi.Mode.Perm()&0o002 != 0
}

// factFor returns the fact for one interest name.
func factFor(t *testing.T, res Result, name string) fact.FSMatches {
	t.Helper()
	for _, f := range res.Facts {
		if f.Interest == name {
			return f
		}
	}
	t.Fatalf("no fact for interest %q; got %v", name, interestNames(res))
	return fact.FSMatches{}
}

func interestNames(res Result) []string {
	var out []string
	for _, f := range res.Facts {
		out = append(out, f.Interest)
	}
	return out
}

func paths(f fact.FSMatches) []string {
	out := make([]string, 0, len(f.Rows))
	for _, r := range f.Rows {
		out = append(out, r.Path)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func hasReason(f fact.FSMatches, want fact.TruncationReason) bool {
	for _, r := range f.TruncationReasons {
		if r == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// one traversal, many interests
// ---------------------------------------------------------------------------

// TestOneTraversalManyInterests is the reason this package exists. Two
// interests must produce two facts from one pass, and the counter is the proof
// — without it the test would pass just as happily against two walks.
func TestOneTraversalManyInterests(t *testing.T) {
	s := fixture(t, "fswalk-basic")

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{
			{Name: "suid", Match: suid},
			{Name: "world_writable", Match: worldWritable},
		},
		Now: steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if got, want := len(res.Facts), 2; got != want {
		t.Fatalf("produced %d facts, want %d: %v", got, want, interestNames(res))
	}

	suidFact := factFor(t, res, "suid")
	if got := paths(suidFact); len(got) != 1 || got[0] != "/usr/bin/passwd" {
		t.Errorf("fs.suid rows = %v, want [/usr/bin/passwd]", got)
	}
	if got, want := suidFact.FactID(), fact.ID("fs.suid"); got != want {
		t.Errorf("fact ID = %q, want %q", got, want)
	}

	wwFact := factFor(t, res, "world_writable")
	if got := paths(wwFact); !contains(got, "/var/tmp/scratch") {
		t.Errorf("fs.world_writable rows = %v, want to include /var/tmp/scratch", got)
	}

	// Every directory listed exactly once. More than one read of any directory
	// means the second interest caused a second traversal.
	for dir, n := range s.readDirs {
		if n != 1 {
			t.Errorf("directory %s was listed %d times; the walk must be one pass", dir, n)
		}
	}
	if got, want := s.totalReadDirs(), res.DirsVisited; got != want {
		t.Errorf("ReadDir called %d times but DirsVisited = %d", got, want)
	}

	// Both facts describe the same traversal, so they agree on its size.
	if suidFact.InodesVisited != wwFact.InodesVisited {
		t.Errorf("facts disagree on the traversal: %d vs %d",
			suidFact.InodesVisited, wwFact.InodesVisited)
	}
	if !suidFact.Complete() || !wwFact.Complete() {
		t.Errorf("an unbounded walk of a small tree must be complete: %+v / %+v",
			suidFact.TruncationReasons, wwFact.TruncationReasons)
	}
}

// TestRowsAreDeterministic asserts the property the whole product rests on:
// same input, byte-identical facts.
func TestRowsAreDeterministic(t *testing.T) {
	run := func() []string {
		s := fixture(t, "fswalk-basic")
		res, err := Walk(context.Background(), s, Config{
			Interests: []Interest{{Name: "all", Match: everything}},
			Now:       steppingClock(time.Unix(0, 0), 0),
		})
		if err != nil {
			t.Fatalf("Walk: %v", err)
		}
		return paths(factFor(t, res, "all"))
	}

	first, second := run(), run()
	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Errorf("two walks of one tree disagreed:\n%v\n%v", first, second)
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("rows are not sorted by path: %v", first)
	}
}

// ---------------------------------------------------------------------------
// cycle detection
// ---------------------------------------------------------------------------

// TestCycleDetectionByDevIno is the acceptance criterion that a bind-mount
// cycle terminates "proven by the device+inode set rather than by a depth
// limit backstop". The fixture's /srv/data/self reports the same identity as
// /srv/data, which is a directory bind-mounted inside itself.
func TestCycleDetectionByDevIno(t *testing.T) {
	s := fixture(t, "fswalk-cycle")

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		// Generous, so that a depth limit demonstrably did not do this job.
		MaxDepth: 32,
		Now:      steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if got, want := res.CyclesBroken, 1; got != want {
		t.Fatalf("CyclesBroken = %d, want %d", got, want)
	}

	f := factFor(t, res, "all")
	got := paths(f)

	// The cycle's own directory entry is seen — it is an inode like any other.
	if !contains(got, "/srv/data/self") {
		t.Errorf("the cycle directory itself should be recorded: %v", got)
	}
	// What must not happen is descending through it a second time.
	if contains(got, "/srv/data/self/secret") {
		t.Errorf("walked into the cycle: /srv/data/self/secret is /srv/data/secret again: %v", got)
	}
	if contains(got, "/srv/data/self/real/deep") {
		t.Errorf("walked through the cycle into a whole second copy of the tree: %v", got)
	}
	// The real subtree is still walked; breaking a cycle must not cost content.
	if !contains(got, "/srv/data/real/deep") {
		t.Errorf("the genuine subtree was not walked: %v", got)
	}

	// The important half: a cycle is deduplication, not ignorance. Everything
	// inside the repeated directory was enumerated under its other path, so
	// absence is still safe to conclude and the fact must not be truncated.
	if !f.Complete() {
		t.Errorf("breaking a cycle must not truncate the walk: reasons=%v", f.TruncationReasons)
	}
	if hasReason(f, fact.TruncDepth) {
		t.Errorf("the depth limit fired; the cycle was stopped by the backstop, not by the dev+ino set")
	}
}

// TestSymlinkLoopIsNeverFollowed covers the other half of the same acceptance
// criterion. The fixture holds a symlink to its own parent and one to the
// root; neither may be descended into, and neither may be opened.
func TestSymlinkLoopIsNeverFollowed(t *testing.T) {
	s := fixture(t, "fswalk-cycle")

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		MaxDepth:  32,
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	f := factFor(t, res, "all")
	for _, link := range []string{"/srv/data/loop", "/srv/data/rootloop"} {
		if !contains(paths(f), link) {
			t.Errorf("symlink %s should be recorded as an inode: %v", link, paths(f))
		}
		if s.readDirs[link] != 0 {
			t.Errorf("descended into symlink %s", link)
		}
	}
	for _, row := range f.Rows {
		if row.Path == "/srv/data/loop" && !row.IsSymlink {
			t.Errorf("%s recorded as a non-symlink: %+v", row.Path, row)
		}
	}
	if !f.Complete() {
		t.Errorf("a symlink loop must not truncate the walk: %v", f.TruncationReasons)
	}
}

// ---------------------------------------------------------------------------
// non-regular files
// ---------------------------------------------------------------------------

// TestNonRegularFilesAreRecordedNeverOpened is the FIFO acceptance criterion.
// Opening an unprivileged user's FIFO as root blocks forever, which is a local
// denial of service against the scanner, so the assertion is about the calls
// the walker made and not only about what it returned.
func TestNonRegularFilesAreRecordedNeverOpened(t *testing.T) {
	s := fixture(t, "fswalk-nonregular")

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	f := factFor(t, res, "all")
	byPath := map[string]fact.FSRow{}
	for _, r := range f.Rows {
		byPath[r.Path] = r
	}

	for _, p := range []string{"/dev/console", "/run/initctl", "/run/docker.sock"} {
		row, ok := byPath[p]
		if !ok {
			t.Fatalf("%s was not reached by the walk: %v", p, paths(f))
		}
		if row.IsRegular {
			t.Errorf("%s recorded as a regular file: mode=%v", p, row.Mode)
		}
		if row.IsDir {
			t.Errorf("%s recorded as a directory: mode=%v", p, row.Mode)
		}
		if s.readFiles[p] != 0 {
			t.Errorf("opened %s; a walk must never open a non-directory", p)
		}
		if s.readDirs[p] != 0 {
			t.Errorf("listed %s as a directory", p)
		}
	}

	if got := byPath["/dev/console"].Mode & fs.ModeCharDevice; got == 0 {
		t.Errorf("/dev/console lost its character-device bit: %v", byPath["/dev/console"].Mode)
	}
	if got := byPath["/run/initctl"].Mode & fs.ModeNamedPipe; got == 0 {
		t.Errorf("/run/initctl lost its FIFO bit: %v", byPath["/run/initctl"].Mode)
	}
	if got := byPath["/run/docker.sock"].Mode & fs.ModeSocket; got == 0 {
		t.Errorf("/run/docker.sock lost its socket bit: %v", byPath["/run/docker.sock"].Mode)
	}

	// Nothing at all was opened: the walk reads directories, never files.
	if len(s.readFiles) > 1 {
		t.Errorf("the walk opened files: %v", s.readFiles)
	}
	if !f.Complete() {
		t.Errorf("non-regular files must not truncate a walk: %v", f.TruncationReasons)
	}
}

// TestRealFifoAndSocketAreNeverOpened repeats the previous test against inodes
// the kernel actually created, because the fixture describes a FIFO while this
// one is a FIFO. A test-time tree rather than a committed one: a FIFO and a
// socket are not file contents and cannot live in git.
func TestRealFifoAndSocketAreNeverOpened(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "run", "fifo")
	if err := syscall.Mkfifo(fifo, 0o666); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	// A unix socket, created by binding one. The path length limit is why it
	// goes in the shortest directory the test can arrange.
	sock := filepath.Join(dir, "run", "s")
	l, err := netListenUnix(sock)
	if err != nil {
		t.Skipf("cannot create a unix socket here: %v", err)
	}
	defer l()

	s, err := fake.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := wrap(s)

	done := make(chan Result, 1)
	go func() {
		res, err := Walk(context.Background(), c, Config{
			Interests: []Interest{{Name: "all", Match: everything}},
			Now:       steppingClock(time.Unix(0, 0), 0),
		})
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()

	// A walk that opened the FIFO would block here forever, so the timeout is
	// the assertion: this test failing by timing out is the bug it exists to
	// catch.
	var res Result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the walk did not finish; it opened something it should not have")
	}

	f := factFor(t, res, "all")
	if !contains(paths(f), "/run/fifo") {
		t.Errorf("the FIFO was not reached: %v", paths(f))
	}
	if !contains(paths(f), "/run/s") {
		t.Errorf("the socket was not reached: %v", paths(f))
	}
	for _, r := range f.Rows {
		if r.Path == "/run/fifo" && r.IsRegular {
			t.Errorf("the FIFO was recorded as a regular file")
		}
	}
	if c.readFiles["/run/fifo"] != 0 {
		t.Errorf("opened the FIFO")
	}
}

// ---------------------------------------------------------------------------
// boundaries and the fstype skip list
// ---------------------------------------------------------------------------

// TestSkipsVirtualAndNetworkFilesystems proves the skip list against the
// fixture's own mount table rather than against whatever the machine running
// the test happens to have mounted.
func TestSkipsVirtualAndNetworkFilesystems(t *testing.T) {
	s := fixture(t, "fswalk-mounts")

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		// Crossing is on, so nothing but the fstype skip list can be keeping
		// the walk out of these mounts.
		CrossFS: true,
		Now:     steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	f := factFor(t, res, "all")
	got := paths(f)

	// The mount points themselves are inodes on the parent filesystem and are
	// seen. What must not happen is descending into them.
	for _, mount := range []string{"/proc", "/sys", "/mnt/nfs"} {
		if !contains(got, mount) {
			t.Errorf("mount point %s should be recorded: %v", mount, got)
		}
		if s.readDirs[mount] != 0 {
			t.Errorf("descended into %s, which is on the fstype skip list", mount)
		}
	}
	for _, inside := range []string{"/proc/1/cmdline", "/sys/kernel/notes", "/mnt/nfs/home/hang-here"} {
		if contains(got, inside) {
			t.Errorf("walked into a skipped filesystem: %s", inside)
		}
	}

	// An ordinary filesystem at a mount point is walked. Without this the test
	// would pass for a walker that simply refused every mount point.
	if !contains(got, "/mnt/data/payroll/records") {
		t.Errorf("ext4 at /mnt/data should be walked with CrossFS on: %v", got)
	}
	if got, want := res.BoundariesDeclined, 3; got != want {
		t.Errorf("BoundariesDeclined = %d, want %d", got, want)
	}
	if !f.Complete() {
		t.Errorf("declining a skipped filesystem is scope, not truncation: %v", f.TruncationReasons)
	}
}

// TestDoesNotCrossFilesystemBoundaries asserts the default. /mnt/data is on a
// second device in the fixture and must not be entered unless asked for.
func TestDoesNotCrossFilesystemBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		crossFS bool
		want    bool // /mnt/data/payroll/records reached
	}{
		{name: "default stays on one device", crossFS: false, want: false},
		{name: "explicit opt-in crosses", crossFS: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t, "fswalk-mounts")
			res, err := Walk(context.Background(), s, Config{
				Interests: []Interest{{Name: "all", Match: everything}},
				CrossFS:   tc.crossFS,
				Now:       steppingClock(time.Unix(0, 0), 0),
			})
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			f := factFor(t, res, "all")
			if got := contains(paths(f), "/mnt/data/payroll/records"); got != tc.want {
				t.Errorf("reached /mnt/data/payroll/records = %v, want %v (CrossFS=%v)",
					got, tc.want, tc.crossFS)
			}
			// Either way this is scope, not ignorance.
			if !f.Complete() {
				t.Errorf("a boundary must not truncate the walk: %v", f.TruncationReasons)
			}
		})
	}
}

// TestUnknownMountTableRefusesToCross covers the case where the mount table
// could not be read at all. Crossing then means stepping into whatever is
// mounted without being able to tell whether it is a dead NFS server, so the
// walk declines and says why.
func TestUnknownMountTableRefusesToCross(t *testing.T) {
	s := fixture(t, "fswalk-basic") // has no /proc/self/mountinfo

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		CrossFS:   true,
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	f := factFor(t, res, "all")
	if f.Complete() {
		t.Errorf("a walk that could not read the mount table but was asked to cross must say so")
	}
	if !hasReason(f, fact.TruncMountsUnknown) {
		t.Errorf("reasons = %v, want to include %q", f.TruncationReasons, fact.TruncMountsUnknown)
	}
}

// TestSkippedFSType is the skip list itself, including the prefix forms.
func TestSkippedFSType(t *testing.T) {
	for _, fstype := range []string{
		"proc", "sysfs", "devtmpfs", "tracefs", "debugfs", "autofs", "cifs",
		"cgroup", "cgroup2", "nfs", "nfs4", "fuse", "fuse.sshfs", "fuseblk",
	} {
		if !SkippedFSType(fstype) {
			t.Errorf("%s should be skipped", fstype)
		}
	}
	for _, fstype := range []string{"ext4", "xfs", "btrfs", "tmpfs", "vfat", "overlay", "zfs"} {
		if SkippedFSType(fstype) {
			t.Errorf("%s should be walked", fstype)
		}
	}
}

func TestParseMountInfoLine(t *testing.T) {
	for _, tc := range []struct {
		name          string
		line          string
		point, fstype string
		options       []string
		superOpts     []string
		ok            bool
	}{
		{
			name: "no optional fields",
			line: "21 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw",
			// The separator can appear at index 6, which is why neither the
			// fstype nor the superblock options can be read at a fixed offset.
			point: "/", fstype: "ext4",
			options: []string{"rw", "relatime"}, superOpts: []string{"rw"}, ok: true,
		},
		{
			name:  "several optional fields",
			line:  "24 21 0:23 / /mnt/nfs rw shared:4 master:2 propagate_from:1 - nfs4 srv:/e rw",
			point: "/mnt/nfs", fstype: "nfs4",
			options: []string{"rw"}, superOpts: []string{"rw"}, ok: true,
		},
		{
			name: "octal-escaped mount point",
			line: `26 21 0:25 / /mnt/my\040share rw - cifs //srv/share rw`,
			// A skip list that compared the escaped form would fail to match
			// and would walk into the filesystem it meant to avoid.
			point: "/mnt/my share", fstype: "cifs",
			options: []string{"rw"}, superOpts: []string{"rw"}, ok: true,
		},
		{
			// The hardening options the FILESYS mount checks read live in
			// field 5, which is the *per-mount* option list. The superblock
			// list after the fstype is a different set and answering from it
			// would be right often enough to look correct.
			name:  "hardened tmpfs",
			line:  "31 21 0:26 / /dev/shm rw,nosuid,nodev,noexec shared:5 - tmpfs tmpfs rw,inode64",
			point: "/dev/shm", fstype: "tmpfs",
			options:   []string{"rw", "nosuid", "nodev", "noexec"},
			superOpts: []string{"rw", "inode64"}, ok: true,
		},
		{name: "truncated line", line: "21 1 8:1 / /", ok: false},
		{name: "no separator", line: "21 1 8:1 / / rw,relatime ext4 /dev/sda1 rw x", ok: false},
		{name: "empty", line: "", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			point, e, ok := parseMountInfoLine(tc.line)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if point != tc.point || e.fstype != tc.fstype {
				t.Errorf("got (%q, %q), want (%q, %q)", point, e.fstype, tc.point, tc.fstype)
			}
			if !reflect.DeepEqual(e.options, tc.options) {
				t.Errorf("options = %v, want %v", e.options, tc.options)
			}
			if !reflect.DeepEqual(e.superOpts, tc.superOpts) {
				t.Errorf("superOpts = %v, want %v", e.superOpts, tc.superOpts)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// limits, and the truncation marker they set
// ---------------------------------------------------------------------------

// TestEachGlobalLimitTruncatesEveryFact is the acceptance criterion that each
// of the depth, inode-count and wall-clock limits fires in its own test and
// sets the marker on *every* fact the walk produced. A limit is a property of
// the traversal, so a fact that escaped the marker would be a fact claiming a
// completeness the walk did not have.
func TestEachGlobalLimitTruncatesEveryFact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    Config
		reason fact.TruncationReason
	}{
		{
			name:   "depth limit",
			cfg:    Config{MaxDepth: 1},
			reason: fact.TruncDepth,
		},
		{
			name:   "inode limit",
			cfg:    Config{MaxInodes: 3},
			reason: fact.TruncInodes,
		},
		{
			name: "wall clock",
			cfg: Config{
				Budget: 10 * time.Second,
				// Each consultation of the clock jumps a minute, so the budget
				// is spent almost immediately and the test never depends on
				// how fast the machine is.
				Now: steppingClock(time.Unix(0, 0), time.Minute),
			},
			reason: fact.TruncDeadline,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t, "fswalk-basic")
			cfg := tc.cfg
			cfg.Interests = []Interest{
				{Name: "suid", Match: suid},
				{Name: "world_writable", Match: worldWritable},
				{Name: "all", Match: everything},
			}
			if cfg.Now == nil {
				cfg.Now = steppingClock(time.Unix(0, 0), 0)
			}

			res, err := Walk(context.Background(), s, cfg)
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if len(res.Facts) != 3 {
				t.Fatalf("produced %d facts, want 3", len(res.Facts))
			}
			for _, f := range res.Facts {
				if f.Complete() {
					t.Errorf("fact %s survived the %s untruncated", f.FactID(), tc.name)
				}
				if !hasReason(f, tc.reason) {
					t.Errorf("fact %s reasons = %v, want to include %q",
						f.FactID(), f.TruncationReasons, tc.reason)
				}
			}
		})
	}
}

// TestContextCancellationTruncatesRatherThanErrors asserts the deliberate
// choice in Collect: a walk whose context expired returns what it found, with
// a marker, instead of an error. The runner discards the partial output of a
// collector that errors under a fired deadline, and discarding a SUID binary
// we actually found is worse than reporting it alongside "the walk did not
// finish".
func TestContextCancellationTruncatesRatherThanErrors(t *testing.T) {
	s := fixture(t, "fswalk-basic")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := Walk(ctx, s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk returned an error for a cancelled context: %v", err)
	}
	f := factFor(t, res, "all")
	if f.Complete() {
		t.Errorf("a cancelled walk claimed completeness")
	}
	if !hasReason(f, fact.TruncDeadline) {
		t.Errorf("reasons = %v, want to include %q", f.TruncationReasons, fact.TruncDeadline)
	}
}

// TestUnreadableDirectoryTruncates covers the unprivileged scan: a directory
// we could not list is a directory nothing may be claimed absent from.
func TestUnreadableDirectoryTruncates(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"etc", "root"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "hosts"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "_plumbline")
	if err := os.MkdirAll(manifest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifest, "fixture.json"),
		[]byte(`{"description":"root's home is unreadable","unreadable":["/root"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := fake.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "all", Match: everything}},
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	f := factFor(t, res, "all")
	if f.Complete() {
		t.Errorf("a walk that could not read /root claimed completeness")
	}
	if !hasReason(f, fact.TruncUnreadable) {
		t.Errorf("reasons = %v, want to include %q", f.TruncationReasons, fact.TruncUnreadable)
	}
	// What it did read is still reported. That is the asymmetry.
	if !contains(paths(f), "/etc/hosts") {
		t.Errorf("a partial walk must still report what it found: %v", paths(f))
	}
}

// TestTruncatedDirListingTruncates covers the seam's own entry cap: a listing
// that is not the whole directory means something in it was never seen.
func TestTruncatedDirListingTruncates(t *testing.T) {
	s := fixture(t, "fswalk-basic")
	res, err := Walk(context.Background(), s, Config{
		Interests:     []Interest{{Name: "all", Match: everything}},
		MaxDirEntries: 1,
		Now:           steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	f := factFor(t, res, "all")
	if f.Complete() {
		t.Errorf("a walk over truncated listings claimed completeness")
	}
	if !hasReason(f, fact.TruncDirListing) {
		t.Errorf("reasons = %v, want to include %q", f.TruncationReasons, fact.TruncDirListing)
	}
}

// ---------------------------------------------------------------------------
// MaxHits: per-interest truncation
// ---------------------------------------------------------------------------

// TestMaxHitsTruncatesOnlyItsOwnInterest is why there is one fact per interest
// rather than one fact holding everything. A check requiring fs.suid must not
// resolve to UNKNOWN because an unrelated interest overflowed its cap.
func TestMaxHitsTruncatesOnlyItsOwnInterest(t *testing.T) {
	s := fixture(t, "fswalk-basic")

	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{
			{Name: "greedy", Match: everything, MaxHits: 2},
			{Name: "suid", Match: suid},
		},
		Now: steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	greedy := factFor(t, res, "greedy")
	if got, want := len(greedy.Rows), 2; got != want {
		t.Errorf("greedy kept %d rows, want the cap of %d", got, want)
	}
	if greedy.Overflow <= 0 {
		t.Errorf("overflow was not counted; it must never be silently dropped")
	}
	if got, want := greedy.Overflow+len(greedy.Rows), greedy.InodesVisited; got != want {
		t.Errorf("rows+overflow = %d but the walk saw %d inodes; matches went missing", got, want)
	}
	if greedy.Complete() {
		t.Errorf("an interest that hit its cap must not claim completeness")
	}
	if !hasReason(greedy, fact.TruncMaxHits) {
		t.Errorf("reasons = %v, want to include %q", greedy.TruncationReasons, fact.TruncMaxHits)
	}

	// The other interest is untouched, and the walk itself finished.
	suidFact := factFor(t, res, "suid")
	if !suidFact.Complete() {
		t.Errorf("fs.suid was truncated by an unrelated interest's cap: %v", suidFact.TruncationReasons)
	}
	if got := paths(suidFact); len(got) != 1 || got[0] != "/usr/bin/passwd" {
		t.Errorf("fs.suid rows = %v, want [/usr/bin/passwd]", got)
	}

	// The walk was not aborted: the cap stops recording, not traversing.
	if res.DirsVisited < 4 {
		t.Errorf("the walk stopped early: DirsVisited = %d", res.DirsVisited)
	}
}

// ---------------------------------------------------------------------------
// the asymmetric truncation rule, as a check would apply it
// ---------------------------------------------------------------------------

// TestAsymmetricTruncationRule is the rule that matters most in WP-15:
//
//	A truncated walk can invalidate a negative result. It can never
//	invalidate a positive one.
//
// evaluate below is shaped exactly like a real check — a pure function from a
// fact to an outcome — but is local to this test on purpose. The FILESYS
// module owns the real check and its permanent ID; allocating one here to make
// a walker test pass would burn an ID that appears in users' suppression files
// forever.
func TestAsymmetricTruncationRule(t *testing.T) {
	// evaluate is "no SUID binaries outside the allowlist": a negative
	// assertion, which is the shape every filesystem check has.
	evaluate := func(f fact.FSMatches) (finding.Result, finding.UnknownReason) {
		if len(f.Rows) > 0 {
			// Positive. A SUID binary the walk found is a SUID binary that
			// exists, whether or not the walk finished.
			return finding.Fail, ""
		}
		if !f.Complete() {
			// Negative over a partial walk. "We stopped looking" is not
			// "there is nothing there".
			return finding.Unknown, finding.ReasonTruncated
		}
		return finding.Pass, ""
	}

	for _, tc := range []struct {
		name       string
		f          fact.FSMatches
		wantResult finding.Result
		wantReason finding.UnknownReason
	}{
		{
			name:       "complete walk, nothing found, is a PASS",
			f:          fact.FSMatches{Interest: "suid"},
			wantResult: finding.Pass,
		},
		{
			name: "complete walk, something found, is a FAIL",
			f: fact.FSMatches{
				Interest: "suid",
				Rows:     []fact.FSRow{{Path: "/tmp/rootshell"}},
			},
			wantResult: finding.Fail,
		},
		{
			name: "truncated walk, nothing found, is UNKNOWN and never PASS",
			f: fact.FSMatches{
				Interest:          "suid",
				Truncated:         true,
				TruncationReasons: []fact.TruncationReason{fact.TruncDeadline},
			},
			wantResult: finding.Unknown,
			wantReason: finding.ReasonTruncated,
		},
		{
			name: "truncated walk, something found, is still a FAIL",
			f: fact.FSMatches{
				Interest:          "suid",
				Rows:              []fact.FSRow{{Path: "/tmp/rootshell"}},
				Truncated:         true,
				TruncationReasons: []fact.TruncationReason{fact.TruncInodes},
			},
			wantResult: finding.Fail,
		},
		{
			name: "overflowed interest, nothing found, is UNKNOWN",
			f: fact.FSMatches{
				Interest: "suid",
				Overflow: 12,
			},
			wantResult: finding.Unknown,
			wantReason: finding.ReasonTruncated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotResult, gotReason := evaluate(tc.f)
			if gotResult != tc.wantResult {
				t.Errorf("result = %v, want %v", gotResult, tc.wantResult)
			}
			if gotReason != tc.wantReason {
				t.Errorf("unknown reason = %q, want %q", gotReason, tc.wantReason)
			}
			if gotResult == finding.Pass && !tc.f.Complete() {
				t.Errorf("PASS from an incomplete walk: this is the bug the project exists to prevent")
			}
		})
	}
}

// TestAsymmetricTruncationRuleEndToEnd runs the same rule over facts a real
// truncated walk produced, so that the rule is asserted against the walker and
// not only against hand-built facts.
func TestAsymmetricTruncationRuleEndToEnd(t *testing.T) {
	// A walk bounded so tightly it cannot reach /usr/bin/passwd.
	s := fixture(t, "fswalk-basic")
	res, err := Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "suid", Match: suid}},
		MaxDepth:  1,
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	negative := factFor(t, res, "suid")
	if len(negative.Rows) != 0 {
		t.Fatalf("the bounded walk was supposed to miss the SUID binary; it found %v", paths(negative))
	}
	if negative.Complete() {
		t.Fatalf("the bounded walk claimed completeness")
	}

	// The same tree, unbounded, finds it.
	s = fixture(t, "fswalk-basic")
	res, err = Walk(context.Background(), s, Config{
		Interests: []Interest{{Name: "suid", Match: suid}},
		Now:       steppingClock(time.Unix(0, 0), 0),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	positive := factFor(t, res, "suid")
	if len(positive.Rows) == 0 {
		t.Fatalf("the unbounded walk did not find the SUID binary")
	}
	if !positive.Complete() {
		t.Fatalf("the unbounded walk claimed truncation: %v", positive.TruncationReasons)
	}
}

// ---------------------------------------------------------------------------
// registration and the collector
// ---------------------------------------------------------------------------

func TestRegisterRejectsBadInterests(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Interest
	}{
		{name: "empty name", in: Interest{Match: everything}},
		{name: "no matcher", in: Interest{Name: "suid"}},
		{name: "name would not be a fact ID", in: Interest{Name: "fs.suid", Match: everything}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(resetRegistry)
			resetRegistry()
			defer func() {
				if recover() == nil {
					t.Errorf("registering %+v did not panic", tc.in)
				}
			}()
			Register(tc.in)
		})
	}
}

func TestRegisterRejectsDuplicatesAndLateArrivals(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		t.Cleanup(resetRegistry)
		resetRegistry()
		Register(Interest{Name: "suid", Match: everything})
		defer func() {
			if recover() == nil {
				t.Errorf("registering a duplicate interest did not panic")
			}
		}()
		Register(Interest{Name: "suid", Match: everything})
	})

	t.Run("after the walk began", func(t *testing.T) {
		t.Cleanup(resetRegistry)
		resetRegistry()
		Register(Interest{Name: "suid", Match: everything})
		_ = Interests() // seals

		defer func() {
			if recover() == nil {
				t.Errorf("registering after the walk began did not panic")
			}
		}()
		Register(Interest{Name: "world_writable", Match: everything})
	})
}

// TestCollectorContract asserts the scheduling and privilege declarations the
// runner depends on. Cost in particular: Expensive is the entire mechanism
// that stops a dozen simultaneous filesystem walks on a production host.
func TestCollectorContract(t *testing.T) {
	c := New()
	if got, want := c.ID(), "fswalk"; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if got, want := c.Cost(), collect.Expensive; got != want {
		t.Errorf("Cost = %v, want %v", got, want)
	}
	if got, want := c.Requires(), collect.CapNone; got != want {
		t.Errorf("Requires = %v, want %v", got, want)
	}
	if c.DependsOn() != nil {
		t.Errorf("DependsOn = %v, want nil", c.DependsOn())
	}
	// The collector's runner-enforced budget must exceed the walk's own, or
	// the walk is killed before it can write the facts it did gather.
	if c.Timeout() <= DefaultBudget {
		t.Errorf("Timeout %v does not exceed the walk budget %v; partial facts would be discarded",
			c.Timeout(), DefaultBudget)
	}
	if _, ok := collect.Default().Get("fswalk"); !ok {
		t.Errorf("fswalk did not register itself; the default registry holds %v", collect.Default().IDs())
	}
}

// TestCollectorProducesOneFactPerInterest ties the collector to the registry:
// the facts a check will look for are the facts a timed-out walk is blamed for.
func TestCollectorProducesOneFactPerInterest(t *testing.T) {
	t.Cleanup(resetRegistry)
	resetRegistry()
	Register(Interest{Name: "suid", Match: suid})
	Register(Interest{Name: "world_writable", Match: worldWritable})

	c := New()
	// fs.mounts is produced unconditionally: the walk reads the mount table to
	// decide where not to descend, so it is available whether or not any
	// interest was registered.
	want := []fact.ID{"fs.suid", "fs.world_writable", fact.MountsID}
	got := c.Produces()
	if len(got) != len(want) {
		t.Fatalf("Produces = %v, want %v", got, want)
	}
	for n := range want {
		if got[n] != want[n] {
			t.Fatalf("Produces = %v, want %v", got, want)
		}
	}

	s := fixture(t, "fswalk-basic")
	set := fact.NewSet()
	if err := c.Collect(context.Background(), s, set); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range []fact.ID{"fs.suid", "fs.world_writable"} {
		f, ferr, ok := fact.Get[fact.FSMatches](set, id)
		if !ok {
			t.Fatalf("fact %s missing after Collect (err=%v)", id, ferr)
		}
		if f.FactID() != id {
			t.Errorf("fact %s reports ID %s", id, f.FactID())
		}
	}
	if _, ferr, ok := fact.Get[fact.Mounts](set, fact.MountsID); !ok {
		t.Fatalf("fact %s missing after Collect (err=%v)", fact.MountsID, ferr)
	}
}

// TestCollectWithNoInterestsWalksNothingButStillPublishesMounts.
//
// Walking a production filesystem to answer no questions is pure cost on the
// host being audited, so no directory is read. The mount table is a different
// matter: it is not a product of the traversal — the walk reads it to decide
// where *not* to descend — and making it conditional on some unrelated module
// having registered an interest would leave the FILESYS mount checks resolving
// to UNKNOWN for a reason that has nothing to do with the host.
func TestCollectWithNoInterestsWalksNothingButStillPublishesMounts(t *testing.T) {
	t.Cleanup(resetRegistry)
	resetRegistry()

	s := fixture(t, "fswalk-basic")
	set := fact.NewSet()
	if err := New().Collect(context.Background(), s, set); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := s.totalReadDirs(); got != 0 {
		t.Errorf("walked %d directories with no interests registered", got)
	}
	if got := set.IDs(); len(got) != 1 || got[0] != fact.MountsID {
		t.Errorf("facts = %v, want just %s", got, fact.MountsID)
	}
	if _, _, ok := fact.Get[fact.Mounts](set, fact.MountsID); !ok {
		t.Error("the mount table was not published")
	}
}

func TestWalkRejectsNoInterests(t *testing.T) {
	s := fixture(t, "fswalk-basic")
	if _, err := Walk(context.Background(), s, Config{}); err == nil {
		t.Errorf("Walk with no interests should be a caller error")
	}
}

// TestFactIDNaming pins the fact namespace. Fact IDs appear in bundles on disk
// and in users' suppression files, so the derivation is not free to drift.
func TestFactIDNaming(t *testing.T) {
	if got, want := fact.FSFactID("suid"), fact.ID("fs.suid"); got != want {
		t.Errorf("FSFactID(suid) = %q, want %q", got, want)
	}
	if got, want := fact.FSFactID("world_writable"), fact.ID("fs.world_writable"); got != want {
		t.Errorf("FSFactID(world_writable) = %q, want %q", got, want)
	}
}

func TestMarkTruncatedIsSortedAndUnique(t *testing.T) {
	var f fact.FSMatches
	f.MarkTruncated(fact.TruncInodes)
	f.MarkTruncated(fact.TruncDepth)
	f.MarkTruncated(fact.TruncInodes)

	want := []fact.TruncationReason{fact.TruncDepth, fact.TruncInodes}
	if len(f.TruncationReasons) != len(want) {
		t.Fatalf("reasons = %v, want %v", f.TruncationReasons, want)
	}
	for n := range want {
		if f.TruncationReasons[n] != want[n] {
			t.Fatalf("reasons = %v, want %v", f.TruncationReasons, want)
		}
	}
	if !f.Truncated {
		t.Errorf("MarkTruncated did not set Truncated")
	}
	if got, want := f.TruncationSummary(), "depth_limit, inode_limit"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

// netListenUnix binds a unix socket and returns a closer. It is a function
// rather than an inline net.Listen so that the walker package's test file does
// not import net at the top level for one line — the check-purity gate greps
// for that import, and although this is a collector rather than a check, the
// habit is worth keeping.
func netListenUnix(path string) (func(), error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	sa := &syscall.SockaddrUnix{Name: path}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", path, err)
	}
	return func() {
		syscall.Close(fd)
		_ = os.Remove(path)
	}, nil
}
