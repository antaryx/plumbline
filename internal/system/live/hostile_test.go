package live_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/live"
)

// The hostile corpus is generated rather than committed. A FIFO, a symlink
// chain and a 100 MB file cannot live in git — the first two are not file
// contents and the third would be absurd — so the tests build them, which has
// the side benefit that they exercise the real filesystem rather than a
// recording of one.
//
// Every case here asserts the same three things: it completes, it does not
// panic, and it does not read more than it was allowed to. A scanner that runs
// as root has to survive a host that is actively trying to trap it, and every
// one of these is a real technique rather than a hypothetical (see
// docs/THREAT-MODEL.md T-01, T-02, T-04).

const configPath = "/etc/ssh/sshd_config"

// hostileRoot returns a scan root with an /etc/ssh directory ready for the
// caller to booby-trap.
func hostileRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// withinDeadline runs f and fails the test if it has not returned in time.
// This is not belt and braces: a blocking open on a FIFO never returns, and a
// test that hangs is a worse failure than one that fails, because CI reports it
// as a timeout with no indication of which guard stopped working.
func withinDeadline(t *testing.T, d time.Duration, what string, f func()) time.Duration {
	t.Helper()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		f()
		done <- time.Since(start)
	}()
	select {
	case elapsed := <-done:
		return elapsed
	case <-time.After(d):
		t.Fatalf("%s did not return within %s; the guard that should have stopped it is not firing", what, d)
		return 0
	}
}

// TestFIFOWhereAConfigIsExpected is the acceptance criterion. A FIFO at a path
// a root process is about to read is the cheapest denial of service there is:
// an unprivileged user creates it, the auditor opens it, and the scan blocks
// forever with no output and no explanation.
//
// live.ReadFile opens with O_NONBLOCK so the open itself cannot block, and
// verifies the mode after opening rather than before, which closes the
// check-then-open window. This test proves both fire rather than being
// decorative comments.
func TestFIFOWhereAConfigIsExpected(t *testing.T) {
	root := hostileRoot(t)
	fifo := filepath.Join(root, "etc", "ssh", "sshd_config")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	sys := live.New(root)

	var res system.ReadResult
	var err error
	elapsed := withinDeadline(t, 5*time.Second, "ReadFile on a FIFO", func() {
		res, err = sys.ReadFile(configPath, 0)
	})

	if !errors.Is(err, system.ErrNotRegular) {
		t.Errorf("err = %v, want ErrNotRegular", err)
	}
	if len(res.Data) != 0 {
		t.Errorf("read %d bytes from a FIFO", len(res.Data))
	}
	// "Within milliseconds" is the criterion. The generous bound is for a
	// loaded CI machine; the point is that it is not "never".
	if elapsed > time.Second {
		t.Errorf("took %s to refuse a FIFO; O_NONBLOCK is not doing its job", elapsed)
	}

	// Stat must also survive it, and must say what it is.
	fi, err := sys.Stat(configPath)
	if err != nil {
		t.Errorf("Stat on a FIFO: %v", err)
	}
	if fi.IsRegular {
		t.Error("a FIFO was reported as a regular file")
	}
}

// TestSymlinkChainAndLoop: a chain 40 deep and a loop both have to fail
// gracefully. O_NOFOLLOW refuses the terminal symlink outright, so neither the
// kernel's own ELOOP limit nor our patience is what stops it.
func TestSymlinkChainAndLoop(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, dir string)
	}{
		{"a chain 40 deep", func(t *testing.T, dir string) {
			// The far end is a real file, so the only thing being tested is
			// the chain itself.
			target := filepath.Join(dir, "real")
			if err := os.WriteFile(target, []byte("PermitRootLogin no\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			prev := target
			for i := 40; i >= 1; i-- {
				link := filepath.Join(dir, fmt.Sprintf("link%02d", i))
				if err := os.Symlink(prev, link); err != nil {
					t.Fatal(err)
				}
				prev = link
			}
			if err := os.Symlink(prev, filepath.Join(dir, "sshd_config")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a loop", func(t *testing.T, dir string) {
			a, b := filepath.Join(dir, "sshd_config"), filepath.Join(dir, "b")
			if err := os.Symlink(b, a); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(a, b); err != nil {
				t.Fatal(err)
			}
		}},
		{"a link to itself", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "sshd_config")
			if err := os.Symlink(p, p); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := hostileRoot(t)
			tc.build(t, filepath.Join(root, "etc", "ssh"))
			sys := live.New(root)

			var err error
			withinDeadline(t, 5*time.Second, "ReadFile on "+tc.name, func() {
				_, err = sys.ReadFile(configPath, 0)
			})
			if !errors.Is(err, system.ErrNotRegular) {
				t.Errorf("err = %v, want ErrNotRegular", err)
			}
		})
	}
}

// TestSymlinkToShadowIsNotRead is the acceptance criterion. A symlink at a
// config path pointing at /etc/shadow is a request that the auditor read the
// password hashes and put them in a bundle that gets attached to a ticket.
//
// The refusal does not depend on the file's permissions, which is what makes it
// a control rather than luck: O_NOFOLLOW refuses the link itself, so the answer
// is the same whether the scan is running as root or as nobody.
func TestSymlinkToShadowIsNotRead(t *testing.T) {
	root := hostileRoot(t)

	// A decoy standing in for /etc/shadow, with contents this test can look
	// for. Pointing at the real /etc/shadow would make the assertion depend on
	// the machine's permissions instead of on our guard.
	secret := filepath.Join(root, "decoy-shadow")
	const hash = "root:$6$SUPERSECRETHASH:19000:0:99999:7:::"
	if err := os.WriteFile(secret, []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "etc", "ssh", "sshd_config")); err != nil {
		t.Fatal(err)
	}

	sys := live.New(root)
	res, err := sys.ReadFile(configPath, 0)

	if !errors.Is(err, system.ErrNotRegular) {
		t.Errorf("err = %v, want ErrNotRegular", err)
	}
	if strings.Contains(string(res.Data), "SUPERSECRETHASH") {
		t.Fatal("the contents of the symlink target were read")
	}
	if len(res.Data) != 0 {
		t.Errorf("read %d bytes through a symlink", len(res.Data))
	}

	// And the same applies to the real thing: whatever this machine's
	// permissions are, a link is refused as a link.
	if err := os.Remove(filepath.Join(root, "etc", "ssh", "sshd_config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "etc", "ssh", "sshd_config")); err != nil {
		t.Fatal(err)
	}
	res, err = sys.ReadFile(configPath, 0)
	if !errors.Is(err, system.ErrNotRegular) {
		t.Errorf("err = %v, want ErrNotRegular for a link to /etc/shadow", err)
	}
	if len(res.Data) != 0 {
		t.Errorf("read %d bytes of /etc/shadow", len(res.Data))
	}
}

// TestHugeFileIsCappedAndBounded is the acceptance criterion. A 4 GB
// /etc/passwd is a two-line denial of service against a scanner that reads
// whole files (THREAT-MODEL.md T-04).
//
// The assertion is on allocation as well as on the result: a cap that reads
// everything and then discards the tail is not a cap.
func TestHugeFileIsCappedAndBounded(t *testing.T) {
	const size = 100 << 20 // 100 MB

	root := hostileRoot(t)
	path := filepath.Join(root, "etc", "ssh", "sshd_config")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// A megabyte of real bytes so the head of the file is not all zeros, then
	// a sparse tail: the read cap does not care, and the test stays fast.
	junk := make([]byte, 1<<20)
	for i := range junk {
		junk[i] = byte(i*7 + 13)
	}
	if _, err := f.Write(junk); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	sys := live.New(root)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var res system.ReadResult
	withinDeadline(t, 30*time.Second, "ReadFile on a 100 MB file", func() {
		res, err = sys.ReadFile(configPath, 0)
	})
	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !res.Truncated {
		t.Error("a 100 MB file was not reported as truncated")
	}
	if int64(len(res.Data)) != system.DefaultMaxRead {
		t.Errorf("read %d bytes, want the cap of %d", len(res.Data), system.DefaultMaxRead)
	}
	if res.Size != system.DefaultMaxRead {
		t.Errorf("Size = %d, want the capped size %d", res.Size, system.DefaultMaxRead)
	}

	// A capped read cannot allocate as much as the file it declined to read.
	// The bound is the file size rather than a tuned constant: a growing buffer
	// roughly doubles, and the race detector inflates allocation further, so a
	// tighter number would measure the allocator rather than the guard.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= size {
		t.Errorf("allocated %d bytes reading %d bytes of file; the cap is not bounding the read", allocated, size)
	}

	// The sharper proof: allocation tracks the cap, not the file. An
	// implementation that read everything and trimmed the tail afterwards would
	// allocate 100 MB here too.
	const small = 64 << 10
	runtime.GC()
	runtime.ReadMemStats(&before)
	res, err = sys.ReadFile(configPath, small)
	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("ReadFile with a small cap: %v", err)
	}
	if !res.Truncated || len(res.Data) != small {
		t.Errorf("small cap: truncated=%v, read %d bytes, want %d", res.Truncated, len(res.Data), small)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Errorf("a %d-byte cap allocated %d bytes; the read is sized by the file rather than by the cap", small, allocated)
	}
}

// TestHostileFilenames: names containing newlines and escape sequences must not
// break the directory walk, the glob, or the read. A name is data, and the
// place it stops being data is the renderer, which sanitises it.
func TestHostileFilenames(t *testing.T) {
	root := hostileRoot(t)
	dir := filepath.Join(root, "etc", "ssh", "sshd_config.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	esc := string(rune(0x1b))
	names := []string{
		"10-two" + "\n" + "lines.conf",
		"20-clear" + esc + "[2J" + esc + "[H.conf",
		"30-tab\tand\rcarriage.conf",
		"40-quote\"and'quote.conf",
		"50-\xc3\xa9accented.conf",
	}
	for i, n := range names {
		body := fmt.Sprintf("Port %d\n", 2200+i)
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
			t.Skipf("this filesystem will not accept hostile names: %v", err)
		}
	}

	sys := live.New(root)

	listing, err := sys.ReadDir("/etc/ssh/sshd_config.d", 0)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(listing.Entries) != len(names) {
		t.Errorf("ReadDir returned %d entries, want %d", len(listing.Entries), len(names))
	}
	if listing.Truncated {
		t.Error("a complete listing was reported as truncated")
	}

	matches, err := sys.Glob("/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != len(names) {
		t.Errorf("Glob matched %d files, want %d", len(matches), len(names))
	}

	// And every one of them is readable by the name the walk reported, which is
	// the property that actually matters: a name we cannot round-trip is a file
	// we cannot cite as evidence.
	for _, m := range matches {
		res, err := sys.ReadFile(m, 0)
		if err != nil {
			t.Errorf("ReadFile(%q): %v", m, err)
			continue
		}
		if !strings.HasPrefix(string(res.Data), "Port ") {
			t.Errorf("ReadFile(%q) returned %q", m, res.Data)
		}
	}
}

// TestDirectoryWhereAFileIsExpected: a directory at a config path is a mistake
// as often as an attack, and either way the answer is "that is not a file"
// rather than a read error nobody can interpret.
func TestDirectoryWhereAFileIsExpected(t *testing.T) {
	root := hostileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssh", "sshd_config"), 0o755); err != nil {
		t.Fatal(err)
	}

	sys := live.New(root)
	res, err := sys.ReadFile(configPath, 0)
	if !errors.Is(err, system.ErrNotRegular) {
		t.Errorf("err = %v, want ErrNotRegular", err)
	}
	if len(res.Data) != 0 {
		t.Errorf("read %d bytes from a directory", len(res.Data))
	}

	fi, err := sys.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.IsDir || fi.IsRegular {
		t.Errorf("Stat reported %+v for a directory", fi)
	}
}

// TestEscapingTheRootIsRefused: a path that climbs out of --root must not be
// read, or --root is a suggestion rather than a boundary.
func TestEscapingTheRootIsRefused(t *testing.T) {
	root := hostileRoot(t)
	sys := live.New(root)

	for _, p := range []string{
		"/../../../../etc/shadow",
		"/etc/ssh/../../../etc/shadow",
	} {
		res, err := sys.ReadFile(p, 0)
		// path.Clean folds these to /etc/shadow beneath the root, which does
		// not exist there. Either answer is acceptable; reading the real
		// /etc/shadow is not.
		if err == nil && len(res.Data) > 0 {
			t.Errorf("ReadFile(%q) returned %d bytes", p, len(res.Data))
		}
		if res.Path == "/etc/shadow" && len(res.Data) > 0 {
			t.Errorf("ReadFile(%q) escaped the root", p)
		}
	}
}

// TestReadDirIsBoundedAndSaysSo covers the cap added for the shared walker. A
// bounded listing that did not admit it were bounded would let a caller
// conclude a file is absent from a directory it only partly saw — the same
// false assurance as reporting PASS for something never examined.
func TestReadDirIsBoundedAndSaysSo(t *testing.T) {
	root := hostileRoot(t)
	dir := filepath.Join(root, "etc", "ssh", "sshd_config.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const total = 50
	for i := 0; i < total; i++ {
		name := filepath.Join(dir, fmt.Sprintf("%03d.conf", i))
		if err := os.WriteFile(name, []byte("Port 22\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sys := live.New(root)

	// Under the cap: complete, and it says so.
	full, err := sys.ReadDir("/etc/ssh/sshd_config.d", total)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(full.Entries) != total || full.Truncated {
		t.Errorf("entries=%d truncated=%v, want %d and false", len(full.Entries), full.Truncated, total)
	}
	if full.Path != "/etc/ssh/sshd_config.d" {
		t.Errorf("Path = %q, want the simulated path", full.Path)
	}

	// Over the cap: bounded, and it says so.
	part, err := sys.ReadDir("/etc/ssh/sshd_config.d", 10)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(part.Entries) != 10 {
		t.Errorf("entries = %d, want the cap of 10", len(part.Entries))
	}
	if !part.Truncated {
		t.Fatal("a bounded listing did not report itself truncated; a caller would conclude the rest of the directory does not exist")
	}

	// A cap of zero means the default, not "return nothing".
	def, err := sys.ReadDir("/etc/ssh/sshd_config.d", 0)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(def.Entries) != total || def.Truncated {
		t.Errorf("with maxEntries=0: entries=%d truncated=%v", len(def.Entries), def.Truncated)
	}
}

// TestFileInfoCarriesDeviceAndInode covers what the walker needs for cycle
// detection (ADR-0012). Without it a bind mount pointing at an ancestor makes
// the tree infinite, and a depth limit cannot tell that apart from a
// legitimately deep one.
func TestFileInfoCarriesDeviceAndInode(t *testing.T) {
	root := hostileRoot(t)
	dir := filepath.Join(root, "etc", "ssh")
	a := filepath.Join(dir, "sshd_config")
	b := filepath.Join(dir, "other.conf")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("Port 22\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sys := live.New(root)

	fiA, err := sys.Stat("/etc/ssh/sshd_config")
	if err != nil {
		t.Fatal(err)
	}
	if fiA.Ino == 0 {
		t.Error("Ino is zero; cycle detection has nothing to work with")
	}
	if fiA.Dev == 0 {
		t.Error("Dev is zero; a walk could not tell one filesystem from another")
	}

	// Distinct files are distinct identities...
	fiB, err := sys.Stat("/etc/ssh/other.conf")
	if err != nil {
		t.Fatal(err)
	}
	if fiA.Ino == fiB.Ino {
		t.Errorf("two files share inode %d", fiA.Ino)
	}

	// ...and a hard link is the same identity, which is exactly the case the
	// walker must recognise rather than visit twice.
	link := filepath.Join(dir, "hardlink.conf")
	if err := os.Link(a, link); err != nil {
		t.Skipf("this filesystem will not hard link: %v", err)
	}
	fiLink, err := sys.Stat("/etc/ssh/hardlink.conf")
	if err != nil {
		t.Fatal(err)
	}
	if fiLink.Dev != fiA.Dev || fiLink.Ino != fiA.Ino {
		t.Errorf("a hard link reported a different identity: %d/%d vs %d/%d",
			fiLink.Dev, fiLink.Ino, fiA.Dev, fiA.Ino)
	}

	// The listing carries them too, since that is where the walker gets them.
	listed, err := sys.ReadDir("/etc/ssh", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range listed.Entries {
		if e.Ino == 0 {
			t.Errorf("ReadDir entry %s has no inode", e.Path)
		}
	}
}

// TestReadlinkDoesNotResolveAndDoesNotEscape is the acceptance criterion for
// the seam method WP-21 added.
//
// Readlink is the one seam call whose *result* is attacker-influenced data
// rather than a verdict: it returns whatever string is in the link, and a
// systemd enablement link is written by whoever can write the .wants
// directory. The guarantees that make that safe are that it reads the link
// itself and follows nothing, and that resolving the result is the caller's
// job — through Stat, through the seam, so --root still governs it. A seam
// that resolved the target here would have dereferenced an absolute link
// against the *real* host, which is exactly what --root exists to prevent.
func TestReadlinkDoesNotResolveAndDoesNotEscape(t *testing.T) {
	root := hostileRoot(t)
	dir := filepath.Join(root, "etc", "ssh")
	sys := live.New(root)

	// The absolute target is the systemd case: it names a path inside the
	// simulated system, and there is nothing at it here.
	if err := os.Symlink("/usr/lib/systemd/system/sshd.service", filepath.Join(dir, "absolute")); err != nil {
		t.Fatal(err)
	}
	// A link pointing straight out of the scan root. Reading it is fine; what
	// must not happen is following it.
	if err := os.Symlink("../../../../../../etc/shadow", filepath.Join(dir, "escaping")); err != nil {
		t.Fatal(err)
	}
	// A loop. Readlink terminates on it by construction, because it never
	// takes the second step.
	a, b := filepath.Join(dir, "loop_a"), filepath.Join(dir, "loop_b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "regular"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("returns the target verbatim without resolving it", func(t *testing.T) {
		got, err := sys.Readlink("/etc/ssh/absolute")
		if err != nil {
			t.Fatalf("Readlink: %v", err)
		}
		// Not the root-prefixed path, and not an error for a target that does
		// not exist: a dangling enablement link is the state SERVICES-0004
		// reports, so it has to be readable.
		if got != "/usr/lib/systemd/system/sshd.service" {
			t.Errorf("target = %q, want the string as written", got)
		}
	})

	t.Run("a target outside the root is returned, not followed", func(t *testing.T) {
		got, err := sys.Readlink("/etc/ssh/escaping")
		if err != nil {
			t.Fatalf("Readlink: %v", err)
		}
		if got != "../../../../../../etc/shadow" {
			t.Errorf("target = %q, want the string as written", got)
		}
		// The proof that nothing was dereferenced: the real /etc/shadow is not
		// readable here, and resolving the link through the seam lands inside
		// the scan root, where there is nothing.
		if _, err := sys.ReadFile("/etc/ssh/escaping", 0); !errors.Is(err, system.ErrNotRegular) {
			t.Errorf("ReadFile through the link: err = %v, want ErrNotRegular", err)
		}
	})

	t.Run("a loop terminates", func(t *testing.T) {
		var got string
		var err error
		withinDeadline(t, 5*time.Second, "Readlink on a symlink loop", func() {
			got, err = sys.Readlink("/etc/ssh/loop_a")
		})
		if err != nil {
			t.Fatalf("Readlink: %v", err)
		}
		if !strings.HasSuffix(got, "loop_b") {
			t.Errorf("target = %q, want the link's own contents", got)
		}
	})

	t.Run("a regular file is ErrNotSymlink", func(t *testing.T) {
		// EINVAL translated at the seam, so live and fake agree and a
		// collector can tell "not a link" from "not there" and from "not
		// allowed" without knowing what platform it is on.
		if _, err := sys.Readlink("/etc/ssh/regular"); !errors.Is(err, system.ErrNotSymlink) {
			t.Errorf("err = %v, want ErrNotSymlink", err)
		}
	})

	t.Run("a missing path is ErrNotExist", func(t *testing.T) {
		if _, err := sys.Readlink("/etc/ssh/nothing"); !errors.Is(err, system.ErrNotExist) {
			t.Errorf("err = %v, want ErrNotExist", err)
		}
	})

	t.Run("traversal in the argument stays under the root", func(t *testing.T) {
		// path.Clean folds these to /etc/shadow beneath the scan root, which
		// does not exist there — the same answer TestEscapingTheRootIsRefused
		// asserts for ReadFile. What must never happen is reading the real
		// host's /etc/shadow, or the link at it if one exists.
		for _, p := range []string{
			"/../../../../etc/shadow",
			"/etc/ssh/../../../etc/shadow",
		} {
			if got, err := sys.Readlink(p); err == nil {
				t.Errorf("Readlink(%q) = %q, want an error from beneath the scan root", p, got)
			}
		}
	})
}
