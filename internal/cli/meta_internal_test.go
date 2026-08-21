// This file is package cli rather than cli_test for the reason
// format_internal_test.go is: readOSRelease is a detail of how the report
// labels itself, not surface, and it is not going to be exported.
package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/system/live"
)

// These run against the LIVE seam rather than the fake, and that is the point.
//
// The bug this fixes was invisible for four releases precisely because it lived
// in the seam's behaviour rather than in any logic: the seam opens privileged
// reads with O_NOFOLLOW, /etc/os-release is a symlink on every systemd
// distribution since the file moved to /usr/lib, the read failed, hostMeta
// discarded the error, and every report from Ubuntu, Debian, Fedora and RHEL
// carried an empty os_release with nothing anywhere saying why. A fake that
// resolved links differently from the kernel would have let it back in.
//
// The trees are built at test time. docs/FIXTURES.md keeps the hostile corpus
// out of the repository for the same reason: a symlink loop is not file
// contents, and a committed one is something every tool that walks testdata/
// has to survive.

// osTree writes an os-release layout under a temporary root and returns a live
// seam over it, so every read is subject to the same --root prefixing, escape
// refusal and O_NOFOLLOW as a real scan.
func osTree(t *testing.T, files, links map[string]string) *live.System {
	t.Helper()
	root := t.TempDir()

	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for p, target := range links {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	return live.New(root)
}

const ubuntuOSRelease = `PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
`

// TestOSReleaseIsReadThroughTheSymlinkEveryDistributionShips is the regression
// test for WP-37. Before the fix this case produced an empty string.
func TestOSReleaseIsReadThroughTheSymlinkEveryDistributionShips(t *testing.T) {
	t.Run("a relative link, as Ubuntu and Debian ship it", func(t *testing.T) {
		sys := osTree(t,
			map[string]string{"/usr/lib/os-release": ubuntuOSRelease},
			map[string]string{"/etc/os-release": "../usr/lib/os-release"})

		if got := readOSRelease(sys); got != "Ubuntu 24.04.4 LTS" {
			t.Errorf("os_release = %q, want the PRETTY_NAME through the link", got)
		}
	})

	t.Run("an absolute link resolves inside the scan root", func(t *testing.T) {
		// The distinction that makes --root usable at all. A link reading
		// "/usr/lib/os-release" inside a mounted image must resolve to the
		// image's copy, never to the copy belonging to the machine doing the
		// scanning — otherwise a scan of a Debian image mounted on a Fedora
		// host reports Fedora.
		sys := osTree(t,
			map[string]string{"/usr/lib/os-release": ubuntuOSRelease},
			map[string]string{"/etc/os-release": "/usr/lib/os-release"})

		if got := readOSRelease(sys); got != "Ubuntu 24.04.4 LTS" {
			t.Errorf("os_release = %q; an absolute link did not resolve beneath --root", got)
		}
	})

	t.Run("a plain file still works", func(t *testing.T) {
		sys := osTree(t, map[string]string{"/etc/os-release": ubuntuOSRelease}, nil)

		if got := readOSRelease(sys); got != "Ubuntu 24.04.4 LTS" {
			t.Errorf("os_release = %q", got)
		}
	})
}

// TestOSReleaseFallsBackToTheVendorCopy. os-release(5) specifies the order:
// /etc first because that is where a local override goes, then /usr/lib. A host
// with only the vendor copy is still a host that can say what it is.
func TestOSReleaseFallsBackToTheVendorCopy(t *testing.T) {
	sys := osTree(t, map[string]string{"/usr/lib/os-release": ubuntuOSRelease}, nil)

	if got := readOSRelease(sys); got != "Ubuntu 24.04.4 LTS" {
		t.Errorf("os_release = %q, want the vendor copy", got)
	}
}

// TestOSReleaseStaysSilentRatherThanGuessing.
//
// Every one of these is a host that did not say what it is, and the answer is
// an absent field. meta is descriptive — no check consumes it — so silence
// costs a label on a report. Inventing one would put a fact into a bundle that
// nobody observed, which is the failure this whole project is built against.
func TestOSReleaseStaysSilentRatherThanGuessing(t *testing.T) {
	t.Run("neither file exists", func(t *testing.T) {
		if got := readOSRelease(osTree(t, nil, nil)); got != "" {
			t.Errorf("os_release = %q, want empty", got)
		}
	})

	t.Run("a dangling link", func(t *testing.T) {
		sys := osTree(t, nil, map[string]string{"/etc/os-release": "../usr/lib/os-release"})
		if got := readOSRelease(sys); got != "" {
			t.Errorf("os_release = %q, want empty", got)
		}
	})

	t.Run("a symlink loop", func(t *testing.T) {
		sys := osTree(t, nil, map[string]string{
			"/etc/os-release":     "../usr/lib/os-release",
			"/usr/lib/os-release": "../../etc/os-release",
		})
		if got := readOSRelease(sys); got != "" {
			t.Errorf("os_release = %q, want empty", got)
		}
	})

	t.Run("a file with no PRETTY_NAME", func(t *testing.T) {
		sys := osTree(t, map[string]string{"/etc/os-release": "ID=weird\n"}, nil)
		if got := readOSRelease(sys); got != "" {
			t.Errorf("os_release = %q, want empty", got)
		}
	})

	// The one that matters most. A link at a path this program reads as root
	// is the T-01/T-02 shape, and the seam's O_NOFOLLOW plus O_NONBLOCK is
	// what stops it: the open refuses a FIFO instead of blocking forever
	// waiting for a writer that never comes.
	t.Run("a link to a FIFO is refused, not waited on", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(root, "etc", "trap"), 0o644); err != nil {
			t.Skipf("cannot create a FIFO here: %v", err)
		}
		if err := os.Symlink("trap", filepath.Join(root, "etc", "os-release")); err != nil {
			t.Fatal(err)
		}

		done := make(chan string, 1)
		go func() { done <- readOSRelease(live.New(root)) }()

		select {
		case got := <-done:
			if got != "" {
				t.Errorf("os_release = %q; something was read out of a FIFO", got)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("readOSRelease blocked on a FIFO; O_NONBLOCK is not doing its job")
		}
	})
}

// TestOSReleaseIgnoresAnEmptyHostname is the companion property to the choice
// not to resolve links for /etc/hostname.
//
// No distribution ships that file as a link, so one found there was put there
// by somebody, and following it would put the first line of whatever it points
// at into a field labelled "hostname". The seam refuses it and the field stays
// empty, which is the correct outcome and is asserted here so that a future
// tidy-up does not route both reads through the resolver "for consistency".
func TestOSReleaseIgnoresAnEmptyHostname(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "secret"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret", filepath.Join(root, "etc", "hostname")); err != nil {
		t.Fatal(err)
	}

	m := hostMeta(live.New(root), false)
	if m.Hostname != "" {
		t.Errorf("hostname = %q; a symlink at /etc/hostname was followed", m.Hostname)
	}
}
