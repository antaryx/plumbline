package collect_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// ResolveLinks is the one place in this program that deliberately follows a
// symbolic link, so it is the one place where getting the bound wrong turns a
// hostile filesystem into a hang or a wrong read. The cases below are the ones
// that matter: a chain that ends, a chain that does not, and a link into
// something that is not a file.
//
// The trees are generated rather than committed, for the reason
// docs/FIXTURES.md gives about the hostile corpus: a symlink loop is not file
// contents, and a committed one is something every tool that walks testdata/
// has to survive.

// linkTree writes files and symlinks into a temporary directory and returns a
// seam over it. links maps a path to its target exactly as it will be written,
// so a relative target stays relative — which is what the distributions this
// exists for actually ship.
func linkTree(t *testing.T, files map[string]string, links map[string]string) system.System {
	t.Helper()
	dir := t.TempDir()

	for p, content := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for p, target := range links {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}

	sys, err := fake.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return sys
}

// TestResolveLinksReachesTheFileADistributionMeant covers the two shapes that
// exist on real hosts: /etc/os-release on anything with systemd, and Red Hat's
// PAM stacks, which are a link into a link.
func TestResolveLinksReachesTheFileADistributionMeant(t *testing.T) {
	t.Run("a regular file resolves to itself", func(t *testing.T) {
		sys := linkTree(t, map[string]string{"/etc/os-release": "PRETTY_NAME=\"x\"\n"}, nil)

		got, err := collect.ResolveLinks(sys, "/etc/os-release")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if got != "/etc/os-release" {
			t.Errorf("resolved to %q, want the path itself", got)
		}
	})

	t.Run("one relative hop, as every systemd distribution ships it", func(t *testing.T) {
		sys := linkTree(t,
			map[string]string{"/usr/lib/os-release": "PRETTY_NAME=\"x\"\n"},
			map[string]string{"/etc/os-release": "../usr/lib/os-release"})

		got, err := collect.ResolveLinks(sys, "/etc/os-release")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if got != "/usr/lib/os-release" {
			t.Errorf("resolved to %q, want /usr/lib/os-release", got)
		}
	})

	t.Run("a chain, as Red Hat ships its PAM stacks", func(t *testing.T) {
		sys := linkTree(t,
			map[string]string{"/etc/authselect/system-auth": "auth required pam_unix.so\n"},
			map[string]string{
				"/etc/pam.d/system-auth":    "system-auth-ac",
				"/etc/pam.d/system-auth-ac": "../authselect/system-auth",
			})

		got, err := collect.ResolveLinks(sys, "/etc/pam.d/system-auth")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if got != "/etc/authselect/system-auth" {
			t.Errorf("resolved to %q", got)
		}
	})
}

// TestResolveLinksIsBounded. A loop and a long chain are the two ways a
// filesystem stops this terminating, and neither may hang: the process may be
// root, and a scan that never returns is one an operator kills without a
// report.
func TestResolveLinksIsBounded(t *testing.T) {
	t.Run("a loop ends in an error, not a hang", func(t *testing.T) {
		sys := linkTree(t, nil, map[string]string{
			"/etc/a": "b",
			"/etc/b": "a",
		})

		_, err := collect.ResolveLinks(sys, "/etc/a")
		if !errors.Is(err, collect.ErrLinkChainTooLong) {
			t.Errorf("err = %v, want ErrLinkChainTooLong", err)
		}
	})

	t.Run("a link to itself ends in an error", func(t *testing.T) {
		sys := linkTree(t, nil, map[string]string{"/etc/self": "self"})

		_, err := collect.ResolveLinks(sys, "/etc/self")
		if !errors.Is(err, collect.ErrLinkChainTooLong) {
			t.Errorf("err = %v, want ErrLinkChainTooLong", err)
		}
	})

	t.Run("a chain past the bound ends in an error", func(t *testing.T) {
		links := map[string]string{}
		for i := 0; i < collect.MaxLinkHops+3; i++ {
			links["/etc/link"+itoa(i)] = "link" + itoa(i+1)
		}
		files := map[string]string{"/etc/link" + itoa(collect.MaxLinkHops+3): "end\n"}
		sys := linkTree(t, files, links)

		_, err := collect.ResolveLinks(sys, "/etc/link0")
		if !errors.Is(err, collect.ErrLinkChainTooLong) {
			t.Errorf("err = %v, want ErrLinkChainTooLong", err)
		}
	})

	t.Run("a chain within the bound resolves", func(t *testing.T) {
		links := map[string]string{}
		for i := 0; i < collect.MaxLinkHops-1; i++ {
			links["/etc/link"+itoa(i)] = "link" + itoa(i+1)
		}
		end := "/etc/link" + itoa(collect.MaxLinkHops-1)
		sys := linkTree(t, map[string]string{end: "end\n"}, links)

		got, err := collect.ResolveLinks(sys, "/etc/link0")
		if err != nil {
			t.Fatalf("err = %v; a chain one short of the bound must resolve", err)
		}
		if got != end {
			t.Errorf("resolved to %q, want %q", got, end)
		}
	})
}

// TestResolveLinksReportsWhatItCouldNotSee. Every failure returns the seam's
// own error so a collector can tell "not there" from "not allowed" — the
// difference between NOT_APPLICABLE and UNKNOWN.
func TestResolveLinksReportsWhatItCouldNotSee(t *testing.T) {
	t.Run("a dangling link is ErrNotExist", func(t *testing.T) {
		sys := linkTree(t, nil, map[string]string{"/etc/os-release": "../usr/lib/os-release"})

		_, err := collect.ResolveLinks(sys, "/etc/os-release")
		if !errors.Is(err, system.ErrNotExist) {
			t.Errorf("err = %v, want ErrNotExist", err)
		}
	})

	t.Run("an absent path is ErrNotExist", func(t *testing.T) {
		sys := linkTree(t, nil, nil)

		_, err := collect.ResolveLinks(sys, "/etc/os-release")
		if !errors.Is(err, system.ErrNotExist) {
			t.Errorf("err = %v, want ErrNotExist", err)
		}
	})
}

// TestResolveLinksDoesNotOpenAnything is the property that keeps this from
// being a way around O_NOFOLLOW.
//
// It resolves a path and stops. Deciding whether the thing at the end may be
// read is the caller's, through the seam, which still refuses a directory, a
// FIFO or a device. If this function ever grew a read of its own, that refusal
// would be somewhere else and eventually somewhere weaker.
func TestResolveLinksDoesNotOpenAnything(t *testing.T) {
	sys := linkTree(t, nil, map[string]string{"/etc/os-release": "../var"})
	if err := os.MkdirAll(filepath.Join(t.TempDir(), "unused"), 0o755); err != nil {
		t.Fatal(err)
	}

	// /var does not exist in this tree, so resolution reports that rather than
	// anything about readability: the question was never asked here.
	_, err := collect.ResolveLinks(sys, "/etc/os-release")
	if !errors.Is(err, system.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
