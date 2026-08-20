package fake_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

const corpus = "../../../testdata/fixtures"

// manifest is the subset of a fixture manifest that names paths. Every one of
// these keys describes a path the fixture expects to find in its own tree.
type manifest struct {
	Modes      map[string]string `json:"modes"`
	Owners     map[string]string `json:"owners"`
	Symlinks   map[string]string `json:"symlinks"`
	Inodes     map[string]string `json:"inodes"`
	Unreadable []string          `json:"unreadable"`
	// Unstattable and Missing are the two keys that do not require the path to
	// exist — see namedPaths.
	Unstattable []string `json:"unstattable"`
	Missing     []string `json:"missing"`
}

// TestEveryFixtureSurvivesACheckout is the corpus's own resilience gate, and it
// exists because the failure it catches is invisible in the direction that
// matters.
//
// Git stores files. It does not store an empty directory, and it does not store
// a file nobody added. A fixture whose FAIL case lives in such a path works
// perfectly on the machine that wrote it and arrives in CI as a *different
// tree* — one where the offending inode is simply absent, so the check finds
// nothing wrong and returns PASS. The fixture gate still counts a FAIL case for
// that check, because the gate reads the test source rather than the tree.
//
// That is this project's own failure mode turned on its test corpus: a green
// run that means "we stopped looking" rather than "there is nothing there".
// Three fixtures were in that state when this test was written —
// filesys-suid-writable's setuid helper had never been added to git at all, and
// filesys-sticky and filesys-system-dir each hung their FAIL case on an empty
// directory.
func TestEveryFixtureSurvivesACheckout(t *testing.T) {
	fixtures, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatal(err)
	}

	tracked := gitTrackedPaths(t)
	checked := 0

	for _, f := range fixtures {
		if !f.IsDir() {
			continue
		}
		root := filepath.Join(corpus, f.Name())
		raw, err := os.ReadFile(filepath.Join(root, "_plumbline", "fixture.json"))
		if err != nil {
			continue // not a fixture directory
		}
		var m manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Errorf("%s: manifest is not valid JSON: %v", f.Name(), err)
			continue
		}
		checked++

		absent := map[string]bool{}
		for _, p := range m.Missing {
			absent[path.Clean(p)] = true
		}

		for _, p := range namedPaths(m) {
			if absent[path.Clean(p)] {
				continue
			}
			// A manifest can set a path's mode, ownership or identity. It
			// cannot create the path: fake.infoFor only ever overrides what
			// the tree already holds.
			full := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
			info, err := os.Lstat(full)
			if err != nil {
				t.Errorf("%s: the manifest names %s and the tree does not contain it. A manifest overrides a path's metadata; it cannot conjure the path.",
					f.Name(), p)
				continue
			}
			if info.IsDir() && empty(t, full) {
				t.Errorf("%s: %s is an empty directory, which git cannot store. On a fresh checkout it will not exist, and whatever this fixture proves through it will silently stop being proved. Add a .keep file.",
					f.Name(), p)
			}
		}

		// And the same rule for the whole tree, not only the paths a manifest
		// happens to name.
		if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			if empty(t, p) {
				t.Errorf("%s: %s is an empty directory and will not survive a checkout", f.Name(), p)
			}
			return nil
		}); err != nil {
			t.Errorf("%s: walking the fixture: %v", f.Name(), err)
		}

		if tracked != nil {
			untracked(t, root, tracked)
		}
	}

	if checked == 0 {
		t.Fatal("no fixture was examined; this test would pass on an empty corpus")
	}
	t.Logf("%d fixtures checked", checked)
}

// namedPaths returns every path a manifest refers to.
func namedPaths(m manifest) []string {
	var out []string
	for _, set := range []map[string]string{m.Modes, m.Owners, m.Symlinks, m.Inodes} {
		for p := range set {
			out = append(out, p)
		}
	}
	// Unreadable is included: the fake lets Stat succeed and fails the read,
	// so the path has to be there for the metadata to come from.
	//
	// Unstattable is *not*, and the asymmetry is the point. It fails Stat
	// itself, before the tree is consulted, so a fixture may name a path that
	// does not exist — services-unresolved does exactly that to model an
	// enablement symlink into a directory that refuses traversal, where the
	// question is whether the link dangles and the answer is unknowable.
	return append(out, m.Unreadable...)
}

func empty(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return len(entries) == 0
}

// untracked reports fixture files git does not know about. A file that exists
// only in the author's working tree is the same problem as an empty directory
// and looks identical from inside the test.
func untracked(t *testing.T, root string, tracked map[string]bool) {
	t.Helper()
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !tracked[filepath.ToSlash(filepath.Clean(p))] {
			t.Errorf("%s is not tracked by git. It exists here and will not exist in CI, so whatever it proves is proved only on this machine.", p)
		}
		return nil
	})
}

// gitTrackedPaths returns the corpus files git knows about, or nil when git
// cannot answer — a released tarball has no repository, and this check is a
// convenience for the author rather than a property of the corpus.
func gitTrackedPaths(t *testing.T) map[string]bool {
	t.Helper()
	out, err := exec.Command("git", "ls-files", "--", corpus).Output()
	if err != nil {
		t.Logf("git is unavailable (%v); the untracked-file half of this test is skipped", err)
		return nil
	}
	tracked := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		// git ls-files reports paths relative to the working directory it was
		// run in, which is this package's directory — the same form WalkDir
		// produces below.
		tracked[filepath.ToSlash(filepath.Clean(line))] = true
	}
	return tracked
}
