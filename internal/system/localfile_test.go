package system_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/antaryx/plumbline/internal/system"
)

// TestIsTerminal. The answer decides whether escape sequences are written, so
// the failure that matters is a false positive: anything this says yes to gets
// ANSI, and ANSI in a file or a log is corruption of something somebody reads
// months later in a viewer that is not a terminal.
func TestIsTerminal(t *testing.T) {
	t.Run("a character device is", func(t *testing.T) {
		f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Skipf("cannot open %s: %v", os.DevNull, err)
		}
		defer f.Close()
		if !system.IsTerminal(f) {
			t.Errorf("%s is a character device and was not recognised as one", os.DevNull)
		}
	})

	t.Run("a regular file is not", func(t *testing.T) {
		f, err := os.Create(filepath.Join(t.TempDir(), "out"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if system.IsTerminal(f) {
			t.Error("a regular file was reported as a terminal")
		}
	})

	t.Run("a pipe is not", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		if system.IsTerminal(w) {
			t.Error("a pipe was reported as a terminal; `plumbline scan | less` would get escape sequences")
		}
	})

	t.Run("a non-file writer is not", func(t *testing.T) {
		if system.IsTerminal(&bytes.Buffer{}) {
			t.Error("a bytes.Buffer was reported as a terminal")
		}
	})

	t.Run("a closed file is not", func(t *testing.T) {
		f, err := os.Create(filepath.Join(t.TempDir(), "closed"))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		// Stat fails on a closed descriptor, and a descriptor we cannot
		// describe is not one to write escape sequences to.
		if system.IsTerminal(f) {
			t.Error("a closed file was reported as a terminal")
		}
	})
}
