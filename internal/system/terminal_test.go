package system_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/antaryx/plumbline/internal/system"
)

// A buffer is not a terminal and must not be given a guessed width: a caller
// that receives one would wrap an artifact somebody redirected to a file.
func TestABufferHasNoWidth(t *testing.T) {
	if w, ok := system.TerminalWidth(&bytes.Buffer{}); ok {
		t.Errorf("a bytes.Buffer reported width %d", w)
	}
}

// A pipe is a *os.File and is still not a terminal, which is the case the type
// assertion alone would let through.
func TestAPipeHasNoWidth(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	if got, ok := system.TerminalWidth(w); ok {
		t.Errorf("a pipe reported width %d", got)
	}
}

// /dev/tty when the test has one: the only assertion available is that a
// terminal reports a positive width, since the number is the operator's.
func TestARealTerminalReportsAPositiveWidth(t *testing.T) {
	f, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no controlling terminal")
	}
	defer f.Close()

	got, ok := system.TerminalWidth(f)
	if !ok {
		t.Skip("terminal did not report a size")
	}
	if got <= 0 {
		t.Errorf("width %d", got)
	}
}
