package system

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// TerminalWidth reports how many columns the terminal behind w currently has.
//
// **It is in this package because of the seam.** Nothing outside
// internal/system may touch the OS directly (CONTRIBUTING.md), and asking a
// file descriptor how wide it is is exactly that. The renderer that needs the
// number takes it as an injected function, which is also what lets a test drive
// a layout at eighteen columns without owning a terminal.
//
// **It is asked freshly every time rather than cached.** The alternative is a
// SIGWINCH handler and a mutex-guarded cached width, which is more moving parts
// for a worse answer: the handler can miss a resize that happens while the
// process is not scheduled, and a cache can be stale at exactly the moment a
// line is drawn. One ioctl costs about a microsecond and a scan draws a few
// hundred lines, so the total is noise against a filesystem walk — and every
// line is laid out against the width the terminal has at the instant it is
// written. Resizing mid-scan therefore reflows from the next line onward,
// which is the behaviour a person expects and the strongest guarantee
// available: already-printed lines are somebody else's scrollback and cannot
// be reflowed by anyone.
//
// The bool is false for anything that is not a terminal — a pipe, a file, a
// test buffer — and for a terminal that will not answer. A caller that gets
// false must not guess 80: a guessed width on a redirected stream is a wrapped
// artifact nobody asked for.
func TerminalWidth(w io.Writer) (int, bool) {
	f, ok := w.(*os.File)
	if !ok {
		return 0, false
	}

	var ws struct {
		rows, cols, xpixel, ypixel uint16
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	// A zero column count is what a terminal reports when it does not know —
	// inside some CI pty allocations, and on a serial console that never
	// negotiated a size. It is not a width, so it is not returned as one.
	if errno != 0 || ws.cols == 0 {
		return 0, false
	}
	return int(ws.cols), true
}
