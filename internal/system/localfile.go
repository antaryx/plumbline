package system

import (
	"fmt"
	"io"
	"io/fs"
	"os"
)

// Local files are the ones the operator named on the command line: the bundle
// a scan writes, the bundle an evaluation reads. They live here because this
// package is the only place allowed to touch the operating system (CONTRIBUTING.md
// rule 1) and that rule is enforced mechanically over every other directory.
//
// They are deliberately *not* part of the System interface. System is the
// observation seam — everything it opens is a fact about the host being
// audited, is interpreted beneath --root, and is faked in tests. An output
// path is none of those things: it is an instruction, it is relative to the
// operator's own filesystem rather than to the scan root, and prefixing it
// with --root would write the bundle inside the image being scanned.

// BundleMode is the permission a bundle is created with.
//
// A bundle carries the user list, open ports, package inventory and file
// paths of the host it describes (docs/DATA-MODEL.md §6.1). It is a complete
// reconnaissance package, and a world-readable one on a shared machine hands
// that to whoever is next to log in.
const BundleMode fs.FileMode = 0o600

// CreateBundle creates or truncates path for writing, owner-only.
//
// The mode is applied explicitly after opening rather than relying on the
// create mode, because O_CREATE only sets permissions on a file that did not
// already exist: overwriting yesterday's world-readable bundle would otherwise
// leave it world-readable.
func CreateBundle(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, BundleMode)
	if err != nil {
		return nil, fmt.Errorf("creating bundle %s: %w", path, err)
	}
	if err := f.Chmod(BundleMode); err != nil {
		f.Close()
		return nil, fmt.Errorf("securing bundle %s: %w", path, err)
	}
	return f, nil
}

// ScriptMode is the permission a generated remediation script is created with.
//
// **0700, and the difference from BundleMode is the execute bit rather than the
// secrecy.** A remediation script is a list of the exact commands that would
// change this host's security posture, written by a tool an operator trusts. On
// a shared machine a world-writable or group-writable copy is an invitation to
// edit it between the review and the run, which is the one window where nobody
// is looking at it — so owner-only, and executable because the operator asked
// for a script rather than a document.
const ScriptMode fs.FileMode = 0o700

// CreateScript creates or truncates path for writing an executable script,
// owner-only.
//
// The mode is applied explicitly after opening for the reason CreateBundle
// does: O_CREATE sets permissions only on a file that did not already exist, so
// overwriting yesterday's group-readable script would otherwise leave it that
// way.
func CreateScript(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ScriptMode)
	if err != nil {
		return nil, fmt.Errorf("creating script %s: %w", path, err)
	}
	if err := f.Chmod(ScriptMode); err != nil {
		f.Close()
		return nil, fmt.Errorf("securing script %s: %w", path, err)
	}
	return f, nil
}

// OpenLocal opens a file the operator named, for reading.
func OpenLocal(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return f, nil
}

// CreateLocal creates or truncates a file the operator named for output that
// is not a bundle — a findings document, say. Reports are less sensitive than
// bundles but not public, so they inherit the same mode.
func CreateLocal(path string) (*os.File, error) { return CreateBundle(path) }

// LocalExists reports whether a path the operator named is present. It exists
// so that the CLI can check for a config file without reaching for os.Stat
// outside this package, which the seam gate forbids and which is exactly the
// habit the gate exists to catch early.
func LocalExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsTerminal reports whether w is a character device — a terminal rather than
// a file, a pipe or a test buffer.
//
// It lives here for the reason CreateBundle does: this package is the only one
// allowed to touch the operating system, and asking the kernel what an open
// file descriptor is counts. It is deliberately *not* on the System interface,
// because it is not an observation about the host being audited — it is a
// property of this process's own output, and running it beneath --root would
// be meaningless.
//
// It is the third and weakest of the three colour rules. --no-color and
// NO_COLOR are statements of intent; this one is an inference, and it exists
// so that `plumbline scan > report.txt` produces a file without escape
// sequences in it without the operator having to remember a flag.
//
// Anything that is not an *os.File is not a terminal, which is the answer that
// keeps a test buffer's output free of ANSI without the test having to say so.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		// A descriptor we cannot describe is not one we should write escape
		// sequences to.
		return false
	}
	return info.Mode()&fs.ModeCharDevice != 0
}
