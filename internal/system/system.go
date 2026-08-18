// Package system is the single seam between Plumbline and the operating
// system. Nothing outside this package may call os.Open, os.ReadFile,
// exec.Command, or read /proc directly. That rule is what makes every check
// testable against fixtures; see CLAUDE.md and docs/FIXTURES.md.
//
// This is the v0.1 subset of the interface described in ARCHITECTURE.md §2.1.
// Methods are added as collectors need them, never speculatively.
package system

import (
	"context"
	"errors"
	"io/fs"
	"time"
)

// DefaultMaxRead is the byte cap applied to a single ReadFile when the caller
// does not specify one. A hostile or broken /etc file must never be able to
// exhaust memory in a root-privileged process.
const DefaultMaxRead int64 = 8 << 20 // 8 MiB

// Sentinel errors. Callers compare with errors.Is; collectors translate these
// into typed fact errors so that dependent checks resolve to UNKNOWN rather
// than to a wrong verdict.
var (
	ErrNotExist    = errors.New("does not exist")
	ErrPermission  = errors.New("permission denied")
	ErrNotRegular  = errors.New("not a regular file")
	ErrEscapesRoot = errors.New("path escapes scan root")
	ErrUnsupported = errors.New("unsupported on this system")
)

// FileInfo is a flattened, serialisable stat result. It deliberately does not
// embed fs.FileInfo: everything a fact may carry has to survive a round trip
// through a bundle on disk.
type FileInfo struct {
	Path       string      `json:"path"`
	Mode       fs.FileMode `json:"mode"`
	UID        uint32      `json:"uid"`
	GID        uint32      `json:"gid"`
	Size       int64       `json:"size"`
	ModTime    time.Time   `json:"mod_time"`
	IsDir      bool        `json:"is_dir"`
	IsRegular  bool        `json:"is_regular"`
	IsSymlink  bool        `json:"is_symlink"`
	LinkTarget string      `json:"link_target,omitempty"`
}

// ReadResult carries file contents plus the provenance a Finding needs to cite
// as evidence. SHA256 is over the bytes actually read.
type ReadResult struct {
	Path      string `json:"path"`
	Data      []byte `json:"-"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	SHA256    string `json:"sha256"`
}

// ExecResult is the outcome of running an external command. Argv is retained so
// that evidence can state exactly what was run.
type ExecResult struct {
	Argv     []string `json:"argv"`
	Stdout   []byte   `json:"-"`
	Stderr   []byte   `json:"-"`
	ExitCode int      `json:"exit_code"`
}

// System is implemented by live (real host), rooted (--root prefixed), and
// fake (fixture backed). All paths passed in are absolute and interpreted
// relative to Root().
type System interface {
	// Root returns the scan root: "" or "/" for a live scan, "/mnt/host" when
	// scanning a mounted image or a container's host mount.
	Root() string

	// Stat never follows a terminal symlink; IsSymlink reports whether the
	// path itself is one.
	Stat(path string) (FileInfo, error)

	// ReadFile reads at most maxBytes (DefaultMaxRead when <= 0). It refuses
	// anything that is not a regular file, which is what stops a root process
	// from blocking forever on an unprivileged user's FIFO.
	ReadFile(path string, maxBytes int64) (ReadResult, error)

	// ReadDir returns entries without following symlinks.
	ReadDir(path string) ([]FileInfo, error)

	// Glob expands a shell-style pattern against the scan root. Used by
	// sshd_config Include resolution. It never matches outside the root.
	Glob(pattern string) ([]string, error)

	// Exec runs argv with a sanitised environment (LC_ALL=C, TZ=UTC, minimal
	// PATH). There is no shell: argv is never a command string.
	Exec(ctx context.Context, argv []string) (ExecResult, error)

	// Now is injectable so that time-dependent checks are deterministic.
	Now() time.Time

	// Euid reports the effective uid the scan is running as, used to decide
	// SKIPPED-for-privilege rather than guessing.
	Euid() int
}
