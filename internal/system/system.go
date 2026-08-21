// Package system is the single seam between Plumbline and the operating
// system. Nothing outside this package may call os.Open, os.ReadFile,
// exec.Command, or read /proc directly. That rule is what makes every check
// testable against fixtures; see CONTRIBUTING.md and docs/FIXTURES.md.
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

// DefaultMaxDirEntries is the entry cap applied to a single ReadDir when the
// caller does not specify one.
//
// It is a policy number, like DefaultMaxRead. The largest legitimate system
// directory on a fat distribution holds a few thousand entries; a mail spool, a
// session directory or an attacker's scratch space holds millions. 100,000 is
// generous enough that no honest directory reaches it and small enough that the
// slice it bounds stays in tens of megabytes — which matters because the
// process reading it may be root and the directory may not be honest.
const DefaultMaxDirEntries = 100_000

// Sentinel errors. Callers compare with errors.Is; collectors translate these
// into typed fact errors so that dependent checks resolve to UNKNOWN rather
// than to a wrong verdict.
var (
	ErrNotExist    = errors.New("does not exist")
	ErrPermission  = errors.New("permission denied")
	ErrNotRegular  = errors.New("not a regular file")
	ErrNotSymlink  = errors.New("not a symbolic link")
	ErrEscapesRoot = errors.New("path escapes scan root")
	ErrUnsupported = errors.New("unsupported on this system")
)

// FileInfo is a flattened, serialisable stat result. It deliberately does not
// embed fs.FileInfo: everything a fact may carry has to survive a round trip
// through a bundle on disk.
type FileInfo struct {
	Path      string      `json:"path"`
	Mode      fs.FileMode `json:"mode"`
	UID       uint32      `json:"uid"`
	GID       uint32      `json:"gid"`
	Size      int64       `json:"size"`
	ModTime   time.Time   `json:"mod_time"`
	IsDir     bool        `json:"is_dir"`
	IsRegular bool        `json:"is_regular"`
	IsSymlink bool        `json:"is_symlink"`

	// Dev and Ino identify the inode. Together they are what lets the shared
	// walker detect a bind-mount or hardlink cycle: a tree that contains itself
	// is infinite, and a depth limit terminates such a walk without being able
	// to tell it apart from a legitimately deep one (ADR-0012).
	//
	// They are flattened integers rather than a syscall.Stat_t on purpose.
	// Everything a fact carries must survive a round trip through JSON in a
	// bundle, and no syscall type may reach a check.
	//
	// Zero means not recorded. Inode 0 is not a valid inode and device 0 is not
	// a real device for a file, so the zero value is unambiguous.
	Dev uint64 `json:"dev,omitempty"`
	Ino uint64 `json:"ino,omitempty"`
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

// DirResult is a directory listing plus whether it is the whole directory.
type DirResult struct {
	Path    string     `json:"path"`
	Entries []FileInfo `json:"entries"`
	// Truncated means this listing is not the complete contents of the
	// directory, for either of two reasons: the entry cap was reached, or an
	// entry could not be stat'ed and was therefore omitted. Both have the same
	// consequence for a caller, which is why they share one flag — nothing may
	// conclude that a file is absent from a truncated listing.
	Truncated bool `json:"truncated,omitempty"`
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

	// ReadDir lists a directory without following symlinks, reading at most
	// maxEntries of them (DefaultMaxDirEntries when <= 0).
	//
	// The cap is why this returns a DirResult rather than a slice. A bounded
	// read that returned the first N entries and nothing else would let a
	// caller conclude a file is absent from a directory it only partly saw,
	// which is the same false assurance as reporting PASS for something never
	// examined. DirResult.Truncated is the caller's warning not to conclude
	// absence.
	ReadDir(path string, maxEntries int) (DirResult, error)

	// Readlink returns the contents of a symbolic link without resolving it.
	//
	// The value is the target *as written*, which may be relative and may name
	// a path that does not exist. Both are load-bearing: systemd's enablement
	// symlinks are the record of what an administrator turned on, and a link
	// pointing at a unit file that was uninstalled is a service the operator
	// believes is running and which systemd silently never starts.
	//
	// Resolution is the caller's job, and it must go back through this
	// interface — Stat on the resolved path — so that --root still applies.
	// A seam method that returned a resolved absolute path would have
	// dereferenced it against the real host, which is precisely what --root
	// exists to prevent.
	//
	// A path that is not a symlink returns ErrNotSymlink rather than the
	// platform's EINVAL, so that live and fake agree.
	Readlink(path string) (string, error)

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
