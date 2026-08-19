// Package filesys registers the FILESYS module's questions with the shared
// filesystem walker.
//
// It contains no collector. There is exactly one traversal per scan and it
// belongs to internal/collect/walker; a module gets filesystem facts by
// registering an interest at init, not by walking the tree itself. A second
// walk written "just for now" is a permanent second walk, and on a host with
// ten million inodes it is the difference between a scan that finishes and one
// that does not.
//
// Every interest here is a **pure predicate over one inode's metadata**, which
// is what the walker's Match contract requires: it runs once per inode per
// interest, on a filesystem that may hold millions, before any fact exists.
// That constraint is why this module has no "unowned files" check — deciding
// whether a uid belongs to a real account means joining against /etc/passwd,
// which is not available at registration time, and matching every non-root
// file so a check could do the join afterwards would overflow the interest cap
// on any host that has users. A uid threshold instead of a join would be a
// guess, and CLAUDE.md rule 3 forbids guessing. It needs an aggregating
// interest in the walker, which is a change to WP-15's design rather than a
// check.
package filesys

import (
	"io/fs"
	"strings"

	"github.com/antaryx/plumbline/internal/collect/walker"
	"github.com/antaryx/plumbline/internal/system"
)

// Interest names. They become fact IDs: "suid" is fs.suid.
const (
	InterestSUID       = "suid"
	InterestSGID       = "sgid"
	InterestWorldWrite = "world_writable"
	InterestWorldDir   = "world_writable_dir"
	InterestDevice     = "device_outside_dev"
)

// DevDir is the directory device nodes legitimately live in.
const DevDir = "/dev"

func init() {
	// SUID and SGID are separate interests rather than one, because the two
	// have different consequences and a check reporting both together could
	// not say which it found. A setuid binary runs as its owner — usually
	// root. A setgid one runs with the file's group, which is a narrower but
	// still real escalation, and setgid on a *directory* is an ordinary and
	// legitimate way to share a workspace.
	walker.Register(walker.Interest{
		Name:  InterestSUID,
		Match: func(fi system.FileInfo) bool { return fi.IsRegular && fi.Mode&fs.ModeSetuid != 0 },
	})
	walker.Register(walker.Interest{
		Name: InterestSGID,
		// Regular files only. A setgid directory makes new files inherit the
		// directory's group, which is how a shared project directory is meant
		// to work; recording those would bury the executables that matter
		// under a list of ordinary directories.
		Match: func(fi system.FileInfo) bool { return fi.IsRegular && fi.Mode&fs.ModeSetgid != 0 },
	})

	walker.Register(walker.Interest{
		Name:  InterestWorldWrite,
		Match: worldWritableFile,
	})
	walker.Register(walker.Interest{
		Name:  InterestWorldDir,
		Match: worldWritableDir,
	})

	walker.Register(walker.Interest{
		Name:  InterestDevice,
		Match: deviceOutsideDev,
	})
}

// worldWritableFile matches a non-directory anyone may write.
//
// **Symlinks are excluded, and that exclusion is load-bearing.** A symlink's
// own mode is lrwxrwxrwx on Linux and the kernel ignores it entirely —
// permission is decided by the target. Including them would report every
// symlink on the host as world-writable, which is thousands of findings on a
// stock install, all of them false, and the real ones buried among them.
func worldWritableFile(fi system.FileInfo) bool {
	return !fi.IsDir && !fi.IsSymlink && fi.Mode.Perm()&0o002 != 0
}

// worldWritableDir matches a directory anyone may write.
//
// The sticky bit is deliberately *not* tested here. /tmp is world-writable by
// design and correct with the sticky bit set, so the interest records both
// kinds and the checks classify them: FILESYS-0004 asks whether the sticky bit
// is present, FILESYS-0005 asks whether the directory should be world-writable
// at all. One interest answering both questions keeps the walk cheaper and
// keeps the two checks reading the same evidence.
func worldWritableDir(fi system.FileInfo) bool {
	return fi.IsDir && !fi.IsSymlink && fi.Mode.Perm()&0o002 != 0
}

// deviceOutsideDev matches a block or character device outside /dev.
//
// A device node is a doorway to raw hardware: /dev/sda read directly bypasses
// every file permission on the filesystem above it, and /dev/mem or /dev/kmem
// bypass the kernel's own memory protection. The device driver honours the
// node's mode, not its location — so a node an attacker creates in /tmp or in
// a home directory works exactly as well as the one in /dev, and is not
// removed by anything that tidies /dev.
//
// This is why the walker stats non-regular files rather than skipping them,
// and why it never opens one.
func deviceOutsideDev(fi system.FileInfo) bool {
	if fi.Mode&fs.ModeDevice == 0 {
		return false
	}
	return fi.Path != DevDir && !strings.HasPrefix(fi.Path, DevDir+"/")
}
