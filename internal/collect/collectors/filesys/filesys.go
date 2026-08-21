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
// The module registers both kinds of question the walker supports, and which
// kind a check needs is decided by the shape of the claim rather than by
// convenience:
//
//   - **Interests** are pure predicates over one inode's metadata, recorded as
//     rows. Every rule of the form "no inode should have property P" is one of
//     these, because the answer is a short list of offenders and the walk can
//     hold it.
//
//   - **Tallies** fold every inode into a bounded keyspace. Ownership is the
//     case that forces them. Deciding whether a uid belongs to a real account
//     means joining against /etc/passwd, which does not exist when a predicate
//     is registered; and deferring the join by recording every owned inode as
//     a row would overflow the interest cap in the first populated directory
//     of any host that has users. A uid threshold instead of a join would be a
//     guess, and CONTRIBUTING.md rule 3 forbids guessing. The tally counts owners
//     during the walk and lets FILESYS-0010 do the join where facts live
//     (WP-25).
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

// Tally names. They become fact IDs: "owner_uid" is fs.tally.owner_uid.
const (
	TallyOwnerUID = "owner_uid"
	TallyOwnerGID = "owner_gid"
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

	// Owner tallies. Two rather than one, for the reason SUID and SGID are
	// two: a uid that resolves to nothing and a gid that resolves to nothing
	// are different findings with different remedies, and a single tally could
	// not say which it had counted.
	//
	// Every inode participates, including symlinks, sockets and device nodes.
	// A symlink owned by a uid nobody holds is exactly as much of a finding as
	// a regular file is — more, if someone is using it to hold a name in a
	// directory they no longer own an account in.
	walker.RegisterTally(walker.Tally{
		Name: TallyOwnerUID,
		Key:  func(fi system.FileInfo) (uint64, bool) { return uint64(fi.UID), true },
	})
	walker.RegisterTally(walker.Tally{
		Name: TallyOwnerGID,
		Key:  func(fi system.FileInfo) (uint64, bool) { return uint64(fi.GID), true },
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
