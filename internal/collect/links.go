package collect

import (
	"errors"
	"fmt"
	"path"

	"github.com/antaryx/plumbline/internal/system"
)

// MaxLinkHops bounds a symlink chain. Red Hat's /etc/pam.d/system-auth is one
// hop, Ubuntu's /etc/os-release is one hop, and eight is far past anything a
// distribution ships while being nowhere near a chain built to exhaust
// something.
const MaxLinkHops = 8

// ErrLinkChainTooLong reports a symlink chain that did not terminate within
// MaxLinkHops. It is deliberately its own error: a caller has to be able to
// tell "this is a loop or a chain bomb" from "this file is not there", because
// the first is a reason to report UNKNOWN and the second is often a legitimate
// NOT_APPLICABLE.
var ErrLinkChainTooLong = errors.New("symlink chain too long")

// ResolveLinks walks a symlink chain one observed hop at a time and returns
// the path of the first non-symlink it reaches.
//
// **This does not weaken the O_NOFOLLOW seam and must never be changed into
// something that does.** The seam opens every privileged read with O_NOFOLLOW,
// which is what stops a hostile symlink at a configuration path from
// redirecting a root process into /etc/shadow or into a FIFO that never returns
// (THREAT-MODEL.md T-01, T-02). Handing the kernel a path and letting it
// resolve the chain would give exactly that up.
//
// What happens instead is that every hop goes back through the seam — Stat,
// Readlink, resolve, Stat again — so each one is separately subject to the
// scan root, to the escape refusal, and to Readlink returning the target as
// written rather than as resolved (ADR-0017). The caller's final ReadFile still
// refuses a symlink, a FIFO, a device and a directory. Four properties follow,
// and they are the whole justification for this function existing:
//
//   - **Bounded.** A loop or a chain bomb ends at MaxLinkHops with an error,
//     not with a hang or a stack overflow.
//   - **Contained.** Resolution is textual and then re-enters the seam, so a
//     link pointing at /etc/shadow under --root /mnt/image resolves beneath
//     the image, and one pointing outside the root is refused there.
//   - **Observed.** Every hop is a real Stat of a real inode. Nothing is
//     inferred from the shape of a path.
//   - **Honest about failure.** A hop that cannot be stat'ed or read returns
//     the seam's own error, so a collector reports UNKNOWN rather than
//     concluding something from a file it never saw.
//
// What is gained is that files distributions deliberately ship as symlinks are
// readable at all: Red Hat's PAM stacks, and /etc/os-release on every
// systemd distribution since it moved to /usr/lib. Without this the AUTH module
// reports UNKNOWN across the whole Red Hat family and every report from a
// modern host says nothing about which operating system it audited.
//
// It is *not* a general invitation to follow links. Use it where a
// distribution ships a symlink on purpose. Following one somewhere nobody
// intended is following one an attacker may have put there.
func ResolveLinks(sys system.System, p string) (string, error) {
	real := p
	for hop := 0; ; hop++ {
		fi, err := sys.Stat(real)
		if err != nil {
			return real, err
		}
		if !fi.IsSymlink {
			return real, nil
		}
		if hop >= MaxLinkHops {
			return real, fmt.Errorf("%w: %s did not resolve within %d hops",
				ErrLinkChainTooLong, p, MaxLinkHops)
		}

		target, err := sys.Readlink(real)
		if err != nil {
			return real, err
		}
		// Resolved textually against the link's own directory, which is what
		// the kernel would do, and then handed straight back to the seam. An
		// absolute target is absolute *within the scan root*, because that is
		// the only frame of reference a --root scan has.
		if path.IsAbs(target) {
			real = path.Clean(target)
		} else {
			real = path.Clean(path.Join(path.Dir(real), target))
		}
	}
}
