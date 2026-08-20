package collect

import (
	"bytes"
	"fmt"

	"github.com/antaryx/plumbline/internal/fact"
)

// Every file this project parses is a line-oriented text configuration file:
// sshd_config, /etc/passwd, a PAM stack, rsyslog.conf, nsswitch.conf. This
// file answers one question about such a file's bytes, and answers it without
// guessing.

// NotText reports why data cannot be the text configuration file it was read
// as, or "" when nothing rules it out.
//
// **The test is a NUL byte, and it is proof rather than a heuristic.** Every
// consumer of these files on a Linux host — sshd, PAM, glibc's passwd and
// group parsers, rsyslog, systemd — is C reading NUL-terminated strings, and
// every one of them stops at the first NUL or refuses the file outright. So a
// NUL is not evidence that a file is "probably binary"; it is proof that the
// software which actually acts on the file does not see what we would see if
// we kept parsing past it. Our reading and the system's would describe
// different configurations, and only one of them is the one in force.
//
// What is deliberately *not* tested here:
//
//   - **Invalid UTF-8 is not malformation.** A GECOS field on an old host
//     carries a name in Latin-1, and a comment may carry anything at all.
//     internal/sanitize already escapes such bytes so they reach a report
//     visible rather than raw, which is the correct handling; rejecting the
//     file would report a broken account database on a host that merely has a
//     European name in it.
//   - **A high proportion of control characters** would be a threshold, and a
//     threshold is a guess. The NUL test needs no threshold: one is enough,
//     and 4 KiB of random bytes contains one with probability 1 - (255/256)^4096,
//     which is about 0.99999989.
//   - **Unrecognised keywords.** sshd refuses to start on one, but the set of
//     valid keywords differs by version, and calling a newer option malformed
//     would report a fault on a host that is simply more current than this
//     build. That is a check-level judgement over collected directives, not a
//     property of the bytes.
//
// The offset is reported because "somewhere in this file" is not something an
// operator can act on, and because a NUL at byte 0 and a NUL at byte 4 million
// are different accidents.
func NotText(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return fmt.Sprintf("contains a NUL byte at offset %d, so it is not the text configuration file it was read as; every parser on this host stops at that byte or refuses the file", i)
	}
	return ""
}

// MalformedError builds the fact error for a file that was read successfully
// and turned out not to be parseable.
//
// It is one constructor rather than each collector writing its own literal, so
// that every one of them lands in the bundle with the same Kind and a message
// shaped the same way. fact.ErrParse is the existing kind for "source found
// but unintelligible" and maps to UNKNOWN(unparseable_source); a second kind
// meaning the same thing would be a change to findings-v1 that no reader could
// act on differently.
func MalformedError(id fact.ID, path, why string) *fact.Error {
	return &fact.Error{
		Fact: id,
		Kind: fact.ErrParse,
		Msg:  "malformed file: " + why,
		Path: path,
	}
}
