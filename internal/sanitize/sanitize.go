// Package sanitize neutralises untrusted text before it reaches anything that
// renders it.
//
// This is a security control, not formatting. docs/THREAT-MODEL.md T-03: a
// filename may contain arbitrary bytes including ESC, and a file called
// "\x1b[2J\x1b[H  All checks passed" lands in evidence, in the terminal
// report, and in CI logs, where it can clear the screen, forge output, retitle
// the window, or stage a command for the operator to paste. The auditor's
// terminal is part of the attack surface of an auditing tool.
//
// Two rules follow from that, and both are load-bearing:
//
// Control characters are made visible rather than deleted. An auditor needs to
// know that a filename contains an escape sequence — that is itself a finding
// — and deleting the bytes would report a name the host does not have.
//
// Sanitisation happens once, at the boundary where untrusted text becomes part
// of a finding, never per renderer. A control that each output format has to
// remember is a control that the next output format forgets.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

const (
	// MaxExcerpt caps an evidence excerpt. An excerpt is quoted material for a
	// human to read, not the source itself: the full bytes live in the
	// bundle's evidence store, addressed by their digest.
	MaxExcerpt = 512

	// MaxText caps a single-value string — a path, a subject, a detail
	// sentence. It is PATH_MAX, because a path longer than PATH_MAX is not a
	// path this tool could have read, and because capping paths at display
	// width would corrupt legitimate deep paths to defend against a purely
	// cosmetic problem.
	MaxText = 4096

	// TruncationMarker says that something was left out. A capped string that
	// does not admit it is a lie about what the host contains.
	TruncationMarker = "... [truncated]"
)

// Text neutralises control characters and caps the result at MaxText.
// Use it for paths, subjects, and rendered detail.
func Text(s string) string { return clean(s, MaxText) }

// Excerpt neutralises control characters and caps the result at MaxExcerpt.
func Excerpt(s string) string { return clean(s, MaxExcerpt) }

// clean escapes anything a terminal would act on and stops at max bytes of
// output.
//
// The budget is spent on output, not input, and the loop stops as soon as it
// is exhausted. A 10 MB hostile source is therefore read for as long as it
// takes to fill a few hundred bytes and no longer: capping after building the
// escaped form would let an attacker turn 10 MB of ESC into 40 MB of
// allocation in a process running as root.
func clean(s string, max int) string {
	var b strings.Builder
	b.Grow(min(len(s), max)) // never sized from attacker-controlled length

	truncated := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])

		var piece string
		switch {
		case r == utf8.RuneError && size == 1:
			// Not valid UTF-8. Escaping the raw byte keeps the output
			// well-formed without inventing a character the host never had.
			piece = escapeByte(s[i])
		case r == '\t':
			// Tab is the one control character worth keeping: it carries
			// meaning in configuration files and cannot address the cursor.
			piece = "\t"
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			// C0, DEL and C1. C1 matters as much as C0: 0x9b is CSI on its
			// own in terminals that accept 8-bit controls, so stripping only
			// ESC would leave a working escape sequence behind. Everything in
			// those ranges fits in one byte.
			piece = escapeByte(byte(r))
		default:
			piece = s[i : i+size]
		}

		if b.Len()+len(piece) > max {
			truncated = true
			break
		}
		b.WriteString(piece)
		i += size
	}

	if truncated {
		return b.String() + TruncationMarker
	}
	return b.String()
}

const hexDigits = "0123456789abcdef"

func escapeByte(c byte) string {
	return `\x` + string([]byte{hexDigits[c>>4], hexDigits[c&0x0f]})
}
