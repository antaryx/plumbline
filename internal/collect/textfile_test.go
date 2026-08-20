package collect_test

import (
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
)

// TestNotTextFindsWhatItClaimsTo. The false-positive direction is the one that
// matters: a rule that rejects ordinary configuration files makes every check
// UNKNOWN on healthy hosts, which is worse than the problem it was solving.
func TestNotTextFindsWhatItClaimsTo(t *testing.T) {
	rejected := map[string][]byte{
		"a NUL at the start":           {0x00, 'P', 'o', 'r', 't'},
		"a NUL after valid directives": []byte("PermitRootLogin no\n\x00\x01\x02"),
		"a NUL at the very end":        append([]byte("Port 22\n"), 0x00),
		"an ELF header":                {0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
		"a run of zero bytes":          make([]byte, 64),
	}
	for name, data := range rejected {
		if collect.NotText(data) == "" {
			t.Errorf("%s: accepted as a text configuration file", name)
		}
	}

	accepted := map[string][]byte{
		"empty":                    nil,
		"an ordinary config":       []byte("PermitRootLogin no\nPort 22\n"),
		"tabs and CRLF":            []byte("Port\t22\r\nPermitRootLogin no\r\n"),
		"a comment with an escape": []byte("# \x1b[31mred\x1b[0m\nPort 22\n"),
		"UTF-8 in a GECOS field":   []byte("bjorn:x:1000:1000:Bjørn Ærlig:/home/bjorn:/bin/sh\n"),
		"only whitespace":          []byte("\n\n\t\n"),
		// Latin-1 is not UTF-8 and is not malformation: an old host's GECOS
		// field carries a name in it, and sanitize already escapes such bytes
		// on the way to a report. Rejecting the file would report a broken
		// account database on a host that merely has a European name in it.
		"a Latin-1 name":          []byte("bjorn:x:1000:1000:Bj\xf8rn:/home/bjorn:/bin/sh\n"),
		"a very long single line": []byte(strings.Repeat("a", 100000)),
	}
	for name, data := range accepted {
		if why := collect.NotText(data); why != "" {
			t.Errorf("%s: rejected as not text (%s)", name, why)
		}
	}
}

// TestNotTextNamesTheOffset. "Somewhere in this file" is not something an
// operator can act on, and a NUL at byte 0 and one at byte four million are
// different accidents.
func TestNotTextNamesTheOffset(t *testing.T) {
	why := collect.NotText([]byte("Port 22\n\x00"))
	if !strings.Contains(why, "offset 8") {
		t.Errorf("the reason does not locate the byte: %q", why)
	}
	if !strings.Contains(why, "NUL") {
		t.Errorf("the reason does not say what was found: %q", why)
	}
}

// TestMalformedErrorIsTheExistingVocabulary.
//
// fact.ErrParse already means "source found but unintelligible" and already
// maps to UNKNOWN(unparseable_source). A second error kind meaning the same
// thing would be a change to findings-v1 that no reader could act on
// differently, so this constructor deliberately produces the existing one.
func TestMalformedErrorIsTheExistingVocabulary(t *testing.T) {
	e := collect.MalformedError(fact.SSHDConfigID, "/etc/ssh/sshd_config", "contains a NUL byte at offset 3")
	if e.Kind != fact.ErrParse {
		t.Errorf("kind = %q, want %q", e.Kind, fact.ErrParse)
	}
	if e.Fact != fact.SSHDConfigID {
		t.Errorf("fact = %q", e.Fact)
	}
	if e.Path != "/etc/ssh/sshd_config" {
		t.Errorf("path = %q", e.Path)
	}
	if !strings.Contains(e.Msg, "malformed") || !strings.Contains(e.Msg, "NUL") {
		t.Errorf("message loses either the classification or the reason: %q", e.Msg)
	}
}
