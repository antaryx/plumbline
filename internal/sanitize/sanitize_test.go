package sanitize_test

import (
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/sanitize"
)

// screenClear is the attack from THREAT-MODEL.md T-03: a filename that clears
// the operator's screen, homes the cursor, and prints a verdict Plumbline
// never reached.
const screenClear = "\x1b[2J\x1b[H  All checks passed"

// csi and osc are the 8-bit forms of the same controls. They are built from
// code points rather than written literally so that this file stays readable
// in an editor that would otherwise interpret them.
var (
	csi = string(rune(0x9b))
	osc = string(rune(0x9d))
)

// TestEscapeSequencesAreInert is the acceptance criterion. The bytes a
// terminal would act on must not survive, and what replaces them must still
// tell the auditor what the host actually contains — a filename carrying an
// escape sequence is itself a finding, so deleting the evidence of it would
// report a name the host does not have.
func TestEscapeSequencesAreInert(t *testing.T) {
	for _, fn := range []struct {
		name string
		f    func(string) string
	}{{"Text", sanitize.Text}, {"Excerpt", sanitize.Excerpt}} {
		t.Run(fn.name, func(t *testing.T) {
			got := fn.f(screenClear)

			if strings.ContainsRune(got, 0x1b) {
				t.Errorf("ESC survived sanitisation: %q", got)
			}
			if !strings.Contains(got, `\x1b`) {
				t.Errorf("the escape was deleted rather than made visible: %q", got)
			}
			// The readable part is evidence and must be preserved verbatim, or
			// the operator cannot recognise the file being described.
			if !strings.Contains(got, "[2J") || !strings.Contains(got, "All checks passed") {
				t.Errorf("readable text was lost: %q", got)
			}
			if want := `\x1b[2J\x1b[H  All checks passed`; got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

// TestControlCharacters covers every range an attacker can reach, not just ESC.
func TestControlCharacters(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"C0 bell", "a\x07b", `a\x07b`},
		{"C0 newline", "a\nb", `a\x0ab`},
		{"C0 carriage return overwrites a line", "PASS\rFAIL", `PASS\x0dFAIL`},
		{"DEL", "a\x7fb", `a\x7fb`},
		// U+009B is CSI on its own in a terminal that accepts 8-bit controls,
		// so a sanitiser that strips only ESC leaves a working escape behind.
		{"C1 CSI", "a" + csi + "2Jb", `a\x9b2Jb`},
		{"C1 OSC retitles the window", "a" + osc + "0;pwn\x07b", `a\x9d0;pwn\x07b`},
		{"tab is kept: it means something in a config file", "a\tb", "a\tb"},
		{"printable text is untouched", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config"},
		{"UTF-8 survives", "café — ✓", "café — ✓"},
		{"invalid UTF-8 becomes visible", "a\xffb", `a\xffb`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitize.Text(tc.in); got != tc.want {
				t.Errorf("Text(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestTruncationIsCappedAndTruthful is the acceptance criterion: a 10 MB
// source produces a capped excerpt with a truthful marker, and does not
// exhaust memory on the way.
//
// The budget is spent on output rather than input, so the hostile case — 10 MB
// of ESC, which quadruples in size when escaped — costs no more than the
// benign one. Sanitising first and capping afterwards would let an attacker
// turn 10 MB into 40 MB of allocation in a process running as root.
func TestTruncationIsCappedAndTruthful(t *testing.T) {
	const tenMB = 10 << 20

	cases := []struct {
		name string
		in   string
	}{
		{"plain text", strings.Repeat("a", tenMB)},
		{"escape sequences", strings.Repeat("\x1b[2J", tenMB/4)},
		{"invalid UTF-8", strings.Repeat("\xff", tenMB)},
		{"one enormous line of config", strings.Repeat("PermitRootLogin yes ", tenMB/20)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.in) < tenMB {
				t.Fatalf("test input is %d bytes, want at least %d", len(tc.in), tenMB)
			}

			got := sanitize.Excerpt(tc.in)

			if !strings.HasSuffix(got, sanitize.TruncationMarker) {
				t.Fatalf("truncated excerpt does not say so: ends %q", tail(got))
			}
			if body := strings.TrimSuffix(got, sanitize.TruncationMarker); len(body) > sanitize.MaxExcerpt {
				t.Errorf("excerpt body is %d bytes, cap is %d", len(body), sanitize.MaxExcerpt)
			}
			if strings.ContainsRune(got, 0x1b) {
				t.Error("ESC survived in a truncated excerpt")
			}

			// Text has a larger cap because it holds paths, and truncating a
			// legitimate deep path would corrupt evidence to defend against a
			// purely cosmetic problem.
			asText := sanitize.Text(tc.in)
			if !strings.HasSuffix(asText, sanitize.TruncationMarker) {
				t.Error("Text did not mark truncation")
			}
			if body := strings.TrimSuffix(asText, sanitize.TruncationMarker); len(body) > sanitize.MaxText {
				t.Errorf("text body is %d bytes, cap is %d", len(body), sanitize.MaxText)
			}
		})
	}
}

// TestUntruncatedOutputCarriesNoMarker: claiming truncation that did not
// happen is the same class of bug as hiding truncation that did.
func TestUntruncatedOutputCarriesNoMarker(t *testing.T) {
	in := strings.Repeat("a", sanitize.MaxExcerpt)
	got := sanitize.Excerpt(in)
	if strings.Contains(got, sanitize.TruncationMarker) {
		t.Error("an excerpt that fits exactly was marked as truncated")
	}
	if got != in {
		t.Error("an excerpt that fits was altered")
	}
}

// TestTruncationNeverSplitsARune: half a UTF-8 sequence is not text, and a
// renderer handed one prints a replacement character the host never contained.
func TestTruncationNeverSplitsARune(t *testing.T) {
	got := sanitize.Excerpt(strings.Repeat("é", sanitize.MaxExcerpt))
	body := strings.TrimSuffix(got, sanitize.TruncationMarker)
	if strings.ContainsRune(body, '�') {
		t.Errorf("truncation split a rune: %q", tail(body))
	}
	if len(body)%2 != 0 { // "é" is two bytes; an odd length means a split
		t.Errorf("body length %d is not a whole number of runes", len(body))
	}
}

func tail(s string) string {
	if len(s) <= 40 {
		return s
	}
	return s[len(s)-40:]
}
