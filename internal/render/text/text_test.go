package text_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	rendertext "github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/score"
)

func render(t *testing.T, in rendertext.Input) string {
	t.Helper()
	var buf bytes.Buffer
	if err := rendertext.Render(&buf, in); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

// sample is a report with one of everything, so a test can assert on the shape
// without each one building its own.
func sample(t *testing.T) rendertext.Input {
	t.Helper()

	findings := []finding.Finding{
		{
			CheckID: "SSHD-0002", Module: "SSHD", Title: "Root may not log in over SSH",
			Result: finding.Fail, Severity: finding.High, BaseSeverity: finding.High,
			Detail:  "PermitRootLogin is yes.",
			Subject: "/etc/ssh/sshd_config",
			Evidence: []finding.Evidence{
				finding.NewEvidence("/etc/ssh/sshd_config", 12, "PermitRootLogin yes", ""),
			},
			Remediation: &finding.Remediation{
				Summary: "Set PermitRootLogin no and reload sshd.",
				Effort:  "LOW",
				Caution: "Confirm another account can reach root first.",
			},
			Fingerprint: "aaaa",
		},
		{
			CheckID: "AUTH-0001", Module: "AUTH", Title: "A password quality module is enforced",
			Result: finding.Pass, Severity: finding.Medium, BaseSeverity: finding.Medium,
			Detail: "pam_pwquality.so is present and required.", Fingerprint: "bbbb",
		},
		{
			CheckID: "FILESYS-0010", Module: "FILESYS", Title: "Every uid resolves",
			Result: finding.Unknown, UnknownReason: finding.ReasonAmbiguousState,
			Severity: finding.Medium, BaseSeverity: finding.Medium,
			Detail: "nsswitch.conf routes passwd to sss.",
			Evidence: []finding.Evidence{
				finding.NewEvidence("/etc/nsswitch.conf", 0, "passwd: files sss", ""),
			},
			Fingerprint: "cccc",
		},
		{
			CheckID: "NETWORK-0001", Module: "NETWORK", Title: "A firewall is configured",
			Result: finding.NotApplicable, Severity: finding.Info, BaseSeverity: finding.Info,
			Detail: "No firewall manager is installed.", Fingerprint: "dddd",
		},
	}

	started := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	return rendertext.Input{
		Tool: rendertext.Tool{Name: "plumbline", Version: "0.3.0-dev"},
		Scan: rendertext.Scan{
			Started: started, Finished: started.Add(2 * time.Second),
			Root: "", EUID: 0, Profile: "default",
			Host: &rendertext.Host{Hostname: "auditbox", OSVersion: "Debian GNU/Linux 12 (bookworm)"},
		},
		Score:    score.Compute(findings, 12),
		Findings: findings,
	}
}

// ---------------------------------------------------------------------------
// the security property
// ---------------------------------------------------------------------------

// TestNoEscapeSequenceFromTheHostReachesTheTerminal is the test this package
// most needs to have.
//
// THREAT-MODEL.md T-03: a filename may contain arbitrary bytes including ESC.
// This renderer is the one that writes to an operator's terminal and the one
// that deliberately emits escape sequences of its own, so it is where a hostile
// path stops being a curiosity and becomes a way to clear the screen, forge a
// clean report, retitle the window, or stage a command for someone to paste.
//
// The defence is upstream — sanitisation happens once, where untrusted text
// becomes part of a finding — and this test asserts the defence actually holds
// through this renderer rather than assuming it.
func TestNoEscapeSequenceFromTheHostReachesTheTerminal(t *testing.T) {
	hostile := "\x1b[2J\x1b[H  ALL CHECKS PASSED"

	in := sample(t)
	in.Color = false
	in.Findings = []finding.Finding{{
		CheckID: "SSHD-0001", Module: "SSHD",
		Title:  "Title " + hostile,
		Result: finding.Fail, Severity: finding.High, BaseSeverity: finding.High,
		Detail:  "Detail " + hostile,
		Subject: "/tmp/" + hostile,
		Evidence: []finding.Evidence{
			finding.NewEvidence("/etc/"+hostile, 1, "excerpt "+hostile, ""),
		},
		Remediation: &finding.Remediation{
			Summary: "Summary " + hostile,
			Effort:  "LOW",
			Caution: "Caution " + hostile,
		},
		Fingerprint: "eeee",
	}}
	in.FactErrors = []fact.Error{{
		Fact: "sshd.config", Kind: fact.ErrParse,
		Path: "/etc/" + hostile, Msg: "message " + hostile,
	}}
	in.Score = score.Compute(in.Findings, 12)

	out := render(t, in)

	if strings.Contains(out, "\x1b") {
		t.Fatalf("a raw ESC byte reached the output with colour disabled:\n%q", out)
	}
	// The bytes must be *shown*, not deleted: an auditor needs to know the
	// filename contains an escape sequence, because that is itself a finding.
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("the escape sequence was dropped rather than made visible; the report now names a path the host does not have:\n%s", out)
	}
}

// TestColourIsTheOnlySourceOfEscapeBytes: with colour on, every ESC in the
// output must be one this package wrote. The hostile text is still escaped.
func TestColourIsTheOnlySourceOfEscapeBytes(t *testing.T) {
	in := sample(t)
	in.Color = true
	in.Findings[0].Title = "Root \x1b[31mmay not\x1b[0m log in"
	in.Score = score.Compute(in.Findings, 12)

	out := render(t, in)
	for _, seq := range []string{"\033[0m", "\033[1m"} {
		if !strings.Contains(out, seq) {
			t.Errorf("colour is on but %q never appears", seq)
		}
	}
	// The finding's own "\x1b[31m" must have been neutralised into text, so
	// the only red in the output is red this package chose.
	if strings.Count(out, "\033[31m") != strings.Count(withoutTitle(out), "\033[31m") {
		t.Error("an escape sequence from a finding survived into the output as an escape sequence")
	}
	if !strings.Contains(out, `\x1b[31m`) {
		t.Errorf("the title's escape sequence was not made visible:\n%s", out)
	}
}

func withoutTitle(s string) string {
	return strings.ReplaceAll(s, `\x1b[31m`, "")
}

// ---------------------------------------------------------------------------
// colour discipline
// ---------------------------------------------------------------------------

func TestColourOffEmitsNoAnsiAtAll(t *testing.T) {
	in := sample(t)
	in.Color = false
	in.FactErrors = []fact.Error{{Fact: "users.shadow", Kind: fact.ErrPermission, Path: "/etc/shadow", Msg: "denied"}}

	if out := render(t, in); strings.Contains(out, "\033") {
		t.Errorf("Color=false produced an escape sequence:\n%q", out)
	}
}

func TestColourOnMarksEachResultWithItsOwnColour(t *testing.T) {
	in := sample(t)
	in.Color = true
	out := render(t, in)

	// The status tokens, not the enum words: the tokens are what a reader's eye
	// lands on, and they are the thing the colour has to distinguish.
	//
	// Asserted as "each token carries a colour, and no two carry the same one"
	// rather than by matching the escape bytes. Which byte means red is an
	// implementation detail that gets tuned; that UNKNOWN does not look like
	// PASS is a promise. The exact state-to-colour mapping is pinned in
	// palette_internal_test.go, which is inside the package and can compare the
	// constants themselves instead of copies of them.
	seen := map[string]string{}
	for _, token := range []string{"[ OK ]", "[ WARNING ]", "[ UNKNOWN ]"} {
		code := sgrBefore(out, token)
		if code == "" {
			t.Errorf("%s is not painted at all", token)
			continue
		}
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s are painted identically (%q)", token, other, code)
		}
		seen[code] = token
	}
}

// sgrBefore returns the colour in force at the first occurrence of token: the
// last complete SGR sequence before it, or "" if that sequence is a reset and
// the token is therefore unpainted.
//
// It looks for the last sequence rather than requiring one to be flush against
// the token, because a status token is padded inside its paint call — the
// escape opens, then the padding spaces, then the word. Insisting on adjacency
// made this return "" for every painted token, which is a test that fails on
// correct output.
func sgrBefore(out, token string) string {
	i := strings.Index(out, token)
	if i < 0 {
		return ""
	}
	head := out[:i]
	start := strings.LastIndex(head, "\033[")
	if start < 0 {
		return ""
	}
	end := strings.Index(head[start:], "m")
	if end < 0 {
		return ""
	}
	if seq := head[start : start+end+1]; seq != "\033[0m" {
		return seq
	}
	return ""
}

// ---------------------------------------------------------------------------
// determinism
// ---------------------------------------------------------------------------

// TestRenderIsDeterministic. Two reports of an unchanged host must diff to
// nothing, or a scheduled scan produces noise every night and people stop
// reading the diff. Module grouping is where this is easiest to lose: ranging
// over a map would pass every other test in this file.
func TestRenderIsDeterministic(t *testing.T) {
	for _, colour := range []bool{false, true} {
		in := sample(t)
		in.Color = colour

		first := render(t, in)
		for i := 0; i < 20; i++ {
			if got := render(t, in); got != first {
				t.Fatalf("colour=%v: render %d differs from the first", colour, i)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// what the report must say
// ---------------------------------------------------------------------------

// TestUnknownGetsTheSameWeightAsFail is this package's argument rendered as a
// test. A report that lists failures loudly and mentions unknowns in a
// footnote describes a cleaner host than the one it examined.
func TestUnknownGetsTheSameWeightAsFail(t *testing.T) {
	out := render(t, sample(t))

	if !strings.Contains(out, "Could not determine (1)") {
		t.Fatal("there is no section for results the scan could not determine")
	}

	// **Same weight means the same entry, not more of one.** The warnings list
	// is two lines per finding; an UNKNOWN gets those two lines under its own
	// heading, with its title, its ID, and a reason on the details line. What
	// this test guards is that it is never demoted to a bare count — the
	// failure it exists to catch is a report that lists failures loudly and
	// mentions unknowns in a footnote.
	body := sectionOf(t, out, "Warnings and suggestions")
	for _, want := range []string{
		"- [UNKNOWN] Every uid resolves [FILESYS-0010]",
		"Details: ambiguous system state",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the UNKNOWN block omits %q:\n%s", want, body)
		}
	}
	if !strings.Contains(out, "not passes") {
		t.Error("the section does not say that an UNKNOWN is not a pass")
	}
}

// TestAWarningIsATitleAndAnAction.
//
// **The warnings list is an action list, and this is the whole of its
// contract.** It used to print everything a finding held — severity, reason,
// subject, detail, five evidence excerpts with their sources and line numbers,
// then the remedy, its effort and its caution. Eleven lines each, forty
// findings on a real host, and a terminal holding five hundred lines of prose
// that a reader looking for what to do next scrolls straight past.
//
// A title and an action: which check, how bad, and what to do about it.
// Everything named in the second loop below is still produced and still carried — by --json, by
// --format sarif, and by docs/checks/<ID>.md — and none of it belongs on a
// terminal.
func TestAWarningIsATitleAndAnAction(t *testing.T) {
	out := render(t, sample(t))
	body := sectionOf(t, out, "Warnings and suggestions")

	for _, want := range []string{
		"Warnings (1)",
		"- [HIGH]",
		"Root may not log in over SSH [SSHD-0002]",
		"      Details: Set PermitRootLogin no and reload sshd.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the warnings block omits %q:\n%s", want, body)
		}
	}

	for _, banned := range []struct{ what, text string }{
		{"an evidence source", "/etc/ssh/sshd_config:12"},
		{"an evidence excerpt", "PermitRootLogin yes"},
		{"the detail sentence", "PermitRootLogin is yes."},
		{"the remediation effort", "Effort"},
		{"the remediation caution", "Caution"},
		{"the caution text", "Confirm another account can reach root first."},
		{"a severity label", "Severity"},
		{"the machine-readable unknown reason", "ambiguous_system_state"},
	} {
		if strings.Contains(body, banned.text) {
			t.Errorf("the warnings block still prints %s (%q):\n%s", banned.what, banned.text, body)
		}
	}
}

// detailsIndent is the column the value on a Details line starts in, and
// therefore the hanging indent every wrapped line after the first sits at. It
// is duplicated from the renderer on purpose: a test that imported the constant
// would agree with the code by construction and prove nothing about the layout.
const detailsIndent = 15

// TestAnEntryIsABulletAndItsDetailsBlock.
//
// The test above names the fields that must not appear; this one closes the
// door on any field at all. Whatever a finding grows next, its entry in this
// section is a bullet and one hanging block of prose — asserted by shape rather
// than by a list of forbidden words, which is a list somebody has to remember
// to extend.
//
// The details block may be more than one line, and that is the point of the
// hanging indent: a wrapped remedy is still visibly one value belonging to one
// finding, and anything at any *other* indent is a field that has crept back in.
func TestAnEntryIsABulletAndItsDetailsBlock(t *testing.T) {
	body := sectionOf(t, render(t, sample(t)), "Warnings and suggestions")

	entries := 0
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  - ") {
			continue
		}
		entries++
		if !strings.HasSuffix(line, "]") {
			t.Errorf("an entry headline does not end in its check ID: %q", line)
		}
		if i+1 >= len(lines) {
			t.Errorf("nothing follows the entry %q", line)
			continue
		}
		if next := lines[i+1]; !strings.HasPrefix(next, "      Details: ") {
			t.Errorf("the line under %q is not its details line: %q", line, next)
		}

		// Everything else up to the end of the entry is a continuation of that
		// one value, at the hanging indent and nowhere else.
		for j := i + 2; j < len(lines); j++ {
			l := lines[j]
			if l == "" || strings.HasPrefix(l, "  - ") || strings.HasPrefix(l, "[=] ") {
				break
			}
			if !strings.HasPrefix(l, strings.Repeat(" ", detailsIndent)) ||
				strings.HasPrefix(l, strings.Repeat(" ", detailsIndent+1)) {
				t.Errorf("the entry %q carries a line that is not a details continuation: %q", line, l)
			}
		}
	}
	if entries != 2 {
		t.Errorf("found %d entries in the warnings section, want 2 (one FAIL, one UNKNOWN):\n%s", entries, body)
	}
}

// TestALongRemedyWrapsAndIsNotCutOff.
//
// **The first version of this section truncated the details line at the grid
// and that made the section useless.** The one sentence in the report telling
// an operator what to type was cut mid-clause, and the half that survived was
// the half restating the problem. Nothing here may be lost to the layout.
//
// Three claims: the value wraps rather than ending in an ellipsis, every line
// of it fits the grid, and the whole sentence is recoverable from the page.
func TestALongRemedyWrapsAndIsNotCutOff(t *testing.T) {
	const remedy = "Remove nullok and nullok_secure from every pam_unix.so auth rule " +
		"in /etc/pam.d, then check for a distribution override in " +
		"/usr/share/pam-configs and regenerate the stack with pam-auth-update."

	in := sample(t)
	for i := range in.Findings {
		if in.Findings[i].Result == finding.Fail {
			in.Findings[i].Remediation = &finding.Remediation{Summary: remedy}
		}
	}
	body := sectionOf(t, render(t, in), "Warnings and suggestions")

	var got []string
	for _, l := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(l, "      Details: "):
			got = append(got, strings.TrimPrefix(l, "      Details: "))
		case strings.HasPrefix(l, strings.Repeat(" ", detailsIndent)) && len(got) > 0:
			got = append(got, strings.TrimSpace(l))
		default:
			if len(got) > 0 {
				goto done
			}
		}
	}
done:
	if len(got) < 2 {
		t.Fatalf("a %d-character remedy did not wrap: %q", len(remedy), got)
	}
	if joined := strings.Join(got, " "); joined != remedy {
		t.Errorf("the remedy did not survive the layout.\n got: %q\nwant: %q", joined, remedy)
	}
	if strings.Contains(strings.Join(got, " "), "…") {
		t.Error("the remedy is still being truncated")
	}
	for _, l := range strings.Split(body, "\n") {
		if n := len([]rune(l)); n > 78 {
			t.Errorf("a wrapped line is %d columns, over the 78-column grid: %q", n, l)
		}
	}
}

// TestTheSeverityTagIsColouredByImpact.
//
// The list is read by running an eye down the left edge, and the tag is what
// that eye is for. An UNKNOWN is magenta rather than a shade of warning,
// because it is not a mild failure — it is the absence of a verdict, and it
// must not sit in the same colour as a check that was evaluated and failed.
func TestTheSeverityTagIsColouredByImpact(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*finding.Finding)
		tag    string
		colour string
	}{
		{"critical", func(f *finding.Finding) { f.Severity = finding.Critical }, "[CRITICAL]", "\033[1;38;2;239;68;68m"},
		{"high", func(f *finding.Finding) { f.Severity = finding.High }, "[HIGH]", "\033[1;38;2;239;68;68m"},
		{"medium", func(f *finding.Finding) { f.Severity = finding.Medium }, "[MEDIUM]", "\033[1;38;2;245;158;11m"},
		{"low", func(f *finding.Finding) { f.Severity = finding.Low }, "[LOW]", "\033[38;2;96;165;250m"},
		{"unknown", func(f *finding.Finding) {
			f.Result = finding.Unknown
			f.UnknownReason = finding.ReasonPermission
		}, "[UNKNOWN]", "\033[1;38;2;168;85;247m"},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := sample(t)
			in.Color = true
			for i := range in.Findings {
				if in.Findings[i].CheckID == "SSHD-0002" {
					c.mutate(&in.Findings[i])
				}
			}
			body := sectionOf(t, render(t, in), "Warnings and suggestions")
			if want := c.colour + c.tag; !strings.Contains(body, want) {
				t.Errorf("%s is not painted its own colour:\n%s", c.tag, body)
			}
		})
	}
}

// TestTheTitleColumnHoldsAcrossBothBlocks.
//
// The tag is padded to the widest one in the section rather than to whatever
// each entry happens to need, so the titles line up. A column that re-aligns
// itself between "Warnings" and "Could not determine" is two columns, and the
// eye that was running down it stops.
func TestTheTitleColumnHoldsAcrossBothBlocks(t *testing.T) {
	body := sectionOf(t, render(t, sample(t)), "Warnings and suggestions")

	col := -1
	for _, l := range strings.Split(body, "\n") {
		if !strings.HasPrefix(l, "  - ") {
			continue
		}
		i := strings.Index(l, "]")
		if i < 0 {
			t.Errorf("no severity tag on %q", l)
			continue
		}
		// Past the tag and past the padding: where the title actually begins.
		rest := l[i+1:]
		start := i + 1 + len(rest) - len(strings.TrimLeft(rest, " "))
		if col < 0 {
			col = start
			continue
		}
		if start != col {
			t.Errorf("a title starts in column %d where the one above starts in %d: %q", start, col, l)
		}
	}
	if col < 0 {
		t.Fatalf("no entries in:\n%s", body)
	}
}

func TestHeaderCarriesTheScanContext(t *testing.T) {
	out := render(t, sample(t))

	for _, want := range []string{
		"plumbline 0.3.0-dev",
		"catalog 12",
		"auditbox",
		"Debian GNU/Linux 12 (bookworm)",
		"2026-08-20 09:00:00 UTC",
		"live host",
		"0  (root)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the header omits %q:\n%s", want, out)
		}
	}
}

// TestANonRootScanSaysSoInTheHeader. "euid 1000" tells an operator nothing
// about why half the report is UNKNOWN.
func TestANonRootScanSaysSoInTheHeader(t *testing.T) {
	in := sample(t)
	in.Scan.EUID = 1000
	if out := render(t, in); !strings.Contains(out, "not root") {
		t.Errorf("an unprivileged scan does not say so in the header:\n%s", out)
	}
}

func TestSummaryCountsEveryState(t *testing.T) {
	out := render(t, sample(t))
	for _, want := range []string{"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "SKIPPED", "evaluated"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary omits %q", want)
		}
	}
	if !strings.Contains(out, "the scan could not tell") {
		t.Error("a non-zero UNKNOWN count is not called out in the summary")
	}
}

// ---------------------------------------------------------------------------
// the posture invariant
// ---------------------------------------------------------------------------

// TestPostureIsNeverShownWithoutCoverage is the same invariant the JSON
// renderer enforces, for the same reason: a posture with no scale beside it is
// a number that flatters an unexamined host.
func TestPostureIsNeverShownWithoutCoverage(t *testing.T) {
	t.Run("both defined", func(t *testing.T) {
		out := render(t, sample(t))
		if !strings.Contains(out, "posture") || !strings.Contains(out, "coverage") {
			t.Fatalf("posture and coverage are not shown together:\n%s", out)
		}
	})

	t.Run("neither defined", func(t *testing.T) {
		in := sample(t)
		// Nothing that carries weight: every finding NOT_APPLICABLE.
		in.Findings = []finding.Finding{{
			CheckID: "SSHD-0001", Module: "SSHD", Title: "no sshd here",
			Result: finding.NotApplicable, Severity: finding.Info, BaseSeverity: finding.Info,
			Fingerprint: "ffff",
		}}
		in.Score = score.Compute(in.Findings, 12)

		out := render(t, in)
		if !strings.Contains(out, "undefined") {
			t.Errorf("an undefined posture is not reported as undefined:\n%s", out)
		}
		if strings.Contains(out, "0.0") {
			t.Errorf("an undefined posture was rendered as a number; undefined is not zero:\n%s", out)
		}
	})
}

// TestLowCoverageTakesGreenAwayFromPosture. A posture of 86 over 17% coverage
// is arithmetically right and, painted green, is a lie an operator acts on.
func TestLowCoverageTakesGreenAwayFromPosture(t *testing.T) {
	// One PASS and forty-nine UNKNOWNs: posture 100, coverage 2%.
	findings := []finding.Finding{{
		CheckID: "AAAA-0001", Module: "AAAA", Title: "the one that ran",
		Result: finding.Pass, Severity: finding.High, BaseSeverity: finding.High, Fingerprint: "1",
	}}
	for i := 0; i < 49; i++ {
		findings = append(findings, finding.Finding{
			CheckID: "BBBB-" + string(rune('a'+i)), Module: "BBBB", Title: "blind",
			Result: finding.Unknown, UnknownReason: finding.ReasonPermission,
			Severity: finding.High, BaseSeverity: finding.High, Fingerprint: "x",
		})
	}

	in := sample(t)
	in.Color = true
	in.Findings = findings
	in.Score = score.Compute(findings, 12)

	out := render(t, in)
	postureLine := lineContaining(t, out, "posture")
	if strings.Contains(postureLine, "\033[32m") {
		t.Errorf("a posture of 100 over 2%% coverage was painted green:\n%s", postureLine)
	}
	if !strings.Contains(postureLine, "coverage") {
		t.Errorf("the posture line does not carry coverage:\n%s", postureLine)
	}
}

func lineContaining(t *testing.T, out, want string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	t.Fatalf("no line contains %q:\n%s", want, out)
	return ""
}

// ---------------------------------------------------------------------------
// layout
// ---------------------------------------------------------------------------

// TestColumnsAlignWithColourOn is the tabwriter hazard, asserted.
//
// A coloured cell is nine runes wider than it looks. Where this package pads by
// hand it uses a width function that skips escape sequences; if that ever
// regressed, the check-ID column would ripple with the length of each result
// word and the report would look broken on precisely the hosts that have
// something to report.
// reportWidth is the grid the renderer lays the report out on. It is repeated
// here rather than exported: this test's job is to pin the layout, so it has
// to fail when the renderer's constant changes rather than follow it.
const reportWidth = 78

func TestColumnsAlignWithColourOn(t *testing.T) {
	out := render(t, sample(t))
	coloured := func() string {
		in := sample(t)
		in.Color = true
		return render(t, in)
	}()

	plain := bracketColumns(t, out)
	colour := bracketColumns(t, coloured)
	if len(plain) == 0 {
		t.Fatal("no status-bracket lines found")
	}
	if len(plain) != len(colour) {
		t.Fatalf("colour changed the number of status lines: %d vs %d", len(plain), len(colour))
	}
	for i := range plain {
		if plain[i] != colour[i] {
			t.Fatalf("the status column moved when colour was enabled: %v vs %v", plain, colour)
		}
	}
	// Every closing bracket lands on the same column, and that column is the
	// grid's right edge rather than wherever the longest title happened to
	// push it. This is the assertion the whole layout is built to satisfy.
	for _, c := range plain {
		if c != reportWidth {
			t.Fatalf("a status bracket ends at column %d, not the grid edge %d: %v", c, reportWidth, plain)
		}
	}
}

// TestNoLineOverflowsTheGrid. The grid is only worth having if nothing escapes
// it: one long title or subject running past the right edge undoes the run of
// brackets the eye is following down the page.
func TestNoLineOverflowsTheGrid(t *testing.T) {
	in := sample(t)
	in.FactErrors = []fact.Error{{Fact: "users.shadow", Kind: fact.ErrPermission, Path: "/etc/shadow", Msg: "denied"}}
	for _, colour := range []bool{false, true} {
		in.Color = colour
		for _, raw := range strings.Split(render(t, in), "\n") {
			// The header and the collection-gap table are tabwriter output
			// sized by their content, and the posture line carries a sentence
			// explaining an undefined score. The grid governs the scan phase
			// and the entries, which is where the alignment lives.
			line := stripANSI(raw)
			if !strings.HasPrefix(line, "  - ") && !strings.HasPrefix(line, "  * ") &&
				!strings.HasPrefix(line, "      - ") {
				continue
			}
			if n := len([]rune(line)); n > reportWidth {
				t.Errorf("colour=%v: line is %d columns, grid is %d:\n%s", colour, n, reportWidth, line)
			}
		}
	}
}

// TestTheScanPhaseCarriesNoDetail is WP-28's actual requirement. The status
// listing has to stay a status listing: the moment a detail sentence or a
// remediation line appears between two check rows, the column of brackets
// stops being scannable and the report is back to what it replaced.
func TestTheScanPhaseCarriesNoDetail(t *testing.T) {
	out := render(t, sample(t))

	head, tail, found := strings.Cut(out, "[=] ")
	if !found {
		t.Fatal("the report has no [=] section, so there is no scan phase to bound")
	}
	for _, leaked := range []string{
		"Set PermitRootLogin no", // a remediation summary
		"ambiguous system state", // why an unknown could not be determined
		"Details:",               // the label that carries either of them
	} {
		if strings.Contains(head, leaked) {
			t.Errorf("the scan phase leaked %q; it belongs in the section at the bottom", leaked)
		}
		if !strings.Contains(tail, leaked) {
			t.Errorf("%q is missing from the bottom section entirely", leaked)
		}
	}
}

// bracketColumns returns the visible column each scan-phase line's closing
// bracket sits in.
//
// It stops at the first [=] heading. The warnings list below uses the same
// `  - ` bullet and also ends in `[ID]`, and measuring those against the status
// column would be comparing two grids that were never meant to line up.
func bracketColumns(t *testing.T, out string) []int {
	t.Helper()
	if i := strings.Index(out, "[=] "); i >= 0 {
		out = out[:i]
	}
	var cols []int
	for _, raw := range strings.Split(out, "\n") {
		line := stripANSI(raw)
		if !strings.HasPrefix(line, "  - ") || !strings.HasSuffix(line, "]") {
			continue
		}
		cols = append(cols, len([]rune(line)))
	}
	return cols
}

// sectionOf returns the body of one `[=]` section, up to the next one. Several
// assertions below are about what a section does *not* contain, and a report
// has five sections — a plain strings.Contains over the whole thing would find
// the word in the summary and pass a broken warnings block.
func sectionOf(t *testing.T, out, title string) string {
	t.Helper()
	i := strings.Index(out, "[=] "+title)
	if i < 0 {
		t.Fatalf("no %q section in:\n%s", title, out)
	}
	body := out[i+4:]
	if j := strings.Index(body, "\n[=] "); j >= 0 {
		body = body[:j]
	}
	return body
}

func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestNoLineHasTrailingWhitespace. A report is something people paste into a
// ticket and diff against last week's; trailing spaces make both worse.
func TestNoLineHasTrailingWhitespace(t *testing.T) {
	in := sample(t)
	in.FactErrors = []fact.Error{{Fact: "users.shadow", Kind: fact.ErrPermission, Path: "/etc/shadow", Msg: "denied"}}

	for i, l := range strings.Split(render(t, in), "\n") {
		if l != strings.TrimRight(l, " \t") {
			t.Errorf("line %d has trailing whitespace: %q", i+1, l)
		}
	}
}

// TestCollectionGapsAreReportedSeparately. What the scanner could not observe
// and what it observed and disliked are different problems with different
// remedies; merging them is how "we could not read /etc/shadow" ends up
// looking like a passing host.
func TestCollectionGapsAreReportedSeparately(t *testing.T) {
	in := sample(t)
	in.Degraded = true
	in.FactErrors = []fact.Error{
		{Fact: "users.shadow", Kind: fact.ErrPermission, Path: "/etc/shadow", Msg: "permission denied"},
	}

	out := render(t, in)
	for _, want := range []string{"Collection gaps", "users.shadow", "/etc/shadow", "permission denied", "degraded"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report omits %q:\n%s", want, out)
		}
	}
}

// TestAnEmptyReportStillRenders. A catalog that evaluated nothing is a real
// state — an empty bundle, every module filtered out — and it must not panic
// or print a posture.
func TestAnEmptyReportStillRenders(t *testing.T) {
	out := render(t, rendertext.Input{
		Tool:  rendertext.Tool{Name: "plumbline", Version: "0.3.0-dev"},
		Score: score.Compute(nil, 12),
	})
	if !strings.Contains(out, "Scan summary") {
		t.Errorf("an empty report has no summary:\n%s", out)
	}
	if !strings.Contains(out, "undefined") {
		t.Errorf("an empty report does not report its posture as undefined:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// suppressions (WP-29)
// ---------------------------------------------------------------------------

// suppressed returns the sample with its FAIL accepted, which is the state the
// renderer has to describe honestly.
func suppressed(t *testing.T) rendertext.Input {
	t.Helper()
	in := sample(t)
	for i := range in.Findings {
		if in.Findings[i].Result == finding.Fail {
			in.Findings[i].Suppression = &finding.Suppression{
				Justification:  "bastion host; root login is required by the break-glass runbook, SEC-4471",
				ExpiresAt:      "2027-01-31T00:00:00Z",
				OriginalResult: finding.Fail,
			}
			in.Findings[i].Result = finding.Skipped
		}
	}
	in.Score = score.Compute(in.Findings, 12)
	return in
}

// TestASuppressedFindingIsNotQuiet is WP-29's argument rendered as a test. A
// suppression makes a finding stop appearing in the warnings list, so if the
// report said nothing else, a host would look clean because somebody wrote a
// JSON file.
func TestASuppressedFindingIsNotQuiet(t *testing.T) {
	out := render(t, suppressed(t))

	for _, want := range []string{
		"[ SUPPRESSED ]", // distinct from a profile skip in the scan phase
		"Accepted risks", // its own section
		"SSHD-0002",      // the check is still named
		"SEC-4471",       // the justification is carried, not summarised away
		"2027-01-31",     // and so is the expiry
		"Would be",       // and what it would otherwise have said
		"FAIL",
		"accepted risk(s)", // and the summary says how many
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a suppressed report omits %q:\n%s", want, out)
		}
	}
}

// TestASuppressedFindingLeavesTheWarningsList. That is the entire point of
// suppressing it — but only the warnings list. It must still be somewhere.
func TestASuppressedFindingLeavesTheWarningsList(t *testing.T) {
	out := render(t, suppressed(t))

	warnings, rest, found := strings.Cut(out, "[=] Accepted risks")
	if !found {
		t.Fatal("there is no accepted-risks section")
	}
	if strings.Contains(warnings, "Warnings (1)") {
		t.Error("the suppressed finding is still listed as a warning")
	}
	if !strings.Contains(rest, "SSHD-0002") {
		t.Error("the suppressed finding is not in the accepted-risks section either — it vanished")
	}
}

// TestSuppressionDoesNotBreakTheGrid. [ SUPPRESSED ] is the widest token any
// result produces, so it is the one most likely to push a line past the right
// edge.
func TestSuppressionDoesNotBreakTheGrid(t *testing.T) {
	for _, colour := range []bool{false, true} {
		in := suppressed(t)
		in.Color = colour
		cols := bracketColumns(t, render(t, in))
		if len(cols) == 0 {
			t.Fatal("no status lines")
		}
		for _, c := range cols {
			if c != reportWidth {
				t.Fatalf("colour=%v: a bracket ends at %d, not %d: %v", colour, c, reportWidth, cols)
			}
		}
	}
}

// TestSuppressionDoesNotPenalisePosture. An accepted risk leaves the posture
// denominator entirely rather than counting against it — a team is not scored
// down for having reviewed something. Coverage does fall, because a suppressed
// check genuinely did not produce a verdict about the host, and that is the
// documented meaning of SKIPPED.
func TestSuppressionDoesNotPenalisePosture(t *testing.T) {
	before, _ := sample(t).Score.Posture()
	after, ok := suppressed(t).Score.Posture()
	if !ok {
		t.Fatal("posture became undefined")
	}
	if after < before {
		t.Errorf("posture fell from %.2f to %.2f when a finding was accepted", before, after)
	}
	if cov, _ := suppressed(t).Score.Coverage(); cov >= 100 {
		t.Errorf("coverage = %.2f; a suppressed check has not produced a verdict and must reduce it", cov)
	}
}

// TestNoEscapeSequenceIsPrintedAsText is the guard for the bug that shipped in
// v1.0.0: `Subject : \x1b[2m/etc/crontab\x1b[0m`, with the escape rendered as
// four literal characters beside the path it was meant to colour.
//
// The cause was an ordering one and it is easy to reintroduce. wrap() sanitises
// every line it produces, sanitize.Text escapes C0 control characters, and ESC
// is one — so a value coloured *before* it reaches the wrapper comes out as
// text. Both orders look equally reasonable at the call site, and only one
// works.
//
// So this asserts the symptom rather than the call sites: nowhere in a coloured
// report may the four characters \x1b appear as text. It covers every field,
// every renderer and every future one, which a test naming Subject would not.
func TestNoEscapeSequenceIsPrintedAsText(t *testing.T) {
	const escapedESC = `\x1b`

	// The suppressed fixture rather than the plain one, because the accepted-risks
	// block is now the only place a *wrapped and painted* value is rendered —
	// the warnings list is two flat lines and goes nowhere near fieldWrappedIn.
	// A test that rendered the plain sample would pass by never exercising the
	// path the bug was on.
	in := suppressed(t)
	in.Color = true
	out := render(t, in)

	if !strings.Contains(out, "Subject") {
		t.Fatal("the fixture renders no wrapped painted field; this test would prove nothing")
	}

	if strings.Contains(out, escapedESC) {
		t.Errorf("an escape sequence was sanitised into the text of the report.\n"+
			"Something was painted before it reached wrap(); paint after wrapping.\n"+
			"first occurrence: %s", excerptAround(out, escapedESC))
	}

	// And with colour off, where nothing should be painted at all.
	plain := render(t, suppressed(t))
	if strings.Contains(plain, escapedESC) || strings.Contains(plain, "\033") {
		t.Error("an uncoloured report carries escape sequences")
	}
}

// excerptAround returns a little context around the first match, because a
// failure that says only "found it" leaves the reader grepping a 200-line
// report by hand.
func excerptAround(s, want string) string {
	i := strings.Index(s, want)
	if i < 0 {
		return ""
	}
	start := max(0, i-60)
	end := min(len(s), i+len(want)+40)
	return strconv.Quote(s[start:end])
}
