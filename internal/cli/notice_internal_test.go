package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
)

var testNotices = []scoringNotice{
	{
		ID: "old", Catalog: 20, Until: "1.1.0",
		Headline: "Something that has already expired.",
		Detail:   []string{"body"},
	},
	{
		ID: "current", Catalog: 33, Until: "1.2.0",
		Headline: "Something that has not.",
		Detail:   []string{"body"},
	},
}

func TestANoticeStopsBeingShownAtTheVersionItNames(t *testing.T) {
	cases := []struct {
		tool string
		want []string
	}{
		// Until is exclusive: the version named is the first one that does not
		// show it, so a 1.0.x build still does.
		{"1.0.0", []string{"old", "current"}},
		{"1.0.9", []string{"old", "current"}},
		{"1.1.0", []string{"current"}},
		{"1.1.4", []string{"current"}},
		{"1.2.0", nil},
		{"2.0.0", nil},

		// What the Makefile actually produces. `git describe --tags --dirty`
		// decorates the tag, and a decorated 1.1.0 is still 1.1.0.
		{"v1.1.0", []string{"current"}},
		{"v1.1.0-4-gabc1234", []string{"current"}},
		{"1.1.0-dirty", []string{"current"}},

		// A build with no release identity has passed no expiry. It shows
		// everything, because the cost of a stale notice is a few skimmed
		// lines and the cost of a missing one is the silent score change
		// VERSIONING §2.4 exists to prevent.
		{"dev", []string{"old", "current"}},
		{"abc1234", []string{"old", "current"}},
		{"", []string{"old", "current"}},
	}

	for _, c := range cases {
		var got []string
		for _, n := range activeNotices(testNotices, c.tool) {
			got = append(got, n.ID)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("tool %q: active %v, want %v", c.tool, got, c.want)
		}
	}
}

func TestTheBlockNamesEveryChangeAndHowToSilenceIt(t *testing.T) {
	var buf bytes.Buffer
	writeScoringNotices(&buf, testNotices, false)
	out := buf.String()

	for _, want := range []string{
		"SCORING NOTICE",
		"2 recent changes",
		"catalog 20", "Something that has already expired.",
		"catalog 33", "Something that has not.",
		// An operator who does not want it must be told how to stop it in the
		// same breath, or the only remedy they find is to stop reading stderr.
		noticeEnvVar,
		// And why it is there at all: a number that moved on a host nobody
		// touched is the question this block exists to answer.
		"severity-weighted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the block does not mention %q:\n%s", want, out)
		}
	}

	// No colour asked for, none emitted. A file or a CI log gets the same text
	// a terminal does, minus the escapes.
	if strings.Contains(out, "\033[") {
		t.Errorf("escape sequences with colour off:\n%q", out)
	}
}

func TestNothingIsWrittenWhenEveryNoticeHasExpired(t *testing.T) {
	var buf bytes.Buffer
	writeScoringNotices(&buf, nil, true)
	if buf.Len() != 0 {
		t.Errorf("wrote %q for an empty register", buf.String())
	}
}

func TestTheOperatorCanSilenceTheBlock(t *testing.T) {
	var on, off bytes.Buffer

	reportScoringNotices(&on, false)
	if on.Len() == 0 {
		t.Fatal("the shipped register produced nothing; either it is empty or every entry has expired")
	}

	// Presence is the signal, not the value — the same rule NO_COLOR and
	// PLUMBLINE_NO_PROGRESS follow.
	t.Setenv(noticeEnvVar, "0")
	reportScoringNotices(&off, false)
	if off.Len() != 0 {
		t.Errorf("%s=0 did not silence it: %q", noticeEnvVar, off.String())
	}
}

// TestTheShippedRegisterIsWellFormed.
//
// The register is hand-written prose and every field of it is load-bearing: an
// entry with an unparseable Until never expires, and one naming a catalog the
// binary does not carry is describing a change this build does not have.
func TestTheShippedRegisterIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range scoringNotices {
		if n.ID == "" || seen[n.ID] {
			t.Errorf("notice ID %q is empty or duplicated", n.ID)
		}
		seen[n.ID] = true

		if _, ok := parseSemver(n.Until); !ok {
			t.Errorf("notice %s: Until %q does not parse, so it can never expire", n.ID, n.Until)
		}
		if n.Catalog <= 0 || n.Catalog > catalog.Version {
			t.Errorf("notice %s: catalog %d, but this binary carries %d",
				n.ID, n.Catalog, catalog.Version)
		}
		if n.Headline == "" || len(n.Detail) == 0 {
			t.Errorf("notice %s: a headline with no body says a number moved and not why", n.ID)
		}
		if !strings.HasSuffix(n.Headline, ".") {
			t.Errorf("notice %s: headline is not a sentence: %q", n.ID, n.Headline)
		}
	}
}
