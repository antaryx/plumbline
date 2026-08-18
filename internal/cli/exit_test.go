package cli_test

import (
	"testing"

	"github.com/antaryx/plumbline/internal/cli"
)

// TestExitLadder covers every branch, in order, and then the combinations that
// actually occur. The audited design had three codes matching one common
// outcome with no tiebreak, so which code CI saw depended on the order the
// implementation happened to check them in (audit A-20). This table is the
// tiebreak, written down.
func TestExitLadder(t *testing.T) {
	cases := []struct {
		name string
		in   cli.Outcome
		want int
	}{
		{"nothing wrong", cli.Outcome{}, cli.ExitOK},

		// Each branch alone.
		{"interrupted", cli.Outcome{Interrupted: true}, 130},
		{"internal", cli.Outcome{Internal: true}, 70},
		{"timed out", cli.Outcome{TimedOut: true}, 11},
		{"usage", cli.Outcome{Usage: true}, 1},
		{"privileges", cli.Outcome{Privileges: true}, 10},
		{"degraded", cli.Outcome{Degraded: true}, 4},
		{"failing", cli.Outcome{Failing: true}, 2},
		{"below threshold", cli.Outcome{BelowThreshold: true}, 3},

		// The acceptance criterion: degraded and failing at once is 4, because
		// "the scanner could not see your host" has to be louder than "your
		// host is misconfigured". A pipeline told only about the failures it
		// can fix, while not being told half the host was unreadable, believes
		// it is green.
		{"degraded and failing", cli.Outcome{Degraded: true, Failing: true}, 4},
		{"degraded and below threshold", cli.Outcome{Degraded: true, BelowThreshold: true}, 4},
		{"failing and below threshold", cli.Outcome{Failing: true, BelowThreshold: true}, 2},

		// Each rung outranks everything below it.
		{"privileges outranks degraded", cli.Outcome{Privileges: true, Degraded: true, Failing: true}, 10},
		{"usage outranks privileges", cli.Outcome{Usage: true, Privileges: true}, 1},
		{"timeout outranks usage", cli.Outcome{TimedOut: true, Usage: true, Degraded: true}, 11},
		{"internal outranks timeout", cli.Outcome{Internal: true, TimedOut: true}, 70},
		{"interrupt outranks everything", cli.Outcome{
			Interrupted: true, Internal: true, TimedOut: true, Usage: true,
			Privileges: true, Degraded: true, Failing: true, BelowThreshold: true,
		}, 130},

		// Everything at once below the top rung, to pin the whole ordering.
		{"all but interrupt", cli.Outcome{
			Internal: true, TimedOut: true, Usage: true, Privileges: true,
			Degraded: true, Failing: true, BelowThreshold: true,
		}, 70},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cli.ExitCode(tc.in); got != tc.want {
				t.Errorf("ExitCode(%+v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestLadderIsTotal: every rung is reachable and no two rungs share a code. A
// ladder with a duplicate is a ladder with no tiebreak, which is the bug.
func TestLadderIsTotal(t *testing.T) {
	rungs := []struct {
		name string
		set  func(*cli.Outcome)
	}{
		{"interrupted", func(o *cli.Outcome) { o.Interrupted = true }},
		{"internal", func(o *cli.Outcome) { o.Internal = true }},
		{"timedOut", func(o *cli.Outcome) { o.TimedOut = true }},
		{"usage", func(o *cli.Outcome) { o.Usage = true }},
		{"privileges", func(o *cli.Outcome) { o.Privileges = true }},
		{"degraded", func(o *cli.Outcome) { o.Degraded = true }},
		{"failing", func(o *cli.Outcome) { o.Failing = true }},
		{"belowThreshold", func(o *cli.Outcome) { o.BelowThreshold = true }},
	}

	seen := map[int]string{}
	for _, r := range rungs {
		var o cli.Outcome
		r.set(&o)
		code := cli.ExitCode(o)
		if code == cli.ExitOK {
			t.Errorf("%s is unreachable: it resolves to 0", r.name)
		}
		if prev, dup := seen[code]; dup {
			t.Errorf("%s and %s both exit %d; the ladder has no tiebreak between them", prev, r.name, code)
		}
		seen[code] = r.name
	}
	if len(seen) != len(rungs) {
		t.Errorf("%d distinct codes for %d rungs", len(seen), len(rungs))
	}
}
