package services_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/services"
	apparmorcollector "github.com/antaryx/plumbline/internal/collect/collectors/apparmor"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// collectAppArmor runs the real AppArmor collector against a fixture.
//
// It is separate from collectFixture because SERVICES-0010 reads a different
// fact from the rest of the module: the systemd collectors say nothing about
// securityfs, and running them here would only slow the table down.
func collectAppArmor(t *testing.T, name string) *fact.Set {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := apparmorcollector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	return facts
}

func evalAppArmor(t *testing.T, name string) finding.Finding {
	t.Helper()

	got := catalog.MustNew(checks.Check0010).Evaluate(collectAppArmor(t, name))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

// TestCheck0010 is the whole vertical slice: the real collector reading a real
// fixture tree, then the real check reading the fact it produced.
//
// **The five cases are five different things an operator must be told**, and
// four of them are not "AppArmor is on".
func TestCheck0010(t *testing.T) {
	for _, c := range []tc{
		{
			// Enabled with a mix. One enforcing profile is the bar: a host
			// confining anything at all is doing the thing this check is about.
			fixture:        "apparmor-enforcing",
			result:         finding.Pass,
			detailContains: "3 of 4 loaded profile(s) are enforcing",
		},
		{
			// **The case this check exists for.** Three profiles loaded, none
			// of them denying anything. A host in this state looks confined to
			// anything that counts profiles.
			fixture:        "apparmor-complain-only",
			result:         finding.Fail,
			severity:       finding.High,
			detailContains: "none of its 3 loaded profile(s) enforces anything",
		},
		{
			// Built in, switched off, profiles sitting on disk applied to
			// nothing.
			fixture:        "apparmor-disabled",
			result:         finding.Fail,
			severity:       finding.High,
			detailContains: "switched off",
		},
		{
			// The LSM running and confining nothing is the same exposure as
			// having it off, and reads differently enough to be its own
			// sentence.
			fixture:        "apparmor-no-profiles",
			result:         finding.Fail,
			severity:       finding.High,
			detailContains: "no profiles loaded",
		},
		{
			// **A RHEL host is not a finding.** No AppArmor in the kernel and
			// no profile directory: this machine confines processes with
			// SELinux, and telling its operator to install a second
			// mandatory-access-control layer would be advice that makes the
			// host worse.
			fixture:        "apparmor-none",
			result:         finding.NotApplicable,
			detailContains: "no AppArmor and no profile directory",
		},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			got := evalAppArmor(t, c.fixture)

			if got.Result != c.result {
				t.Errorf("result = %s, want %s\n detail: %s", got.Result, c.result, got.Detail)
			}
			if c.severity != "" && got.Severity != c.severity {
				t.Errorf("severity = %s, want %s", got.Severity, c.severity)
			}
			if !contains(got.Detail, c.detailContains) {
				t.Errorf("detail %q does not contain %q", got.Detail, c.detailContains)
			}
			if got.CheckID != "SERVICES-0010" || got.Module != "SERVICES" {
				t.Errorf("identity wrong: %s / %s", got.CheckID, got.Module)
			}
		})
	}
}

// TestTheProfileListIsParsedNotSplit.
//
// A profile name is a path or a label a package chose, and both can contain
// spaces and parentheses. Splitting on the first space — the obvious parse —
// reads `/usr/lib/foo (bar) (enforce)` as a profile named `/usr/lib/foo` in a
// mode called `bar)`, which lands in AppArmorOther and reports a confined host
// as unconfined.
func TestTheProfileListIsParsedNotSplit(t *testing.T) {
	got := evalAppArmor(t, "apparmor-enforcing")
	if got.Result != finding.Pass {
		t.Fatalf("result = %s, want PASS: %s", got.Result, got.Detail)
	}
	// man_filter has no leading slash and snap-confine's path has a hyphen;
	// both are real profile names from a stock Ubuntu host.
	if !contains(got.Detail, "3 of 4") {
		t.Errorf("the parse lost a profile: %s", got.Detail)
	}
}

// TestAnUnreadableProfileListIsUnknownNotAVerdict.
//
// securityfs is root-only on most distributions, so this is the ordinary state
// of an unprivileged scan — and a check that read "no profiles" out of a
// refusal would report every unprivileged scan of a hardened host as a
// failure.
func TestAnUnreadableProfileListIsUnknownNotAVerdict(t *testing.T) {
	// The mounted-image shape: the module parameter is absent because /sys is
	// not in an image, while the profile directory is.
	got := evalAppArmor(t, "apparmor-image")
	if got.Result != finding.Unknown {
		t.Errorf("result = %s, want UNKNOWN: %s", got.Result, got.Detail)
	}
	if got.UnknownReason != finding.ReasonFactMissing {
		t.Errorf("reason = %q, want %q", got.UnknownReason, finding.ReasonFactMissing)
	}
	if !contains(got.Detail, "mounted image") {
		t.Errorf("the detail does not say why: %s", got.Detail)
	}
}

func contains(haystack, needle string) bool {
	return needle == "" || len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
