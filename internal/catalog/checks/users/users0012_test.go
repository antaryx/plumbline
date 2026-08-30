package users_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/users"
	authcollector "github.com/antaryx/plumbline/internal/collect/collectors/auth"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// evalLoginDefs runs the real auth collector — which is what reads
// /etc/login.defs — and then this check against the fact it produced.
func evalLoginDefs(t *testing.T, check catalog.Check, name string) finding.Finding {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := authcollector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}

	got := catalog.MustNew(check).Evaluate(facts)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

// TestCheck0012 is the whole vertical slice for the shadow suite's default
// minimum password age.
func TestCheck0012(t *testing.T) {
	for _, c := range []struct {
		fixture        string
		result         finding.Result
		severity       finding.Severity
		reason         finding.UnknownReason
		detailContains string
	}{
		{
			fixture:        "logindefs-strong",
			result:         finding.Pass,
			detailContains: "PASS_MIN_DAYS is 1",
		},
		{
			fixture:        "logindefs-weak",
			result:         finding.Fail,
			severity:       finding.Low,
			detailContains: "changed twice in the same second",
		},
		{
			// **Absent behaves identically to zero and is a different
			// finding.** One is an omission and the other a decision, and an
			// operator needs to know which they are looking at.
			fixture:        "logindefs-minage-zero",
			result:         finding.Fail,
			severity:       finding.Low,
			detailContains: "sets no PASS_MIN_DAYS",
		},
		{
			// No shadow-suite configuration at all: Alpine's busybox tools do
			// not read this file. There is no default to report on, and
			// USERS-0010 still covers the accounts that exist.
			fixture:        "logindefs-absent",
			result:         finding.NotApplicable,
			detailContains: "no /etc/login.defs",
		},
		{
			// **login.defs takes the first match**, which is the reverse of
			// sysctl.d, PAM includes and systemd drop-ins. A check that took
			// the last would report the opposite of what the host does.
			fixture:        "logindefs-shadowed",
			result:         finding.Pass,
			detailContains: "never read — login.defs takes the first match",
		},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			got := evalLoginDefs(t, checks.Check0012, c.fixture)

			if got.Result != c.result {
				t.Errorf("result = %s, want %s\n detail: %s", got.Result, c.result, got.Detail)
			}
			if c.severity != "" && got.Severity != c.severity {
				t.Errorf("severity = %s, want %s", got.Severity, c.severity)
			}
			if c.reason != "" && got.UnknownReason != c.reason {
				t.Errorf("unknown reason = %q, want %q", got.UnknownReason, c.reason)
			}
			if !strings.Contains(got.Detail, c.detailContains) {
				t.Errorf("detail does not contain %q:\n%s", c.detailContains, got.Detail)
			}
			if got.CheckID != "USERS-0012" || got.Module != "USERS" {
				t.Errorf("identity wrong: %s / %s", got.CheckID, got.Module)
			}
		})
	}
}

// TestAShadowedSettingIsNamedNotSilentlyIgnored.
//
// The failure this rules out is the quiet one. A host with PASS_MIN_DAYS 1 at
// the top and PASS_MIN_DAYS 0 at the bottom *passes* — the shadow suite reads
// the first match — and the operator who wrote the second line believes the
// opposite. A PASS that said nothing about it would leave them believing it.
func TestAShadowedSettingIsNamedNotSilentlyIgnored(t *testing.T) {
	got := evalLoginDefs(t, checks.Check0012, "logindefs-shadowed")
	if got.Result != finding.Pass {
		t.Fatalf("result = %s, want PASS: %s", got.Result, got.Detail)
	}
	for _, want := range []string{
		"never read",
		"login.defs takes the first match",
		"line 5",
	} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the detail does not name the dead line (%q):\n%s", want, got.Detail)
		}
	}
}

// TestTheDefaultAndTheAccountsAreDifferentQuestions.
//
// USERS-0012 reads /etc/login.defs and reports what the *next* account will
// get; USERS-0010 reads /etc/shadow and reports what the existing ones have.
// A host can pass either and fail the other, and merging them would hide
// whichever half was wrong.
func TestTheDefaultAndTheAccountsAreDifferentQuestions(t *testing.T) {
	got := evalLoginDefs(t, checks.Check0012, "logindefs-weak")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL", got.Result)
	}
	if !strings.Contains(got.Detail, "USERS-0010") {
		t.Errorf("the finding does not point at the check that covers existing accounts:\n%s", got.Detail)
	}
	if got.Subject != "PASS_MIN_DAYS" {
		t.Errorf("subject = %q, want the directive", got.Subject)
	}
}
