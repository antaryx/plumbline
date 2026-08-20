package network_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/network"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/network"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the NETWORK module as this work package leaves it.
var all = []catalog.Check{checks.Check0001, checks.Check0002, checks.Check0003}

func collectFixture(t *testing.T, name string) *fact.Set {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	return facts
}

// evalCheck runs the real collector against a fixture and then one real check
// against the resulting facts. Tests exercise the whole vertical slice, not
// the check in isolation, because most check bugs are actually collector bugs.
func evalCheck(t *testing.T, check catalog.Check, name string) finding.Finding {
	t.Helper()

	got := catalog.MustNew(check).Evaluate(collectFixture(t, name))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

type tc struct {
	fixture  string
	result   finding.Result
	severity finding.Severity
	reason   finding.UnknownReason
	// detailContains guards against a correct verdict with a misleading
	// explanation, which is its own class of bug.
	detailContains string
}

func run(t *testing.T, check catalog.Check, cases []tc) {
	t.Helper()

	for _, c := range cases {
		t.Run(check.ID+"/"+c.fixture, func(t *testing.T) {
			got := evalCheck(t, check, c.fixture)

			if got.Result != c.result {
				t.Errorf("result = %s, want %s\n detail: %s", got.Result, c.result, got.Detail)
			}
			if c.severity != "" && got.Severity != c.severity {
				t.Errorf("severity = %s, want %s", got.Severity, c.severity)
			}
			if c.reason != "" && got.UnknownReason != c.reason {
				t.Errorf("unknown reason = %q, want %q", got.UnknownReason, c.reason)
			}
			if !strings.Contains(strings.ToLower(got.Detail), strings.ToLower(c.detailContains)) {
				t.Errorf("detail %q does not contain %q", got.Detail, c.detailContains)
			}

			if got.CheckID != check.ID || got.Module != "NETWORK" {
				t.Errorf("identity wrong: %s / %s", got.CheckID, got.Module)
			}
			if got.BaseSeverity != check.BaseSeverity {
				t.Errorf("base severity mutated: %s", got.BaseSeverity)
			}
			if got.Fingerprint == "" {
				t.Error("fingerprint is empty")
			}
			if got.Result == finding.Unknown && got.UnknownReason == "" {
				t.Error("UNKNOWN without a reason code")
			}
			if got.Result == finding.Fail && got.Remediation == nil {
				t.Error("FAIL without remediation")
			}
			if got.Result != finding.Fail && got.Remediation != nil {
				t.Error("remediation attached to a non-FAIL result")
			}
			if (got.Result == finding.Fail || got.Result == finding.Unknown) && len(got.Evidence) == 0 {
				t.Errorf("%s carries no evidence; a verdict an auditor cannot follow up is not actionable", got.Result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// module-wide invariants
// ---------------------------------------------------------------------------

// TestBothBackendsReachTheSameVerdict is the point of having two good-case
// fixtures. network-nftables and network-ufw describe the same host — one
// firewall, default deny — written for two entirely different tools, one of
// which keeps its policy in a second file. A parser that understood only one
// of them would report a correctly firewalled host as unprotected.
func TestBothBackendsReachTheSameVerdict(t *testing.T) {
	for _, check := range all {
		nft := evalCheck(t, check, "network-nftables")
		ufw := evalCheck(t, check, "network-ufw")
		if nft.Result != ufw.Result {
			t.Errorf("%s: nftables = %s but ufw = %s; the same host written for two tools must reach one verdict\n  nft: %s\n  ufw: %s",
				check.ID, nft.Result, ufw.Result, nft.Detail, ufw.Detail)
		}
		if nft.Result != finding.Pass {
			t.Errorf("%s = %s over the good case, want PASS: %s", check.ID, nft.Result, nft.Detail)
		}
	}
}

// TestUnreadableConfigurationIsUnknownEverywhere: a file we were refused could
// be the firewall, could be a second manager, and could hold the accept
// policy. No check may report on the paths it happened to be able to read.
func TestUnreadableConfigurationIsUnknownEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "network-denied")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over network-denied, want UNKNOWN:\n  %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
	}
}

// TestEveryCheckIsRegisteredAtCatalogTen guards the one piece of metadata a
// reviewer cannot see from the diff: a check whose SinceCatalog is wrong claims
// to have existed in a version that never shipped it, and suppression files
// written against that version silently do not match.
func TestEveryCheckIsRegisteredAtCatalogTen(t *testing.T) {
	for _, check := range all {
		if check.SinceCatalog != 10 {
			t.Errorf("%s SinceCatalog = %d, want 10", check.ID, check.SinceCatalog)
		}
		if len(check.Requires) != 1 || check.Requires[0] != fact.FirewallID {
			t.Errorf("%s requires %v, want [%s]", check.ID, check.Requires, fact.FirewallID)
		}
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestCheck0001(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "network-nftables", result: finding.Pass,
			detailContains: "a host firewall is configured"},
		{fixture: "network-ufw", result: finding.Pass, detailContains: "ufw"},
		{fixture: "network-accept", result: finding.Pass,
			detailContains: "nftables"},
		{fixture: "network-none", result: finding.Fail, severity: finding.High,
			detailContains: "no host firewall configuration was found"},
		{fixture: "network-empty", result: finding.Fail, severity: finding.High,
			detailContains: "contains no statements"},
		{fixture: "network-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "could not be read"},
	})
}

func TestCheck0002(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "network-nftables", result: finding.Pass,
			detailContains: "policy drop"},
		{fixture: "network-ufw", result: finding.Pass,
			detailContains: "default_input_policy"},
		{fixture: "network-accept", result: finding.Fail, severity: finding.High,
			detailContains: "policy accept"},
		{fixture: "network-none", result: finding.NotApplicable,
			detailContains: "no subject"},
		{fixture: "network-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "rests on what was not found"},
	})
}

func TestCheck0003(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "network-nftables", result: finding.Pass,
			detailContains: "one firewall configuration is in force"},
		{fixture: "network-both", result: finding.Fail, severity: finding.Medium,
			detailContains: "two managers are configured"},
		{fixture: "network-none", result: finding.NotApplicable,
			detailContains: "no subject"},
		{fixture: "network-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "rests on what was not found"},
	})
}

// ---------------------------------------------------------------------------
// the distinctions that decide a verdict
// ---------------------------------------------------------------------------

// TestAnEmptyConfigurationFileIsNotAFirewall is why NETWORK-0001 counts
// statements. Debian's nftables package installs /etc/nftables.conf whether or
// not anybody has written a rule in it, so a check that treated the file's
// existence as protection would report every such host as firewalled.
func TestAnEmptyConfigurationFileIsNotAFirewall(t *testing.T) {
	facts := collectFixture(t, "network-empty")
	f, _, _ := fact.Get[fact.Firewall](facts, fact.FirewallID)

	var found bool
	for _, s := range f.Sources {
		if s.Path != "/etc/nftables.conf" {
			continue
		}
		found = true
		if s.State != fact.SourcePresent {
			t.Errorf("state = %s, want %s: the file is there and was read", s.State, fact.SourcePresent)
		}
		if s.Statements != 0 {
			t.Errorf("statements = %d, want 0: the file holds only comments", s.Statements)
		}
		if s.Active() {
			t.Error("Active() = true for a file with no statements")
		}
	}
	if !found {
		t.Fatal("no record for /etc/nftables.conf")
	}
}

// TestTwoFilesOfOneKindAreOneConfiguration: rules.v4 and rules.v6 are the two
// halves of a single iptables ruleset, loaded together. Counting them as two
// configurations would fail NETWORK-0003 on every host that filters IPv6.
func TestTwoFilesOfOneKindAreOneConfiguration(t *testing.T) {
	f := fact.Firewall{Sources: []fact.FirewallSource{
		{Kind: fact.FirewallIPTables, Path: "/etc/iptables/rules.v4", State: fact.SourcePresent, Statements: 12},
		{Kind: fact.FirewallIPTables, Path: "/etc/iptables/rules.v6", State: fact.SourcePresent, Statements: 9},
	}}
	if got := f.Kinds(); len(got) != 1 {
		t.Errorf("Kinds() = %v, want one kind", got)
	}
}

// TestADisabledManagerIsNotAFirewall: `ufw disable` leaves every rule in place
// and applies none of them. It is the state that most reliably survives an
// audit of the ruleset itself — the file reads correctly and the host is open.
func TestADisabledManagerIsNotAFirewall(t *testing.T) {
	s := fact.FirewallSource{
		Kind: fact.FirewallUFW, Path: "/etc/ufw/ufw.conf",
		State: fact.SourcePresent, Statements: 4, Enabled: fact.EnabledNo,
	}
	if s.Active() {
		t.Error("Active() = true for a manager with ENABLED=no")
	}
}
