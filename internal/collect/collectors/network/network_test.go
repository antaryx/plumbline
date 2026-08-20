package network_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	collector "github.com/antaryx/plumbline/internal/collect/collectors/network"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collect(t *testing.T, dir string) fact.Firewall {
	t.Helper()

	sys, err := fake.New(dir)
	if err != nil {
		t.Fatalf("load fixture %s: %v", dir, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect %s: %v", dir, err)
	}
	f, ferr, ok := fact.Get[fact.Firewall](facts, fact.FirewallID)
	if !ok || ferr != nil {
		t.Fatalf("fact missing from %s: ok=%v err=%v", dir, ok, ferr)
	}
	return f
}

func fixture(t *testing.T, name string) fact.Firewall {
	t.Helper()
	return collect(t, filepath.Join(fixtureRoot, name))
}

func sourceAt(t *testing.T, f fact.Firewall, path string) fact.FirewallSource {
	t.Helper()
	for _, s := range f.Sources {
		if s.Path == path {
			return s
		}
	}
	t.Fatalf("no record for %s", path)
	return fact.FirewallSource{}
}

// TestPolicyUnderTheHookDeclarationIsFound.
//
// A hand-maintained nftables chain is written across two lines:
//
//	type filter hook input priority 0;
//	policy drop;
//
// A parser that only read the hook's own line would find no policy and report
// UNKNOWN on a correctly configured host — which reads as caution and is a
// wrong answer.
func TestPolicyUnderTheHookDeclarationIsFound(t *testing.T) {
	f := fixture(t, "network-nftables")
	s := sourceAt(t, f, "/etc/nftables.conf")

	if s.Policy != fact.PolicyDeny {
		t.Errorf("policy = %q, want %q", s.Policy, fact.PolicyDeny)
	}
	if s.PolicyLine == 0 || s.PolicyRaw == "" {
		t.Errorf("policy recorded without provenance: line=%d raw=%q", s.PolicyLine, s.PolicyRaw)
	}
	if !s.Active() {
		t.Error("Active() = false for a ruleset with statements")
	}
}

// TestTheInputChainIsTheOneRead: the forward and output chains have their own
// policies and neither is the subject. network-nftables sets output to accept,
// which a parser matching the first `policy` keyword in the file would happily
// report as the inbound default.
func TestTheInputChainIsTheOneRead(t *testing.T) {
	f := fixture(t, "network-nftables")
	if got := sourceAt(t, f, "/etc/nftables.conf").Policy; got != fact.PolicyDeny {
		t.Errorf("policy = %q; the output chain's accept was read instead of the input chain's drop", got)
	}
}

// TestUfwReadsBothOfItsFiles: ufw keeps its on/off switch in ufw.conf and its
// default policy in /etc/default/ufw. Reading only the first would leave the
// policy undetermined on every Ubuntu host.
func TestUfwReadsBothOfItsFiles(t *testing.T) {
	f := fixture(t, "network-ufw")
	s := sourceAt(t, f, "/etc/ufw/ufw.conf")

	if s.Enabled != fact.EnabledYes {
		t.Errorf("enabled = %q, want %q", s.Enabled, fact.EnabledYes)
	}
	if s.Policy != fact.PolicyDeny {
		t.Errorf("policy = %q, want %q; /etc/default/ufw was not read", s.Policy, fact.PolicyDeny)
	}
	// The quoted value has to survive: DEFAULT_INPUT_POLICY="DROP".
	if s.PolicyRaw == "" {
		t.Error("no policy provenance recorded")
	}
}

// TestFirewalldTrustedZoneIsAccept.
//
// firewalld has no policy keyword. Every zone it ships rejects what it does
// not explicitly allow except `trusted`, whose target is ACCEPT — so the
// default zone's name is the policy, and changing that one word disables the
// firewall while leaving the service reporting as running.
func TestFirewalldTrustedZoneIsAccept(t *testing.T) {
	for _, tc := range []struct {
		zone string
		want fact.InputPolicy
	}{
		{"public", fact.PolicyDeny},
		{"drop", fact.PolicyDeny},
		{"trusted", fact.PolicyAllow},
		{"TRUSTED", fact.PolicyAllow},
	} {
		dir := t.TempDir()
		write(t, dir, "etc/firewalld/firewalld.conf",
			"# firewalld config\nDefaultZone="+tc.zone+"\nCleanupOnExit=yes\n")

		s := sourceAt(t, collect(t, dir), "/etc/firewalld/firewalld.conf")
		if s.Policy != tc.want {
			t.Errorf("DefaultZone=%s → policy %q, want %q", tc.zone, s.Policy, tc.want)
		}
	}
}

// TestIPTablesSavePolicyIsTheSecondField: `:INPUT DROP [0:0]`.
func TestIPTablesSavePolicyIsTheSecondField(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "etc/iptables/rules.v4",
		"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"+
			"-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")

	s := sourceAt(t, collect(t, dir), "/etc/iptables/rules.v4")
	if s.Policy != fact.PolicyDeny {
		t.Errorf("policy = %q, want %q", s.Policy, fact.PolicyDeny)
	}
	if s.Statements == 0 {
		t.Error("statements = 0 for a file full of rules")
	}
}

// TestAbsentAndRefusedAreDifferentStates: "there is no firewall" and "we were
// not allowed to read the firewall" produce opposite verdicts, and a boolean
// would have collapsed them into a guess.
func TestAbsentAndRefusedAreDifferentStates(t *testing.T) {
	none := fixture(t, "network-none")
	if got := len(none.Unreadable()); got != 0 {
		t.Errorf("network-none has %d unreadable sources, want 0: absence is a complete observation", got)
	}
	if got := len(none.Active()); got != 0 {
		t.Errorf("network-none has %d active sources, want 0", got)
	}

	denied := fixture(t, "network-denied")
	bad := denied.Unreadable()
	if len(bad) != 1 || bad[0].Path != "/etc/nftables.conf" {
		t.Fatalf("Unreadable() = %v, want just /etc/nftables.conf", bad)
	}
	if bad[0].State != fact.SourceDenied {
		t.Errorf("state = %q, want %q", bad[0].State, fact.SourceDenied)
	}
	if len(denied.Active()) != 0 {
		t.Error("a file we could not read must not count as an active configuration")
	}
}

// TestNoRulesetContentsReachTheFact. A firewall configuration is a map of the
// network — internal ranges, which hosts reach which ports — and a bundle
// designed to travel would carry it wherever the bundle is filed. Only derived
// properties are kept, plus the one policy line a finding must quote.
func TestNoRulesetContentsReachTheFact(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "etc/nftables.conf",
		"table inet filter {\n  chain input {\n"+
			"    type filter hook input priority 0; policy drop;\n"+
			"    ip saddr 10.42.7.0/24 tcp dport 5432 accept\n  }\n}\n")

	s := sourceAt(t, collect(t, dir), "/etc/nftables.conf")
	if s.PolicyRaw == "" {
		t.Fatal("no policy line recorded")
	}
	// The policy line is quoted; the rule naming an internal subnet is not.
	for _, field := range []string{s.PolicyRaw, s.Msg} {
		if strings.Contains(field, "10.42.7.0/24") {
			t.Errorf("an internal address range reached the fact in %q", field)
		}
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
