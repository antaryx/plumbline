package logging_test

import (
	"context"
	"path/filepath"
	"testing"

	collector "github.com/antaryx/plumbline/internal/collect/collectors/logging"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collectFixture(t *testing.T, name string) (fact.Rsyslog, fact.Journald) {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	r, _, _ := fact.Get[fact.Rsyslog](facts, fact.RsyslogID)
	j, _, _ := fact.Get[fact.Journald](facts, fact.JournaldID)
	return r, j
}

// TestBothSyntaxesProduceTheSameFacts is the collector's central claim.
//
// logging-compliant is written entirely in RainerScript and logging-legacy
// entirely in the sysklogd and $-directive forms. They describe the same host,
// so the normalised views a check reads — remote destinations, file creation
// modes — must be identical apart from provenance. Only the recorded syntax
// should differ, because a finding has to quote the operator's own language
// back to them.
func TestBothSyntaxesProduceTheSameFacts(t *testing.T) {
	rainer, _ := collectFixture(t, "logging-compliant")
	legacy, _ := collectFixture(t, "logging-legacy")

	rd, ld := rainer.RemoteDestinations(), legacy.RemoteDestinations()
	if len(rd) != 1 || len(ld) != 1 {
		t.Fatalf("destinations: rainerscript %d, legacy %d — want 1 each", len(rd), len(ld))
	}
	if rd[0].Target != ld[0].Target {
		t.Errorf("target differs by syntax: %q vs %q", rd[0].Target, ld[0].Target)
	}
	if rd[0].Protocol != ld[0].Protocol {
		t.Errorf("protocol differs by syntax: %q vs %q", rd[0].Protocol, ld[0].Protocol)
	}
	if !rd[0].Reliable() || !ld[0].Reliable() {
		t.Error("a TCP destination is not reported as reliable in one of the syntaxes")
	}

	// The provenance is what must differ.
	if rd[0].Syntax != fact.SyntaxRainerScript {
		t.Errorf("RainerScript destination recorded as %q", rd[0].Syntax)
	}
	if ld[0].Syntax != fact.SyntaxLegacy {
		t.Errorf("legacy destination recorded as %q", ld[0].Syntax)
	}

	rm, lm := rainer.FileCreateModes(), legacy.FileCreateModes()
	if len(rm) != 1 || len(lm) != 1 {
		t.Fatalf("file modes: rainerscript %d, legacy %d — want 1 each", len(rm), len(lm))
	}
	if rm[0].Mode != lm[0].Mode {
		t.Errorf("mode differs by syntax: %04o vs %04o", rm[0].Mode, lm[0].Mode)
	}
}

// TestIncludesAreFollowedInBothSyntaxes. `$IncludeConfig` and
// `include(file="...")` mean the same thing, and a collector that followed
// only one would miss every drop-in on half the hosts in service — which
// presents as "no forwarding configured" on a host that forwards.
func TestIncludesAreFollowedInBothSyntaxes(t *testing.T) {
	for _, fx := range []string{"logging-compliant", "logging-legacy"} {
		r, _ := collectFixture(t, fx)
		if len(r.Files) != 2 {
			t.Errorf("%s: read %d file(s) %v, want the main file and one drop-in", fx, len(r.Files), r.Files)
		}
		if len(r.UnresolvedIncludes) != 0 {
			t.Errorf("%s: unresolved includes %v", fx, r.UnresolvedIncludes)
		}
	}
}

// TestMultiLineRainerScriptStatements. Real omfwd actions span four or five
// lines, and a line-at-a-time parser sees none of it — it would find an
// `action(` with no parameters and report the host as not forwarding.
func TestMultiLineRainerScriptStatements(t *testing.T) {
	r, _ := collectFixture(t, "logging-compliant")

	var found bool
	for _, o := range r.Objects {
		if o.Kind != "action" {
			continue
		}
		if typ, _ := o.Param("type"); typ != "omfwd" {
			continue
		}
		found = true
		// Parameters from the second, third and fourth lines of the statement.
		for k, want := range map[string]string{
			"target":                  "logs.example.net",
			"protocol":                "tcp",
			"queue.filename":          "fwd",
			"action.resumeretrycount": "-1",
		} {
			if got, _ := o.Param(k); got != want {
				t.Errorf("param %q = %q, want %q — a continuation line was not joined", k, got, want)
			}
		}
	}
	if !found {
		t.Fatal("the multi-line omfwd action was not parsed at all")
	}
}

// TestUnresolvedIncludeIsRecorded. An include that matched nothing is not the
// same as one nobody wrote: the statement a check is looking for may be in the
// file it was meant to reach.
func TestUnresolvedIncludeIsRecorded(t *testing.T) {
	r, _ := collectFixture(t, "logging-unresolved-include")
	if !r.Installed {
		t.Fatal("rsyslog should be installed")
	}
	if len(r.UnresolvedIncludes) == 0 {
		t.Error("an include matching nothing was not recorded, so every negative verdict over this host would be unsupported")
	}
}

// TestJournaldDropInsOverrideTheMainFile pins systemd's precedence, which is
// the reverse of sshd_config's: the LAST occurrence wins.
func TestJournaldDropInsOverrideTheMainFile(t *testing.T) {
	_, j := collectFixture(t, "logging-dropin-override")

	got, ok := j.Effective("Storage")
	if !ok {
		t.Fatal("Storage not found")
	}
	if got.Value != "volatile" {
		t.Errorf("Storage = %q from %s, want %q from the drop-in; systemd applies the last occurrence",
			got.Value, got.File, "volatile")
	}
	if overridden := j.Overridden("Storage"); len(overridden) != 1 {
		t.Errorf("Overridden(Storage) returned %d, want the one occurrence in the main file", len(overridden))
	}

	persistent, known := j.StoresPersistently()
	if !known || persistent {
		t.Errorf("StoresPersistently() = (%v, %v), want (false, true)", persistent, known)
	}
}

// TestStorageAutoNeedsTheDirectory. auto is the default, and its meaning is a
// property of the filesystem rather than of the configuration — which is why
// the collector stats /var/log/journal.
func TestStorageAutoNeedsTheDirectory(t *testing.T) {
	_, present := collectFixture(t, "logging-compliant")
	if present.PersistentDirState != fact.JournalDirPresent {
		t.Errorf("journal dir state = %q, want present", present.PersistentDirState)
	}

	_, absent := collectFixture(t, "logging-nodefault")
	if absent.PersistentDirState != fact.JournalDirAbsent {
		t.Errorf("journal dir state = %q, want absent", absent.PersistentDirState)
	}
	persistent, known := absent.StoresPersistently()
	if !known {
		t.Error("Storage=auto with an absent directory should be determinable")
	}
	if persistent {
		t.Error("Storage=auto with no /var/log/journal is volatile, not persistent")
	}
}

// TestAbsentDaemonIsNotAnError. A host running only journald has no
// rsyslog.conf, and that is an observation rather than a failure — the fact is
// recorded with Installed false rather than becoming a fact error that would
// resolve every check to UNKNOWN.
func TestAbsentDaemonIsNotAnError(t *testing.T) {
	r, j := collectFixture(t, "logging-rsyslog-absent")
	if r.Installed {
		t.Error("rsyslog reported as installed on a host with no rsyslog.conf")
	}
	if !j.Installed {
		t.Error("journald reported as absent on a host with journald.conf")
	}
}

// TestNoDaemonAtAll. Both absent, both facts present and both marked absent.
func TestNoDaemonAtAll(t *testing.T) {
	r, j := collectFixture(t, "logging-absent")
	if r.Installed || j.Installed {
		t.Errorf("a host with neither daemon reports rsyslog=%v journald=%v", r.Installed, j.Installed)
	}
}

// TestLegacyRuleParsing keeps stray text out of the rule list. A line that is
// not a selector/action pair must not become a forwarding destination that
// does not exist.
func TestLegacyRuleParsing(t *testing.T) {
	r, _ := collectFixture(t, "logging-legacy")

	var sawForward, sawLocal bool
	for _, rule := range r.Rules {
		switch {
		case rule.Action == "@@logs.example.net:514":
			sawForward = true
		case rule.Action == "/var/log/auth.log":
			sawLocal = true
		}
	}
	if !sawForward {
		t.Error("the legacy forwarding rule was not parsed")
	}
	if !sawLocal {
		t.Error("a legacy local file rule was not parsed")
	}
	// $ModLoad and $FileCreateMode are directives, not rules.
	for _, rule := range r.Rules {
		if rule.Selector == "" || rule.Selector[0] == '$' {
			t.Errorf("a $-directive was recorded as a rule: %+v", rule)
		}
	}
}

// TestPortStrippingLeavesIPv6Intact. A bare IPv6 literal is all colons, and
// cutting at the last one would report a destination that does not exist — in
// a finding an operator would then go looking for.
func TestPortStrippingLeavesIPv6Intact(t *testing.T) {
	cases := map[string]string{
		"logs.example.net:514":  "logs.example.net",
		"logs.example.net":      "logs.example.net",
		"[2001:db8::1]:514":     "[2001:db8::1]",
		"2001:db8::1":           "2001:db8::1",
		"10.0.0.5:1514":         "10.0.0.5",
		"logs.example.net:síþe": "logs.example.net:síþe",
	}
	for in, want := range cases {
		r := fact.Rsyslog{Rules: []fact.RsyslogRule{{Selector: "*.*", Action: "@@" + in}}}
		got := r.RemoteDestinations()
		if len(got) != 1 {
			t.Fatalf("%q: %d destinations", in, len(got))
		}
		if got[0].Target != want {
			t.Errorf("%q -> %q, want %q", in, got[0].Target, want)
		}
	}
}
