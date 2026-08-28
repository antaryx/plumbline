package catalog_test

import (
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/sanitize"
)

// hostile is the filename from THREAT-MODEL.md T-03. A host can name a file
// this, and a check will faithfully interpolate it into a detail sentence.
const hostile = "\x1b[2J\x1b[H  All checks passed"

// evilCheck is a check written the ordinary way: it quotes what it found
// without knowing that what it found is an attack on the operator's terminal.
// Nothing about it is careless — this is what every check does.
var evilCheck = catalog.Check{
	ID:           "TEST-0001",
	Module:       "TEST",
	Title:        "check that quotes untrusted host data",
	BaseSeverity: finding.High,
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 1,
	Eval: func(*fact.Set) catalog.Outcome {
		return catalog.Outcome{
			Result:   finding.Fail,
			Subject:  hostile,
			Detail:   "PermitRootLogin is set in " + hostile,
			Evidence: []finding.Evidence{{Source: hostile, Line: 1, Excerpt: hostile}},
		}
	},
	Remediation: &finding.Remediation{Summary: "s", Effort: "LOW"},
}

func factsWithSSHD() *fact.Set {
	fs := fact.NewSet()
	fs.Put(fact.SSHDConfig{Installed: true, Files: []string{"/etc/ssh/sshd_config"}})
	return fs
}

// TestFindingsAreSanitisedOnTheWayOut is the acceptance criterion, asserted at
// the highest level that exists today: whatever a check produces, the finding
// that leaves the runner is inert.
//
// The enforcement point matters as much as the result. Sanitising in each
// renderer would mean the next output format forgets; sanitising in the
// evidence constructor alone would mean the next check that writes an Evidence
// literal forgets. Doing it here means neither can.
func TestFindingsAreSanitisedOnTheWayOut(t *testing.T) {
	got := catalog.MustNew(evilCheck).Evaluate(factsWithSSHD())
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	f := got[0]

	for _, field := range []struct{ name, value string }{
		{"detail", f.Detail},
		{"subject", f.Subject},
		{"evidence source", f.Evidence[0].Source},
		{"evidence excerpt", f.Evidence[0].Excerpt},
	} {
		if strings.ContainsRune(field.value, 0x1b) {
			t.Errorf("%s still contains a raw ESC: %q", field.name, field.value)
		}
		if !strings.Contains(field.value, `\x1b`) {
			t.Errorf("%s lost the escape entirely rather than showing it: %q", field.name, field.value)
		}
	}

	// The verdict itself is untouched: sanitisation is about how text is
	// rendered, never about what was decided.
	if f.Result != finding.Fail {
		t.Errorf("result = %s, want FAIL", f.Result)
	}
}

// TestFingerprintIsTakenFromSanitisedSubject: a suppression an operator wrote
// against a finding must not be dodgeable by re-encoding a control character
// in the subject.
func TestFingerprintIsTakenFromSanitisedSubject(t *testing.T) {
	got := catalog.MustNew(evilCheck).Evaluate(factsWithSSHD())[0]
	if want := finding.Fingerprint("TEST-0001", sanitize.Text(hostile)); got.Fingerprint != want {
		t.Errorf("fingerprint = %s, want %s (taken from the sanitised subject)", got.Fingerprint, want)
	}
}

// TestOrdinaryTextIsUnchanged: the control must be invisible in the normal
// case, or check authors will start working around it.
func TestOrdinaryTextIsUnchanged(t *testing.T) {
	plain := evilCheck
	plain.ID = "TEST-0002"
	plain.Eval = func(*fact.Set) catalog.Outcome {
		return catalog.Outcome{
			Result:   finding.Pass,
			Detail:   "PermitRootLogin is set to no; direct root login over SSH is refused.",
			Evidence: []finding.Evidence{{Source: "/etc/ssh/sshd_config", Line: 3, Excerpt: "PermitRootLogin no"}},
		}
	}
	plain.Remediation = nil

	got := catalog.MustNew(plain).Evaluate(factsWithSSHD())[0]
	if got.Detail != "PermitRootLogin is set to no; direct root login over SSH is refused." {
		t.Errorf("ordinary detail was altered: %q", got.Detail)
	}
	if got.Evidence[0].Source != "/etc/ssh/sshd_config" || got.Evidence[0].Excerpt != "PermitRootLogin no" {
		t.Errorf("ordinary evidence was altered: %+v", got.Evidence[0])
	}
}

// TestAnOpaqueFactStopsTheCheckBeforeEval.
//
// The required-fact gate has three states to distinguish and had only two: a
// fact that errored, and a fact that was never collected. The third — present,
// preserved, and not interpretable by this build — passed the gate, and the
// check then read the zero value out of its typed accessor and reported the
// host as having no sshd at all.
//
// The gate is where this belongs rather than in each check, for the reason the
// other two branches are there: a rule applied at every call site is a rule
// that gets forgotten at one of them.
func TestAnOpaqueFactStopsTheCheckBeforeEval(t *testing.T) {
	evaluated := false
	ck := catalog.Check{
		ID: "TEST-0001", Module: "TEST", Title: "reads a fact",
		BaseSeverity: finding.Medium,
		Requires:     []fact.ID{fact.SSHDConfigID},
		SinceCatalog: 1,
		Eval: func(*fact.Set) catalog.Outcome {
			evaluated = true
			return catalog.Outcome{Result: finding.Pass, Detail: "nothing was wrong"}
		},
	}

	set := fact.NewSet()
	set.Put(opaqueFact{id: fact.SSHDConfigID, version: 99})

	got := catalog.MustNew(ck).Evaluate(set)[0]
	if evaluated {
		t.Error("Eval ran over a fact this build cannot interpret")
	}
	if got.Result != finding.Unknown {
		t.Fatalf("result = %s, want UNKNOWN: %s", got.Result, got.Detail)
	}
	if got.UnknownReason != finding.ReasonFactVersion {
		t.Errorf("reason = %q, want %q", got.UnknownReason, finding.ReasonFactVersion)
	}
	if !strings.Contains(got.Detail, "99") {
		t.Errorf("the detail does not name the version that could not be read: %s", got.Detail)
	}
	if len(got.Evidence) == 0 {
		t.Error("UNKNOWN with no evidence")
	}
}

// opaqueFact is a fact.Opaque that does not drag internal/bundle into this
// package's imports. Evaluation must not depend on the serialisation layer.
type opaqueFact struct {
	id      fact.ID
	version int
}

func (o opaqueFact) FactID() fact.ID  { return o.id }
func (o opaqueFact) FactVersion() int { return o.version }
func (o opaqueFact) OpaqueFact() int  { return o.version }

// tape records what an Observer was told, in the order it was told.
type tape struct{ ids []string }

func (t *tape) CheckDone(f finding.Finding) { t.ids = append(t.ids, f.CheckID) }

// TestTheObserverSeesEveryCheckInTheOrderTheSliceCarries.
//
// The live display and the report have to agree about what ran, and the only
// way they can disagree is if the events and the slice are built by two
// different walks. They are built by one, and this is what says so.
func TestTheObserverSeesEveryCheckInTheOrderTheSliceCarries(t *testing.T) {
	c := catalog.MustNew(
		passing("BBB-0001"),
		passing("AAA-0002"),
		passing("AAA-0001"),
	)

	var seen tape
	out := c.EvaluateWith(fact.NewSet(), &seen)

	if len(out) != len(seen.ids) {
		t.Fatalf("%d findings but %d events", len(out), len(seen.ids))
	}
	for i := range out {
		if out[i].CheckID != seen.ids[i] {
			t.Errorf("event %d was %s, slice has %s", i, seen.ids[i], out[i].CheckID)
		}
	}
	// And that order is the catalog's sorted order, which is what makes two
	// runs over one bundle byte-identical.
	if got := strings.Join(seen.ids, ","); got != "AAA-0001,AAA-0002,BBB-0001" {
		t.Errorf("events came in %s", got)
	}
}

// A check that panics still reaches the observer, as the UNKNOWN the runner
// turned it into. A display that skipped the row would leave a gap exactly
// where the operator most needs to see something happened.
func TestAPanickingCheckStillReachesTheObserver(t *testing.T) {
	c := catalog.MustNew(catalog.Check{
		ID: "BOOM-0001", Module: "BOOM", Title: "t",
		BaseSeverity: finding.Low, Requires: []fact.ID{fact.SSHDConfigID},
		Eval: func(*fact.Set) catalog.Outcome { panic("no") },
	})

	fs := fact.NewSet()
	fs.Put(fact.SSHDConfig{Installed: true})

	var seen tape
	c.EvaluateWith(fs, &seen)
	if len(seen.ids) != 1 || seen.ids[0] != "BOOM-0001" {
		t.Errorf("the panicking check produced events %v", seen.ids)
	}
}

// Evaluate is EvaluateWith with no observer, and must stay exactly that.
func TestEvaluateAndEvaluateWithAgree(t *testing.T) {
	c := catalog.MustNew(passing("AAA-0001"), passing("BBB-0001"))
	fs := fact.NewSet()

	plain := c.Evaluate(fs)
	watched := c.EvaluateWith(fs, &tape{})
	if len(plain) != len(watched) {
		t.Fatalf("%d findings without an observer, %d with", len(plain), len(watched))
	}
	for i := range plain {
		if plain[i].CheckID != watched[i].CheckID || plain[i].Result != watched[i].Result {
			t.Errorf("%s: %s without an observer, %s with",
				plain[i].CheckID, plain[i].Result, watched[i].Result)
		}
	}
}

// passing is a check that needs a fact nothing supplies, so it resolves to
// UNKNOWN without any fixture. What these tests assert is the walk, not the
// verdict.
func passing(id string) catalog.Check {
	return catalog.Check{
		ID: id, Module: strings.SplitN(id, "-", 2)[0], Title: "t",
		BaseSeverity: finding.Low, Requires: []fact.ID{fact.SSHDConfigID},
		Eval: func(*fact.Set) catalog.Outcome {
			return catalog.Outcome{Result: finding.Pass, Detail: "d"}
		},
	}
}
