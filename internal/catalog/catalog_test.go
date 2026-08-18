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
