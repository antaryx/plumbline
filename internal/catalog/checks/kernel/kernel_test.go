package kernel_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/kernel"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/kernel"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the module's catalog as this work package leaves it. Listing the
// checks once means a new check cannot be added without appearing in the
// invariant tests below.
var all = []catalog.Check{
	checks.Check0001,
	checks.Check0002,
	checks.Check0003,
	checks.Check0004,
	checks.Check0005,
	checks.Check0006,
	checks.Check0007,
	checks.Check0008,
	checks.Check0009,
	checks.Check0010,
	checks.Check0011,
	checks.Check0012,
	checks.Check0013,
	checks.Check0014,
	checks.Check0015,
	checks.Check0016, checks.Check0017,
	checks.Check0018, checks.Check0019, checks.Check0020, checks.Check0021, checks.Check0022,
}

// collectFixture runs the real collector against a fixture tree.
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

// evalFixture runs the real collector against a fixture and then one real
// check against the resulting facts. Tests exercise the whole vertical slice,
// not the check in isolation, because most check bugs are collector bugs.
func evalFixture(t *testing.T, check catalog.Check, name string) finding.Finding {
	t.Helper()

	got := catalog.MustNew(check).Evaluate(collectFixture(t, name))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

// tc is one fixture expectation.
type tc struct {
	fixture  string
	result   finding.Result
	severity finding.Severity      // "" means: do not assert
	reason   finding.UnknownReason // "" means: do not assert
	// detailContains guards against a correct verdict with a misleading
	// explanation, which is its own class of bug.
	detailContains string
}

// run executes one check's table and asserts the invariants that hold for
// every check in the project.
func run(t *testing.T, check catalog.Check, cases []tc) {
	t.Helper()

	for _, c := range cases {
		t.Run(check.ID+"/"+c.fixture, func(t *testing.T) {
			got := evalFixture(t, check, c.fixture)

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

			if got.CheckID != check.ID || got.Module != "KERNEL" {
				t.Errorf("identity wrong: %s / %s", got.CheckID, got.Module)
			}
			if got.BaseSeverity != check.BaseSeverity {
				t.Errorf("base severity mutated: %s, want %s", got.BaseSeverity, check.BaseSeverity)
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
			// Every FAIL and every UNKNOWN must be citable. A finding without
			// evidence is a rumour and an auditor cannot use it.
			if (got.Result == finding.Fail || got.Result == finding.Unknown) && len(got.Evidence) == 0 {
				t.Errorf("%s carries no evidence", got.Result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestKernel0001ASLR(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "randomised"},
		{fixture: "kernel-weak", result: finding.Fail, severity: finding.High, detailContains: "disabled entirely"},
		{
			// Partial randomisation is a real state and a lesser one, and the
			// severity has to say so or an operator cannot triage.
			fixture: "kernel-partial", result: finding.Fail, severity: finding.Medium,
			detailContains: "heap layout predictable",
		},
		{
			fixture: "kernel-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read",
		},
		{
			// Something is mounted over /proc/sys. Neither a fabricated 0 nor
			// a fabricated 2 is available to us.
			fixture: "kernel-unparseable", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "not the single integer",
		},
		{
			// The file says 2, the kernel says 0. The failing finding has to
			// point at the configuration, or the operator edits it again.
			fixture: "kernel-drift", result: finding.Fail, severity: finding.High,
			detailContains: "does not match its own configuration",
		},
	})
}

func TestKernel0002KptrRestrict(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "CAP_SYSLOG"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "printed in full"},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "hidden from all users"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0003PtraceScope(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "own descendants"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "read its memory"},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "cannot be re-enabled"},
		{
			// Yama is not in this kernel. There is no parameter to set, so
			// there is nothing to fail: NOT_APPLICABLE means the subject does
			// not exist, and this is the only place in the module it does.
			fixture: "kernel-absent", result: finding.NotApplicable,
			detailContains: "does not expose",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0004DmesgRestrict(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "CAP_SYSLOG"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "any user may read"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0005SuidDumpable(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "do not produce core dumps"},
		{fixture: "kernel-weak", result: finding.Fail, severity: finding.Medium, detailContains: "crashing one"},
		{
			// 2 still writes privileged memory to disk but only root can read
			// it, which is a smaller exposure and a lower severity.
			fixture: "kernel-partial", result: finding.Fail, severity: finding.Low,
			detailContains: "only root may read",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0006UnprivilegedBPF(t *testing.T) {
	run(t, checks.Check0006, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "locked until reboot"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "privilege-escalation surface"},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "may still be raised"},
		{fixture: "kernel-absent", result: finding.NotApplicable, detailContains: "does not expose"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0007Drift(t *testing.T) {
	run(t, checks.Check0007, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "survive a reboot"},
		{
			// The whole reason this check exists: the file was hardened and
			// nobody rebooted, so the host is unprotected today while its
			// configuration says otherwise.
			fixture: "kernel-drift", result: finding.Fail,
			detailContains: "differ between the running kernel",
		},
		{
			// Nothing is configured at all, so there is no configured value
			// for the running kernel to disagree with.
			fixture: "kernel-weak", result: finding.NotApplicable,
			detailContains: "no sysctl configuration file",
		},
		{
			// Two files, two values, and the winner depends on which sysctl
			// implementation applied them. The check refuses to pick.
			fixture: "kernel-conflict", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "more than one configuration file",
		},
		{
			// Part of the configuration could not be read, so "nothing drifts"
			// is a claim about a file we never opened.
			fixture: "kernel-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read",
		},
		{
			// The file configures Yama on a kernel that has no Yama. The
			// setting is inert, and counting it as agreement would report
			// "the configuration matches" about a parameter that does not
			// exist.
			fixture: "kernel-absent", result: finding.NotApplicable,
			detailContains: "does not implement",
		},
	})
}

// TestDriftDoesNotCountInertSettings pins the distinction the previous case
// rests on. A parameter the kernel does not implement is not agreement and not
// drift; it is a setting that does nothing, and the finding has to say which.
func TestDriftDoesNotCountInertSettings(t *testing.T) {
	got := evalFixture(t, checks.Check0007, "kernel-absent")
	if strings.Contains(strings.ToLower(got.Detail), "match the running kernel") {
		t.Errorf("an inert setting was reported as agreement: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "kernel.yama.ptrace_scope") {
		t.Errorf("the inert setting was not named: %s", got.Detail)
	}
}

// TestDriftIgnoresUnprobedKeys: the configuration in kernel-drift sets a key
// this module never reads. The check must say nothing about it, because it has
// no running value to compare and no way to know whether the kernel has it.
func TestDriftIgnoresUnprobedKeys(t *testing.T) {
	got := evalFixture(t, checks.Check0007, "kernel-drift")
	if strings.Contains(got.Detail, "not_a_real_parameter") {
		t.Errorf("the check judged a parameter it never probed: %s", got.Detail)
	}
}

func TestKernel0008RPFilter(t *testing.T) {
	run(t, checks.Check0008, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "enabled on all"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "cannot be trusted"},
		{
			// conf.all is 0 but eth0 is 2, and the effective value is the
			// maximum of the two. A check reading conf.all alone would report
			// this host as unfiltered, which is the trap this check exists to
			// avoid.
			fixture: "kernel-partial", result: finding.Pass,
			detailContains: "loose mode",
		},
		{
			fixture: "kernel-loopback-only", result: finding.NotApplicable,
			detailContains: "no non-loopback network interface",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0009ProtectedSymlinks(t *testing.T) {
	run(t, checks.Check0009, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "only followed when"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "planted there"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0010ProtectedHardlinks(t *testing.T) {
	run(t, checks.Check0010, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "owns or can read and write"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "cannot read into a directory they control"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0011ProtectedFifos(t *testing.T) {
	run(t, checks.Check0011, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "world-writable sticky directory is refused"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "block it indefinitely"},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "group-writable"},
		{
			// The parameter arrived in Linux 4.19. An older kernel does not
			// have it to set, which is NOT_APPLICABLE and not a failure.
			fixture: "kernel-absent", result: finding.NotApplicable,
			detailContains: "does not expose",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0012ProtectedRegular(t *testing.T) {
	run(t, checks.Check0012, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "group-writable"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "attacker planted"},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "world-writable sticky directory is refused"},
		{fixture: "kernel-absent", result: finding.NotApplicable, detailContains: "does not expose"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0013PerfEventParanoid(t *testing.T) {
	run(t, checks.Check0013, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "may not profile the kernel"},
		{
			// -1 is the documented value for no restriction whatsoever, which
			// is materially worse than a merely permissive setting.
			fixture: "kernel-weak", result: finding.Fail, severity: finding.High,
			detailContains: "entirely unrestricted",
		},
		{fixture: "kernel-partial", result: finding.Fail, severity: finding.Medium, detailContains: "may still profile the kernel"},
		{
			// Something is mounted over /proc/sys; neither a fabricated -1 nor
			// a fabricated 2 is available to us.
			fixture: "kernel-unparseable", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "not the single integer",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

func TestKernel0014CorePattern(t *testing.T) {
	run(t, checks.Check0014, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "pipes core dumps to /usr/lib/systemd/systemd-coredump"},
		{
			// The kernel's own default is the bare word "core", which writes
			// the dump into the crashing process's working directory.
			fixture: "kernel-weak", result: finding.Fail,
			detailContains: "relative path",
		},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "one known location"},
		{
			// Pointed at /tmp during a debugging session and never put back:
			// world-writable destination, and it drifted from the file.
			fixture: "kernel-drift", result: finding.Fail,
			detailContains: "world-writable",
		},
		{
			fixture: "kernel-unparseable", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "is empty",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

// TestCorePatternDriftIsNamed: the failing finding has to point at the
// configuration, or the operator re-applies a file that is already correct.
func TestCorePatternDriftIsNamed(t *testing.T) {
	got := evalFixture(t, checks.Check0014, "kernel-drift")
	if !strings.Contains(got.Detail, "does not match its own configuration") {
		t.Errorf("the drift was not reported: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "systemd-coredump") {
		t.Errorf("the configured value was not named: %s", got.Detail)
	}
	var sawConfig bool
	for _, e := range got.Evidence {
		if strings.Contains(e.Source, "sysctl") {
			sawConfig = true
			if e.SHA256 == "" {
				t.Errorf("configuration evidence carries no digest: %+v", e)
			}
		}
	}
	if !sawConfig {
		t.Error("no evidence cites the configuration file")
	}
}

func TestKernel0015AcceptSourceRoute(t *testing.T) {
	run(t, checks.Check0015, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "refused on every interface"},
		{fixture: "kernel-weak", result: finding.Fail, detailContains: "accept source-routed packets"},
		{
			// conf.all is 0 while eth0 is 1. The kernel takes the logical AND
			// here, not the maximum it takes for rp_filter, so this host is
			// safe. A check that reused KERNEL-0008's rule would say the
			// opposite, which is the whole reason this fixture exists.
			fixture: "kernel-partial", result: finding.Pass,
			detailContains: "both non-zero",
		},
		{
			fixture: "kernel-loopback-only", result: finding.NotApplicable,
			detailContains: "no non-loopback network interface",
		},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be resolved"},
	})
}

// TestSourceRouteCombiningRuleIsAndNotMax pins the distinction directly. In
// kernel-partial eth0 carries 1; under the rp_filter maximum rule this host
// would be reported as accepting source routing, and it does not.
func TestSourceRouteCombiningRuleIsAndNotMax(t *testing.T) {
	got := evalFixture(t, checks.Check0015, "kernel-partial")
	if got.Result != finding.Pass {
		t.Fatalf("result = %s, want PASS: conf.all is 0, so the AND can never be true\n detail: %s",
			got.Result, got.Detail)
	}
	// The interface that would take effect if conf.all were raised is named,
	// because a PASS that hides a loaded gun is not helpful.
	if !strings.Contains(got.Detail, "eth0") {
		t.Errorf("the non-zero interface was not named: %s", got.Detail)
	}

	// And the same rule must not turn a genuinely accepting host into a PASS.
	got = evalFixture(t, checks.Check0015, "kernel-weak")
	if got.Result != finding.Fail {
		t.Errorf("result = %s, want FAIL: conf.all and eth0 are both 1", got.Result)
	}
	if !strings.Contains(got.Detail, "eth0") {
		t.Errorf("the accepting interface was not named: %s", got.Detail)
	}
}

func TestKernel0016TCPSyncookies(t *testing.T) {
	run(t, checks.Check0016, []tc{
		{fixture: "kernel-hardened", result: finding.Pass, detailContains: "backlog overflows"},
		{fixture: "kernel-weak", result: finding.Fail, severity: finding.Low, detailContains: "deny service"},
		{fixture: "kernel-partial", result: finding.Pass, detailContains: "unconditionally"},
		{fixture: "kernel-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
	})
}

// ---------------------------------------------------------------------------
// module-wide invariants
// ---------------------------------------------------------------------------

// TestLoopbackIsNotJudged pins the deliberate exclusion in KERNEL-0008. The
// hardened fixture leaves lo at 0, as every distribution does, and a check that
// judged it would fail on almost every host in the world.
func TestLoopbackIsNotJudged(t *testing.T) {
	got := evalFixture(t, checks.Check0008, "kernel-hardened")
	if got.Result != finding.Pass {
		t.Fatalf("result = %s, want PASS; lo is 0 in this fixture and must not be judged", got.Result)
	}
	if strings.Contains(got.Detail, "lo") && strings.Contains(got.Detail, "off on") {
		t.Errorf("loopback was reported as unfiltered: %s", got.Detail)
	}
}

// TestNoCheckPassesWhatItCouldNotRead is the module's central invariant. Every
// parameter in kernel-denied exists and is unreadable, so no check may report
// PASS from it — that would convert an unprivileged scan into a clean bill of
// health, which is the failure mode this project exists to prevent.
func TestNoCheckPassesWhatItCouldNotRead(t *testing.T) {
	for _, check := range all {
		got := evalFixture(t, check, "kernel-denied")
		if got.Result == finding.Pass {
			t.Errorf("%s returned PASS for a host whose parameters it could not read: %s",
				check.ID, got.Detail)
		}
		if got.Result == finding.Unknown && got.UnknownReason == "" {
			t.Errorf("%s returned UNKNOWN without a reason", check.ID)
		}
	}
}

// TestAbsentIsNotUnknown is the other half. A parameter this kernel does not
// implement is NOT_APPLICABLE, not UNKNOWN: there is nothing to harden, and
// reporting ignorance would bury the real UNKNOWNs in noise.
func TestAbsentIsNotUnknown(t *testing.T) {
	for _, check := range []catalog.Check{checks.Check0003, checks.Check0006} {
		got := evalFixture(t, check, "kernel-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s returned %s for a parameter absent from the kernel, want NOT_APPLICABLE: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestCheckIdentityIsWellFormed guards the properties that outlive any single
// release: IDs appear in users' suppression files and must never be reused or
// renumbered.
func TestCheckIdentityIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, check := range all {
		if seen[check.ID] {
			t.Errorf("duplicate check ID %s", check.ID)
		}
		seen[check.ID] = true

		if !strings.HasPrefix(check.ID, "KERNEL-") {
			t.Errorf("%s is not in the KERNEL module namespace", check.ID)
		}
		if check.Module != "KERNEL" {
			t.Errorf("%s declares module %q", check.ID, check.Module)
		}
		if check.Title == "" || check.Description == "" {
			t.Errorf("%s has no title or description", check.ID)
		}
		if len(check.Requires) == 0 {
			t.Errorf("%s declares no required facts, so the runner cannot gate it", check.ID)
		}
		if check.Remediation == nil {
			t.Errorf("%s has no remediation; every check that can FAIL ships a fix", check.ID)
		}
		// The module spans three catalog versions now: 2 introduced it, 3
		// completed the runtime checks, and 25 added the first check about the
		// configuration files rather than /proc/sys. SinceCatalog lets
		// `plumbline diff` tell "newly failing" from "newly existing", so it
		// must record when the check actually entered the catalog and never be
		// bulk-updated to the current version — which is what this assertion
		// is guarding, and why it names the versions rather than accepting any.
		switch check.SinceCatalog {
		case 2, 3, 25, 26, 27, 28:
		default:
			t.Errorf("%s declares SinceCatalog %d, want 2, 3, 25, 26, 27 or 28", check.ID, check.SinceCatalog)
		}
		if check.SinceCatalog > catalog.Version {
			t.Errorf("%s declares SinceCatalog %d, which is ahead of catalog.Version %d",
				check.ID, check.SinceCatalog, catalog.Version)
		}
	}
}

// TestNoPanicOnEmptyFacts asserts the runner's required-fact gate: a check must
// never see a missing fact, and must never crash the scan.
func TestNoPanicOnEmptyFacts(t *testing.T) {
	for _, check := range all {
		got := catalog.MustNew(check).Evaluate(fact.NewSet())
		if len(got) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", check.ID, len(got))
		}
		if got[0].Result != finding.Unknown {
			t.Errorf("%s: result = %s, want UNKNOWN", check.ID, got[0].Result)
		}
		if got[0].UnknownReason != finding.ReasonFactMissing {
			t.Errorf("%s: reason = %q, want %q", check.ID, got[0].UnknownReason, finding.ReasonFactMissing)
		}
	}
}

// TestFingerprintStability guards the suppression and SARIF baseline contract:
// a finding's identity must not change when its verdict does.
func TestFingerprintStability(t *testing.T) {
	pass := evalFixture(t, checks.Check0001, "kernel-hardened")
	fail := evalFixture(t, checks.Check0001, "kernel-weak")
	if pass.Fingerprint != fail.Fingerprint {
		t.Errorf("fingerprint changed with verdict: %s vs %s", pass.Fingerprint, fail.Fingerprint)
	}
}

// TestDeterminism asserts the property the whole architecture exists to
// provide. The KERNEL fact is built from maps, and a check that iterated one
// without sorting would produce a detail string that changed between runs.
func TestDeterminism(t *testing.T) {
	for _, fixture := range []string{"kernel-drift", "kernel-partial", "kernel-conflict"} {
		first := catalog.MustNew(all...).Evaluate(collectFixture(t, fixture))
		for i := 0; i < 25; i++ {
			got := catalog.MustNew(all...).Evaluate(collectFixture(t, fixture))
			if len(got) != len(first) {
				t.Fatalf("%s: finding count changed on iteration %d", fixture, i)
			}
			for n := range got {
				if got[n].Result != first[n].Result ||
					got[n].Detail != first[n].Detail ||
					got[n].Fingerprint != first[n].Fingerprint {
					t.Fatalf("%s: %s non-deterministic on iteration %d:\n first: %s\n  then: %s",
						fixture, got[n].CheckID, i, first[n].Detail, got[n].Detail)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// KERNEL-0017, the module's first check about the files rather than /proc/sys
// ---------------------------------------------------------------------------

func TestKernel0017PersistentBPFHardening(t *testing.T) {
	run(t, checks.Check0017, []tc{
		// Both keys on disk, in one file.
		{fixture: "kernel-hardened", result: finding.Pass,
			detailContains: "Both BPF hardening parameters are written"},

		// Both on disk, split across /etc/sysctl.conf and a drop-in.
		{fixture: "kernel-bpf-persisted", result: finding.Pass,
			detailContains: "Both BPF hardening parameters are written"},

		// The case the check exists for: hardened now, gone at reboot.
		{fixture: "kernel-bpf-runtime-only", result: finding.Fail, severity: finding.High,
			detailContains: "is not set in any sysctl configuration file"},

		// Two files disagree; which wins depends on the tool.
		{fixture: "kernel-bpf-conflict", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "different values in more than one"},

		// 2 for the caller half is fine; 1 for the JIT half is not.
		{fixture: "kernel-bpf-weak", result: finding.Fail, severity: finding.High,
			detailContains: "unprivileged programs only"},

		// No configuration file anywhere is not a finding about a file.
		{fixture: "kernel-bpf-noconfig", result: finding.NotApplicable,
			detailContains: "No sysctl configuration file exists"},

		// A kernel with no BPF at all has nothing to persist.
		{fixture: "kernel-absent", result: finding.NotApplicable,
			detailContains: "implements none of"},

		// A file we could not open may hold either setting.
		{fixture: "kernel-denied", result: finding.Unknown,
			detailContains: "could not be read"},
	})
}

// TestRuntimeHardeningWithoutPersistenceIsTheWholePoint.
//
// kernel-bpf-runtime-only has both parameters hardened in /proc/sys and
// neither in any file. It is the shape three checks disagree about, and the
// disagreement is correct in every case: KERNEL-0006 reports the running value
// and passes; KERNEL-0007 skips a parameter no file mentions, because there is
// nothing to compare it against; KERNEL-0017 is the only one that says this
// host un-hardens itself at the next reboot.
//
// If this ever stops holding, the most likely cause is KERNEL-0007 being
// "improved" to treat unconfigured-but-running as drift — which would be a
// reasonable-looking change that silently makes this check redundant and
// reports the finding against the wrong subject.
func TestRuntimeHardeningWithoutPersistenceIsTheWholePoint(t *testing.T) {
	const fixture = "kernel-bpf-runtime-only"

	if got := evalFixture(t, checks.Check0006, fixture); got.Result != finding.Pass {
		t.Errorf("KERNEL-0006 = %s over a host hardened at runtime, want PASS: %s", got.Result, got.Detail)
	}
	if got := evalFixture(t, checks.Check0007, fixture); got.Result != finding.Pass {
		t.Errorf("KERNEL-0007 = %s, want PASS: a parameter no file sets has nothing to drift from: %s", got.Result, got.Detail)
	}

	got := evalFixture(t, checks.Check0017, fixture)
	if got.Result != finding.Fail {
		t.Fatalf("KERNEL-0017 = %s, want FAIL: %s", got.Result, got.Detail)
	}
	// And it has to say *why* this is not a duplicate of the two passes above,
	// or an operator reading three findings will act on the wrong one.
	if !strings.Contains(got.Detail, "protected now and will not be after the next reboot") {
		t.Errorf("the verdict does not explain the trap it caught: %s", got.Detail)
	}
	for _, key := range []string{"kernel.unprivileged_bpf_disabled", "net.core.bpf_jit_harden"} {
		if !strings.Contains(got.Detail, key) {
			t.Errorf("%s is not named: %s", key, got.Detail)
		}
	}
}

// TestBothBPFParametersAreRequiredSeparately. They are independent settings
// doing different jobs — who may call bpf(), and what the JIT emits for the
// programs that are loaded — so one standing in for the other would report a
// half-hardened host as hardened.
func TestBothBPFParametersAreRequiredSeparately(t *testing.T) {
	got := evalFixture(t, checks.Check0017, "kernel-bpf-weak")

	if got.Result != finding.Fail {
		t.Fatalf("= %s, want FAIL: %s", got.Result, got.Detail)
	}
	// The JIT half fails.
	if !strings.Contains(got.Detail, "net.core.bpf_jit_harden is 1") {
		t.Errorf("the failing parameter is not named with its value: %s", got.Detail)
	}
	// The caller half at 2 must not be reported as a failure: it refuses
	// unprivileged bpf() exactly as 1 does, and failing it would be a finding
	// against a host that is not exposed.
	if strings.Contains(got.Detail, "kernel.unprivileged_bpf_disabled is 2 at") &&
		strings.Contains(got.Detail, "any local user may load BPF programs") {
		t.Errorf("unprivileged_bpf_disabled = 2 was reported as a failure: %s", got.Detail)
	}
}

// TestTheWeakerAcceptedValueIsStillNamed.
//
// unprivileged_bpf_disabled = 2 passes and buys slightly less than 1: both
// refuse unprivileged bpf(), and only 1 locks the setting for the rest of the
// boot. The same two-tier shape SERVICES-0008 uses for ProtectHome=read-only —
// pass, and say what it did not buy, rather than failing a host that is not
// exposed or passing it silently.
func TestTheWeakerAcceptedValueIsStillNamed(t *testing.T) {
	// Built by hand: the fixture corpus has no host with 2 for the caller half
	// and 2 for the JIT half, and inventing one for a wording assertion is
	// less honest than saying what is being tested.
	sc := fact.Sysctl{
		Running:    map[string]fact.SysctlRunning{},
		Configured: map[string][]fact.SysctlSetting{},
		Digests:    map[string]string{},
		Files:      []string{"/etc/sysctl.d/60-hardening.conf"},
	}
	sc.Configured["kernel.unprivileged_bpf_disabled"] = []fact.SysctlSetting{{
		Key: "kernel.unprivileged_bpf_disabled", Value: "2",
		File: "/etc/sysctl.d/60-hardening.conf", Line: 1,
	}}
	sc.Configured["net.core.bpf_jit_harden"] = []fact.SysctlSetting{{
		Key: "net.core.bpf_jit_harden", Value: "2",
		File: "/etc/sysctl.d/60-hardening.conf", Line: 2,
	}}

	fs := fact.NewSet()
	fs.Put(sc)
	got := catalog.MustNew(checks.Check0017).Evaluate(fs)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Result != finding.Pass {
		t.Fatalf("= %s, want PASS: 2 refuses unprivileged bpf(): %s", got[0].Result, got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "1 additionally locks the setting") {
		t.Errorf("the pass does not say what 2 did not buy: %s", got[0].Detail)
	}
}

// TestAConflictIsNotAVerdict. procps and systemd-sysctl walk the drop-in
// directories in different orders, so two files disagreeing means the next
// boot depends on which tool applies them. Guessing would be a confident claim
// about exactly the thing this check reports on.
func TestAConflictIsNotAVerdict(t *testing.T) {
	got := evalFixture(t, checks.Check0017, "kernel-bpf-conflict")

	if got.Result != finding.Unknown {
		t.Fatalf("= %s, want UNKNOWN: %s", got.Result, got.Detail)
	}
	// Both files named, because the remedy is to delete one of them and the
	// operator needs to know which two are in play.
	for _, file := range []string{"/etc/sysctl.d/60-hardening.conf", "/run/sysctl.d/50-cloud.conf"} {
		if !strings.Contains(got.Detail, file) {
			t.Errorf("%s is not named: %s", file, got.Detail)
		}
	}
	if len(got.Evidence) < 2 {
		t.Errorf("evidence cites %d lines, want both sides of the conflict", len(got.Evidence))
	}
}

// TestTheConfiguredCheckCitesFilesAndLines. Its whole subject is a file, so a
// finding that did not say which file and which line would send an operator
// grepping five directories.
func TestTheConfiguredCheckCitesFilesAndLines(t *testing.T) {
	got := evalFixture(t, checks.Check0017, "kernel-bpf-persisted")

	if got.Result != finding.Pass {
		t.Fatalf("= %s, want PASS: %s", got.Result, got.Detail)
	}
	if len(got.Evidence) != 2 {
		t.Fatalf("evidence = %d entries, want one per parameter: %+v", len(got.Evidence), got.Evidence)
	}
	// The two parameters come from two different sources in this fixture, which
	// is what proves the collector merges them rather than reading one.
	sources := map[string]bool{}
	for _, e := range got.Evidence {
		sources[e.Source] = true
		if e.Line == 0 {
			t.Errorf("evidence cites no line: %+v", e)
		}
		if e.SHA256 == "" {
			t.Errorf("evidence cites no digest, so an auditor cannot verify it: %+v", e)
		}
	}
	if len(sources) != 2 {
		t.Errorf("both parameters were read from one file; the fixture splits them: %v", sources)
	}
}

// ---------------------------------------------------------------------------
// KERNEL-0018 and -0019, the information-leak pair
// ---------------------------------------------------------------------------

func TestKernel0018KptrRestrictPersisted(t *testing.T) {
	run(t, checks.Check0018, []tc{
		{fixture: "kernel-leak-restricted", result: finding.Pass,
			detailContains: "prints zeros for every reader"},

		// Written at 1: a band below the host that wrote nothing.
		{fixture: "kernel-leak-capsyslog", result: finding.Fail, severity: finding.Medium,
			detailContains: "CAP_SYSLOG"},

		// Written nowhere.
		{fixture: "kernel-leak-open", result: finding.Fail, severity: finding.High,
			detailContains: "not set in any sysctl configuration file"},

		// Two files disagree.
		{fixture: "kernel-leak-conflict", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "different values in more than one"},

		// The gates.
		{fixture: "kernel-bpf-noconfig", result: finding.NotApplicable,
			detailContains: "No sysctl configuration file exists"},
		{fixture: "kernel-denied", result: finding.Unknown,
			detailContains: "could not be read"},
	})
}

func TestKernel0019DmesgRestrictPersisted(t *testing.T) {
	run(t, checks.Check0019, []tc{
		{fixture: "kernel-leak-restricted", result: finding.Pass,
			detailContains: "requires CAP_SYSLOG to read"},

		// Written down and turned off, with a reason in the file.
		{fixture: "kernel-leak-dmesg-off", result: finding.Fail, severity: finding.High,
			detailContains: "any local user can run dmesg"},

		// Written nowhere.
		{fixture: "kernel-leak-open", result: finding.Fail, severity: finding.High,
			detailContains: "not set in any sysctl configuration file"},

		// A conflict about the *other* parameter must not silence this check.
		{fixture: "kernel-leak-conflict", result: finding.Pass,
			detailContains: "requires CAP_SYSLOG"},

		{fixture: "kernel-bpf-noconfig", result: finding.NotApplicable,
			detailContains: "No sysctl configuration file exists"},
		{fixture: "kernel-denied", result: finding.Unknown,
			detailContains: "could not be read"},
	})
}

// TestOneAtATimeIsHalfDone is why these are two checks rather than one.
//
// Restricting dmesg while kernel pointers are printed in the clear leaves the
// leak open through /proc/kallsyms; hiding pointers while dmesg is
// world-readable leaves the stack traces and the hardware inventory. A host
// that has done one and not the other should see exactly one finding, and the
// two fixtures below are that host in each direction.
func TestOneAtATimeIsHalfDone(t *testing.T) {
	// kptr at 1, dmesg at 1: -0018 fails, -0019 passes.
	if got := evalFixture(t, checks.Check0018, "kernel-leak-capsyslog"); got.Result != finding.Fail {
		t.Errorf("KERNEL-0018 = %s over kptr_restrict=1: %s", got.Result, got.Detail)
	}
	if got := evalFixture(t, checks.Check0019, "kernel-leak-capsyslog"); got.Result != finding.Pass {
		t.Errorf("KERNEL-0019 responded to kptr_restrict: %s", got.Detail)
	}

	// kptr at 2, dmesg at 0: the mirror image.
	if got := evalFixture(t, checks.Check0018, "kernel-leak-dmesg-off"); got.Result != finding.Pass {
		t.Errorf("KERNEL-0018 responded to dmesg_restrict: %s", got.Detail)
	}
	if got := evalFixture(t, checks.Check0019, "kernel-leak-dmesg-off"); got.Result != finding.Fail {
		t.Errorf("KERNEL-0019 = %s over dmesg_restrict=0: %s", got.Result, got.Detail)
	}
}

// TestTheValueThatLooksSafeIsRatedBelowTheOneNobodySet.
//
// kptr_restrict = 1 is a failure and is not the same failure as an unset
// parameter. One operator hid pointers from ordinary readers and left them
// visible to anything holding CAP_SYSLOG; the other never considered it. Same
// verdict, one severity band apart, and the finding says which is which — the
// precedent is CONTAINERS-0006 rating a loopback binding below a routable one.
func TestTheValueThatLooksSafeIsRatedBelowTheOneNobodySet(t *testing.T) {
	written := evalFixture(t, checks.Check0018, "kernel-leak-capsyslog")
	unset := evalFixture(t, checks.Check0018, "kernel-leak-open")

	if written.Result != finding.Fail || unset.Result != finding.Fail {
		t.Fatalf("expected both to fail: %s / %s", written.Result, unset.Result)
	}
	if written.Severity != finding.Medium {
		t.Errorf("kptr_restrict=1 rated %s, want MEDIUM", written.Severity)
	}
	if unset.Severity != finding.High {
		t.Errorf("an unset kptr_restrict rated %s, want HIGH", unset.Severity)
	}
	if !strings.Contains(written.Detail, "Set it to 2") {
		t.Errorf("the weaker value is not told what to do: %s", written.Detail)
	}
	// And the vendor file that set it is cited, because that is the file the
	// operator has to out-rank.
	if len(written.Evidence) == 0 || !strings.Contains(written.Evidence[0].Source, "/usr/lib/sysctl.d/") {
		t.Errorf("the vendor file that set 1 is not cited: %+v", written.Evidence)
	}
}

// TestAConflictAboutOneParameterDoesNotSilenceTheOther.
//
// persistenceGate is given only the keys its check reads, so a disagreement
// about kptr_restrict makes KERNEL-0018 UNKNOWN and leaves KERNEL-0019 free to
// answer. A gate that checked every configured key would have turned one
// unclear parameter into silence across the whole module.
func TestAConflictAboutOneParameterDoesNotSilenceTheOther(t *testing.T) {
	kptr := evalFixture(t, checks.Check0018, "kernel-leak-conflict")
	if kptr.Result != finding.Unknown {
		t.Errorf("KERNEL-0018 = %s over a conflicting kptr_restrict: %s", kptr.Result, kptr.Detail)
	}
	dmesg := evalFixture(t, checks.Check0019, "kernel-leak-conflict")
	if dmesg.Result != finding.Pass {
		t.Errorf("KERNEL-0019 = %s; the conflict is about a parameter it does not read: %s", dmesg.Result, dmesg.Detail)
	}
}

// TestThePersistenceChecksShareTheirGate. The ordering in persistenceGate is a
// correctness property — a kernel that does not implement a parameter is
// excused before an absent configuration is called a failure, and an unreadable
// file stops the check before an absence is concluded — and three checks now
// depend on it. This asserts the consequence rather than the sharing.
func TestThePersistenceChecksShareTheirGate(t *testing.T) {
	persistence := []catalog.Check{checks.Check0017, checks.Check0018, checks.Check0019}

	for _, check := range persistence {
		// No configuration files at all: nothing to have an opinion about.
		if got := evalFixture(t, check, "kernel-bpf-noconfig"); got.Result != finding.NotApplicable {
			t.Errorf("%s = %s on a host with no sysctl configuration: %s", check.ID, got.Result, got.Detail)
		}
		// A file that exists and could not be read may hold the setting, so no
		// absence may be concluded.
		got := evalFixture(t, check, "kernel-denied")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s with an unreadable configuration file: %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason == "" {
			t.Errorf("%s returned UNKNOWN without a reason", check.ID)
		}
		// Every verdict names the check that reads the running value, because
		// the two disagree on the same host all the time and a reader who does
		// not know which they are holding will act on the wrong one.
		for _, fixture := range []string{"kernel-leak-restricted", "kernel-leak-open"} {
			v := evalFixture(t, check, fixture)
			if !strings.Contains(v.Detail, "after the next reboot") {
				t.Errorf("%s over %s does not say it read the files: %s", check.ID, fixture, v.Detail)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// KERNEL-0020 and -0021
// ---------------------------------------------------------------------------

func TestKernel0020PtraceScopePersisted(t *testing.T) {
	run(t, checks.Check0020, []tc{
		{fixture: "kernel-trace-restricted", result: finding.Pass,
			detailContains: "only its own descendants"},

		// Anything above 0 passes, and the verdict says what that level
		// restricts rather than repeating the number.
		{fixture: "kernel-trace-adminonly", result: finding.Pass,
			detailContains: "CAP_SYS_PTRACE"},

		// Written down and wide open.
		{fixture: "kernel-trace-open", result: finding.Fail, severity: finding.High,
			detailContains: "classic behaviour"},

		// Written nowhere, and hardened at runtime — the trap.
		{fixture: "kernel-trace-unset", result: finding.Fail, severity: finding.High,
			detailContains: "will not be after the next reboot"},

		{fixture: "kernel-bpf-noconfig", result: finding.NotApplicable,
			detailContains: "No sysctl configuration file exists"},
		{fixture: "kernel-denied", result: finding.Unknown,
			detailContains: "could not be read"},
	})
}

func TestKernel0021SysrqPersisted(t *testing.T) {
	run(t, checks.Check0021, []tc{
		{fixture: "kernel-trace-restricted", result: finding.Pass,
			detailContains: "SysRq key is disabled"},

		// 1 is every function, and the verdict says so rather than printing 1.
		{fixture: "kernel-trace-open", result: finding.Fail, severity: finding.Medium,
			detailContains: "every SysRq function"},

		// A narrow, deliberate mask: still a failure, one band down.
		{fixture: "kernel-sysrq-narrow", result: finding.Fail, severity: finding.Low,
			detailContains: "syncing all filesystems"},

		// The same shape of mask with the dumps added stays at Medium.
		{fixture: "kernel-sysrq-dumps", result: finding.Fail, severity: finding.Medium,
			detailContains: "debugging dumps"},

		{fixture: "kernel-trace-unset", result: finding.Fail, severity: finding.Medium,
			detailContains: "not set in any sysctl configuration file"},

		{fixture: "kernel-bpf-noconfig", result: finding.NotApplicable,
			detailContains: "No sysctl configuration file exists"},
		{fixture: "kernel-denied", result: finding.Unknown,
			detailContains: "could not be read"},
	})
}

// TestTheSysrqMaskIsDecodedRatherThanPrinted.
//
// "kernel.sysrq is 176" is a number an operator has to go and look up.
// "176 enables syncing all filesystems, remounting all filesystems read-only,
// immediate reboot or power off" is a finding they can act on — and the
// decoding is what makes the severity tier possible at all, since it turns on
// which bits are set rather than on how large the number is.
func TestTheSysrqMaskIsDecodedRatherThanPrinted(t *testing.T) {
	narrow := evalFixture(t, checks.Check0021, "kernel-sysrq-narrow")
	dumps := evalFixture(t, checks.Check0021, "kernel-sysrq-dumps")

	for _, want := range []string{"syncing all filesystems", "remounting all filesystems read-only"} {
		if !strings.Contains(narrow.Detail, want) {
			t.Errorf("48 is not decoded: %s", narrow.Detail)
		}
		if !strings.Contains(dumps.Detail, want) {
			t.Errorf("184 is not decoded: %s", dumps.Detail)
		}
	}
	// The bit that separates them.
	if strings.Contains(narrow.Detail, "debugging dumps") {
		t.Errorf("48 was described as enabling the dumps: %s", narrow.Detail)
	}
	if !strings.Contains(dumps.Detail, "debugging dumps") {
		t.Errorf("184 does not mention the dumps: %s", dumps.Detail)
	}
	// And the consequence, which is the whole reason for decoding.
	if narrow.Severity != finding.Low || dumps.Severity != finding.Medium {
		t.Errorf("the tier does not follow the bits: 48=%s 184=%s", narrow.Severity, dumps.Severity)
	}
	if !strings.Contains(dumps.Detail, "defeat address-space randomisation") {
		t.Errorf("the dangerous bit is not explained: %s", dumps.Detail)
	}
}

// TestANarrowMaskIsNotTheSameFindingAsTheDefault. 48 is a host that considered
// SysRq and kept the two functions its operations team uses; 1 is a host that
// did not consider it. Both fail, one band apart, and the finding says which.
func TestANarrowMaskIsNotTheSameFindingAsTheDefault(t *testing.T) {
	narrow := evalFixture(t, checks.Check0021, "kernel-sysrq-narrow")
	everything := evalFixture(t, checks.Check0021, "kernel-trace-open")

	if narrow.Result != finding.Fail || everything.Result != finding.Fail {
		t.Fatalf("expected both to fail: %s / %s", narrow.Result, everything.Result)
	}
	if narrow.Severity != finding.Low {
		t.Errorf("a narrow mask rated %s, want LOW", narrow.Severity)
	}
	if everything.Severity != finding.Medium {
		t.Errorf("every function enabled rated %s, want MEDIUM", everything.Severity)
	}
	if !strings.Contains(narrow.Detail, "deliberate and narrow choice") {
		t.Errorf("the narrow mask is not credited: %s", narrow.Detail)
	}
}

// TestTheSysrqCheckNamesItsBlindSpot. Nothing in this catalog reads the running
// kernel.sysrq, and the kernel command line can enable SysRq in a way no sysctl
// file records. A caveat pointing at a runtime check that does not exist would
// be worse than no caveat.
func TestTheSysrqCheckNamesItsBlindSpot(t *testing.T) {
	got := evalFixture(t, checks.Check0021, "kernel-trace-restricted")

	if !strings.Contains(got.Detail, "sysrq_always_enabled") {
		t.Errorf("the bootloader override is not named: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "No check in this catalog reads the running value") {
		t.Errorf("the verdict implies a runtime counterpart that does not exist: %s", got.Detail)
	}
}

// TestKernel0004IsRatedWithTheLeakItEnables is the re-rating, asserted rather
// than left to a changelog entry.
//
// An open ring buffer on a host with kptr_restrict at 0 is a KASLR defeat that
// needs no privilege and leaves no trace. Rating that Low while KERNEL-0019
// rates the same parameter's *persistence* High said a file matters more than
// the kernel, which is backwards.
func TestKernel0004IsRatedWithTheLeakItEnables(t *testing.T) {
	if checks.Check0004.BaseSeverity != finding.High {
		t.Errorf("KERNEL-0004 is %s, want HIGH", checks.Check0004.BaseSeverity)
	}
	// A persistence check may outrank the runtime check it persists by at most
	// one band — the "scheduled to fall down" argument — and these two now read
	// the same parameter at the same severity.
	if checks.Check0019.BaseSeverity != checks.Check0004.BaseSeverity {
		t.Errorf("KERNEL-0004 (%s) and KERNEL-0019 (%s) rate the same parameter differently",
			checks.Check0004.BaseSeverity, checks.Check0019.BaseSeverity)
	}
}

// TestTheSysrqMaskIsParsedTheWayTheKernelParsesIt.
//
// The kernel's proc_get_long uses simple_strtoul with base 0, and systemd ships
// `kernel.sysrq = 0x01b6` in /usr/lib/sysctl.d/50-default.conf. A decimal-only
// parse reports that real and common value as "not a number" and resolves the
// check to UNKNOWN on a host that has, in fact, configured it.
//
// This was found by running the finished check against a live host rather than
// by reading the fixture corpus, which is the argument for doing that on every
// work package.
func TestTheSysrqMaskIsParsedTheWayTheKernelParsesIt(t *testing.T) {
	got := evalFixture(t, checks.Check0021, "kernel-sysrq-hex")
	if got.Result != finding.Pass {
		t.Fatalf("0x0 = %s, want PASS: the kernel reads it as zero\n  %s", got.Result, got.Detail)
	}

	// And the decoding of a non-zero hex mask, through a hand-built fact so the
	// assertion names the value rather than depending on a fixture's contents.
	sc := fact.Sysctl{
		Running:    map[string]fact.SysctlRunning{},
		Configured: map[string][]fact.SysctlSetting{},
		Digests:    map[string]string{},
		Files:      []string{"/usr/lib/sysctl.d/50-default.conf"},
	}
	sc.Running["kernel.sysrq"] = fact.SysctlRunning{
		Key: "kernel.sysrq", State: fact.SysctlObserved, Value: "438",
	}
	sc.Configured["kernel.sysrq"] = []fact.SysctlSetting{{
		Key: "kernel.sysrq", Value: "0x01b6",
		File: "/usr/lib/sysctl.d/50-default.conf", Line: 19,
	}}
	fs := fact.NewSet()
	fs.Put(sc)

	out := catalog.MustNew(checks.Check0021).Evaluate(fs)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Result != finding.Fail {
		t.Fatalf("0x01b6 = %s, want FAIL: %s", out[0].Result, out[0].Detail)
	}
	// 0x1b6 is 438 = 2+4+16+32+128+256, which includes the log-level control
	// and the keyboard control — so Medium, not the Low a benign mask gets.
	if out[0].Severity != finding.Medium {
		t.Errorf("0x01b6 rated %s, want MEDIUM: it enables log-level and keyboard control", out[0].Severity)
	}
	if !strings.Contains(out[0].Detail, "changing the console log level") {
		t.Errorf("the hex mask was not decoded: %s", out[0].Detail)
	}
	if strings.Contains(out[0].Detail, "not a number") {
		t.Errorf("a hex value was reported as unparseable: %s", out[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// deterministic conflict resolution, and KERNEL-0022
// ---------------------------------------------------------------------------

// TestSameDirectoryDisagreementIsResolvedNotReported.
//
// The two tools that apply these files disagree about one thing only: how to
// order *directories* against each other. Within a directory both sort by
// filename, so two files there that disagree have a determinable answer — the
// later filename — and reporting UNKNOWN was over-caution that cost a real
// verdict on a real host.
//
// The fixture is the shape found on a live Ubuntu 24.04 workstation, where
// /usr/lib/sysctl.d/50-default.conf sets kernel.sysrq = 0x01b6 and
// 55-magic-sysrq.conf sets 176. The running kernel on that host reports 176.
func TestSameDirectoryDisagreementIsResolvedNotReported(t *testing.T) {
	sc := sysctlFromFixture(t, "kernel-samedir-order")

	if sc.ConfiguredConflict("kernel.sysrq") {
		t.Errorf("two files in one directory reported as conflicting: %+v", sc.Configured["kernel.sysrq"])
	}
	set, found := sc.EffectiveConfigured("kernel.sysrq")
	if !found || set.Value != "176" {
		t.Errorf("effective value = %q, want 176 — the later filename wins", set.Value)
	}

	// And the verdict that follows from it, which is the point of the change.
	got := evalFixture(t, checks.Check0021, "kernel-samedir-order")
	if got.Result != finding.Fail {
		t.Fatalf("= %s, want FAIL: the answer is determinable\n  %s", got.Result, got.Detail)
	}
	if got.Severity != finding.Low {
		t.Errorf("severity = %s, want LOW: 176 is sync, remount-read-only and reboot", got.Severity)
	}
	if !strings.Contains(got.Detail, "55-magic-sysrq.conf") {
		t.Errorf("the verdict does not cite the file that wins: %s", got.Detail)
	}
}

// TestCrossDirectoryDisagreementIsStillUnknown is the other half, and the pair
// is the whole distinction: the same disagreement, the same two values, and
// only the directory differs.
//
// procps walks the directories in its own documented order; systemd-sysctl
// merges them and sorts by filename across all of them. Here those give
// different answers, so what the host does after a reboot depends on which tool
// applied the files, and guessing would be a confident claim about exactly that.
func TestCrossDirectoryDisagreementIsStillUnknown(t *testing.T) {
	sc := sysctlFromFixture(t, "kernel-crossdir-conflict")

	if !sc.ConfiguredConflict("kernel.sysrq") {
		t.Errorf("a cross-directory disagreement was resolved: %+v", sc.Configured["kernel.sysrq"])
	}

	got := evalFixture(t, checks.Check0021, "kernel-crossdir-conflict")
	if got.Result != finding.Unknown {
		t.Fatalf("= %s, want UNKNOWN: %s", got.Result, got.Detail)
	}
	for _, file := range []string{"/usr/lib/sysctl.d/50-default.conf", "/run/sysctl.d/50-cloud.conf"} {
		if !strings.Contains(got.Detail, file) {
			t.Errorf("%s is not named: %s", file, got.Detail)
		}
	}
}

// TestOneDirectoryReachedByTwoPathsIsNotAConflict.
//
// On a usr-merged host /lib is a symlink to /usr/lib, so the same files are
// reached by two paths. The collector now dedupes the search directories by
// inode, and the per-directory reading disposes of any that a recorded bundle
// still carries — each path ends on the same value, so the two agree. Both
// halves matter: the first keeps the fact honest about what was read, the
// second keeps old bundles re-evaluable.
func TestOneDirectoryReachedByTwoPathsIsNotAConflict(t *testing.T) {
	sc := fact.Sysctl{Configured: map[string][]fact.SysctlSetting{}}
	sc.Configured["kernel.sysrq"] = []fact.SysctlSetting{
		{Key: "kernel.sysrq", Value: "0x01b6", File: "/usr/lib/sysctl.d/50-default.conf", Line: 19},
		{Key: "kernel.sysrq", Value: "176", File: "/usr/lib/sysctl.d/55-magic-sysrq.conf", Line: 26},
		{Key: "kernel.sysrq", Value: "0x01b6", File: "/lib/sysctl.d/50-default.conf", Line: 19},
		{Key: "kernel.sysrq", Value: "176", File: "/lib/sysctl.d/55-magic-sysrq.conf", Line: 26},
	}
	if sc.ConfiguredConflict("kernel.sysrq") {
		t.Error("a usr-merge duplicate was reported as a conflict")
	}
	if set, _ := sc.EffectiveConfigured("kernel.sysrq"); set.Value != "176" {
		t.Errorf("effective value = %q, want 176", set.Value)
	}
}

// TestEtcSysctlConfIsItsOwnDirectory.
//
// /etc/sysctl.conf is not a drop-in. procps applies it after every directory
// and systemd treats it as one more file to merge, so a value there and a value
// in /etc/sysctl.d are exactly the cross-directory case — and lumping them
// together by their shared /etc prefix would resolve a disagreement that is not
// determinable.
func TestEtcSysctlConfIsItsOwnDirectory(t *testing.T) {
	sc := fact.Sysctl{Configured: map[string][]fact.SysctlSetting{}}
	sc.Configured["kernel.sysrq"] = []fact.SysctlSetting{
		{Key: "kernel.sysrq", Value: "1", File: "/etc/sysctl.d/60-local.conf", Line: 1},
		{Key: "kernel.sysrq", Value: "0", File: "/etc/sysctl.conf", Line: 3},
	}
	if !sc.ConfiguredConflict("kernel.sysrq") {
		t.Error("/etc/sysctl.conf was treated as a drop-in in /etc/sysctl.d")
	}
}

func TestKernel0022PerfEventParanoid(t *testing.T) {
	run(t, checks.Check0022, []tc{
		{fixture: "kernel-perf-restricted", result: finding.Pass,
			detailContains: "may not profile the kernel"},

		// 3 passes and is told apart from 2.
		{fixture: "kernel-perf-strict", result: finding.Pass,
			detailContains: "stricter than upstream"},

		// Written below the bar.
		{fixture: "kernel-perf-open", result: finding.Fail, severity: finding.Medium,
			detailContains: "KASLR oracle"},

		// Written nowhere. A default is not a decision.
		{fixture: "kernel-trace-unset", result: finding.Fail, severity: finding.Medium,
			detailContains: "a default is not a decision"},

		{fixture: "kernel-bpf-noconfig", result: finding.NotApplicable,
			detailContains: "No sysctl configuration file exists"},
		{fixture: "kernel-denied", result: finding.Unknown,
			detailContains: "could not be read"},
	})
}

// TestTheTwoAcceptedPerfLevelsAreToldApart. 2 is upstream's default and 3 is a
// Debian-family patch that does not exist elsewhere — which is why the bar is 2
// rather than 3, and why a host running 3 is told it chose something rather
// than inherited it.
func TestTheTwoAcceptedPerfLevelsAreToldApart(t *testing.T) {
	two := evalFixture(t, checks.Check0022, "kernel-perf-restricted")
	three := evalFixture(t, checks.Check0022, "kernel-perf-strict")

	if two.Result != finding.Pass || three.Result != finding.Pass {
		t.Fatalf("expected both to pass: %s / %s", two.Result, three.Result)
	}
	if !strings.Contains(two.Detail, "3 is stricter") {
		t.Errorf("a host at 2 is not told a stricter value exists: %s", two.Detail)
	}
	if !strings.Contains(three.Detail, "deliberate choice rather than an inherited one") {
		t.Errorf("a host at 3 is not credited: %s", three.Detail)
	}
}

// sysctlFromFixture collects the fact itself, for the assertions that are about
// the reading rather than about a verdict.
func sysctlFromFixture(t *testing.T, name string) fact.Sysctl {
	t.Helper()
	sc, _, ok := fact.Get[fact.Sysctl](collectFixture(t, name), fact.SysctlID)
	if !ok {
		t.Fatalf("kernel.sysctl missing from %s", name)
	}
	return sc
}
