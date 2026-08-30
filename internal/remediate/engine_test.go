package remediate_test

import (
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/remediate"
)

// TestOnlyFailingUnsuppressedFindingsAreRemediated.
//
// **The safety property of the whole engine.** Everything this package will
// eventually do happens as root on somebody's host, so what it declines to
// touch matters more than what it fixes.
//
// Each case is a result the naive filter — "anything that is not a PASS" —
// gets wrong, and each is wrong in its own way. An UNKNOWN is the dangerous
// one: the check could not read the parameter, so a fix would be writing
// configuration on the strength of a guess.
func TestOnlyFailingUnsuppressedFindingsAreRemediated(t *testing.T) {
	fix := "KERNEL-0004"

	for _, c := range []struct {
		name    string
		mutate  func(*finding.Finding)
		wantFix bool
	}{
		{"a failure", func(*finding.Finding) {}, true},
		{"a pass", func(f *finding.Finding) { f.Result = finding.Pass }, false},
		{"an unknown", func(f *finding.Finding) {
			f.Result = finding.Unknown
			f.UnknownReason = finding.ReasonPermission
		}, false},
		{"not applicable", func(f *finding.Finding) { f.Result = finding.NotApplicable }, false},
		{"skipped by a profile", func(f *finding.Finding) { f.Result = finding.Skipped }, false},
		{"suppressed by an operator", func(f *finding.Finding) {
			f.Suppression = &finding.Suppression{
				Justification:  "accepted; this host's console is physically restricted",
				OriginalResult: finding.Fail,
			}
			f.Result = finding.Skipped
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := failures(fix)[0]
			c.mutate(&f)

			plan := remediate.Generate([]finding.Finding{f}, remediate.Options{})
			if got := !plan.Empty(); got != c.wantFix {
				t.Errorf("a %s produced %d action(s), want fix = %v", c.name, len(plan.Actions), c.wantFix)
			}
		})
	}
}

// TestASuppressedFindingIsNotEvenListedAsUnfixable.
//
// An accepted risk is not an outstanding one. It must not appear in the plan at
// all — not as an action, and not in the list of things no fix covers, which an
// operator reads as work still to do.
func TestASuppressedFindingIsNotEvenListedAsUnfixable(t *testing.T) {
	f := failures("KERNEL-0004")[0]
	f.Suppression = &finding.Suppression{Justification: "accepted", OriginalResult: finding.Fail}

	plan := remediate.Generate([]finding.Finding{f}, remediate.Options{})
	if len(plan.Actions) != 0 || len(plan.Unfixable) != 0 {
		t.Errorf("a suppressed finding produced %d action(s) and %d unfixable; want none of either",
			len(plan.Actions), len(plan.Unfixable))
	}
}

// TestAFailureWithNoFixIsCarriedNotDropped.
//
// A plan that listed four of thirty-six failures and said nothing about the
// rest would read as "this is all that is wrong with the host", which is the
// worst thing a security tool can imply.
func TestAFailureWithNoFixIsCarriedNotDropped(t *testing.T) {
	plan := remediate.Generate(failures("KERNEL-0004", "SSHD-0002", "AUTH-0004"), remediate.Options{})

	if len(plan.Actions) != 1 || plan.Actions[0].CheckID != "KERNEL-0004" {
		t.Fatalf("actions = %+v, want only KERNEL-0004", plan.Actions)
	}
	var got []string
	for _, f := range plan.Unfixable {
		got = append(got, f.CheckID)
	}
	if strings.Join(got, ",") != "AUTH-0004,SSHD-0002" {
		t.Errorf("unfixable = %v, want AUTH-0004 and SSHD-0002 in ID order", got)
	}
}

// TestThePlanIsDeterministic.
//
// Two scans of an unchanged host must propose the same script, or an operator
// diffing this week's plan against last week's reads a reordering as a change.
func TestThePlanIsDeterministic(t *testing.T) {
	forward := failures("KERNEL-0030", "KERNEL-0004", "KERNEL-0026", "KERNEL-0016")
	backward := failures("KERNEL-0016", "KERNEL-0026", "KERNEL-0004", "KERNEL-0030")

	a := remediate.Script(remediate.Generate(forward, remediate.Options{}))
	b := remediate.Script(remediate.Generate(backward, remediate.Options{}))
	if a != b {
		t.Errorf("the script depends on the order the findings arrived in:\n%s\n---\n%s", a, b)
	}
	if !strings.Contains(a, "KERNEL-0004") ||
		strings.Index(a, "KERNEL-0004") > strings.Index(a, "KERNEL-0030") {
		t.Errorf("the actions are not in check-ID order:\n%s", a)
	}
}

// TestTheScriptSetsBothTheRunningKernelAndTheFile.
//
// Neither half is sufficient. `sysctl -w` is undone by the next reboot; a line
// in a drop-in does nothing until something applies it. A remediation that did
// one and stopped would leave a host that passes today and fails in three
// months, or one that passes the file check and is exposed right now.
func TestTheScriptSetsBothTheRunningKernelAndTheFile(t *testing.T) {
	script := remediate.Script(remediate.Generate(
		failures("KERNEL-0004", "KERNEL-0016", "KERNEL-0026", "KERNEL-0030"),
		remediate.Options{}))

	for _, want := range []string{
		"sysctl -w kernel.dmesg_restrict=1",
		"sysctl -w net.ipv4.tcp_syncookies=1",
		"sysctl -w net.ipv6.conf.all.accept_ra=0",
		"sysctl -w net.ipv6.conf.default.accept_ra=0",
		"sysctl -w fs.protected_hardlinks=1",
		"plumbline_sysctl_set kernel.dmesg_restrict 1 \"$DROPIN\"",
		"plumbline_sysctl_set fs.protected_hardlinks 1 \"$DROPIN\"",
		remediate.DefaultDropIn,
		"sysctl --system",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script omits %q:\n%s", want, script)
		}
	}
}

// TestTheCommandsAndTheArgvAreTheSameProposal.
//
// The script is what a person reviews; Argv is what a later phase will execute
// through internal/system, which takes an argument vector and never a command
// line. If the two could disagree, the thing reviewed and the thing run would
// be different things — so they are generated together, and this asserts it
// rather than trusting it.
func TestTheCommandsAndTheArgvAreTheSameProposal(t *testing.T) {
	plan := remediate.Generate(failures("KERNEL-0026"), remediate.Options{})
	if len(plan.Actions) != 1 {
		t.Fatalf("actions = %d, want 1", len(plan.Actions))
	}
	a := plan.Actions[0]

	if len(a.Commands) != len(a.Argv) {
		t.Fatalf("%d command(s) and %d argv", len(a.Commands), len(a.Argv))
	}
	for i, argv := range a.Argv {
		if got, want := a.Commands[i], strings.Join(argv, " "); got != want {
			t.Errorf("command %d reads %q and would execute %q", i, got, want)
		}
		if argv[0] != "sysctl" {
			t.Errorf("argv %d does not start with the program: %v", i, argv)
		}
	}
}

// TestAnEmptyPlanProducesNoDropInMachinery.
//
// A host with nothing to fix gets a script that says so by being empty of it —
// no DROPIN, no helper, no `sysctl --system` reloading a file nothing wrote.
func TestAnEmptyPlanProducesNoDropInMachinery(t *testing.T) {
	plan := remediate.Generate(nil, remediate.Options{})
	if !plan.Empty() {
		t.Fatalf("a plan from no findings is not empty: %+v", plan)
	}
	script := remediate.Script(plan)
	for _, unwanted := range []string{"DROPIN", "plumbline_sysctl_set", "sysctl --system"} {
		if strings.Contains(script, unwanted) {
			t.Errorf("an empty plan still emits %q:\n%s", unwanted, script)
		}
	}
}

// TestTheDropInIsPlumblinesOwnFile.
//
// 99- puts it after every distribution and administrator file, so what
// plumbline sets is what the host boots with; the name says who wrote it. The
// failure this guards is a future fix that decided to edit /etc/sysctl.conf,
// where an upgrade or a configuration-management run will revert it.
func TestTheDropInIsPlumblinesOwnFile(t *testing.T) {
	if got, want := remediate.DefaultDropIn, "/etc/sysctl.d/99-plumbline-hardening.conf"; got != want {
		t.Errorf("the drop-in is %q, want %q", got, want)
	}
	plan := remediate.Generate(failures("KERNEL-0004"), remediate.Options{})
	if plan.DropIn != remediate.DefaultDropIn {
		t.Errorf("a plan built with no options writes to %q", plan.DropIn)
	}
}

// TestFixableNamesWhatThisBuildCanRepair.
func TestFixableNamesWhatThisBuildCanRepair(t *testing.T) {
	for _, id := range []string{"KERNEL-0004", "KERNEL-0016", "KERNEL-0026", "KERNEL-0030"} {
		if !remediate.Fixable(id) {
			t.Errorf("%s has no fix", id)
		}
	}
	if remediate.Fixable("SSHD-0002") {
		t.Error("SSHD-0002 reports a fix this phase does not have")
	}
}
