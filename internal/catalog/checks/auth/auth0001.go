package auth

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// QualityModules are the password-quality modules, under both names.
//
// pam_cracklib is the older of the two and is still present on long-lived
// hosts; pam_pwquality replaced it and reads /etc/security/pwquality.conf.
// A check that looked only for the current one would report "no quality
// enforcement" on a host that has it, which is a wrong verdict produced by the
// module having been renamed.
var QualityModules = []string{"pam_pwquality.so", "pam_cracklib.so"}

// Check0001 tests that a password-quality module is enforced when a password
// is set.
var Check0001 = catalog.Check{
	ID:     "AUTH-0001",
	Module: "AUTH",
	Title:  "A password quality module is enforced",
	Description: `Nothing in Linux checks a password by default. Without a
quality module in the password stack, passwd accepts anything a user types,
including their own username, including one character. The absence is silent:
there is no warning at install time, nothing in the logs, and a password policy
document describing fourteen-character minimums can coexist indefinitely with a
host that enforces none of it.

The module has to be **enforcing**, and that is the half most often wrong. PAM's
'optional' control means the result is ignored entirely, the module runs, it
computes that the password is unacceptable, and PAM proceeds to set it anyway.
A stack with 'password optional pam_pwquality.so' reads to a human exactly like
one that works, and produces no output distinguishing itself from one. Only
'required' and 'requisite', or a bracketed control that maps failure to die or
bad, actually refuse the password.

This check reports whether the rule is written with an enforcing control. It
does not simulate the stack around it, so a 'sufficient' rule placed above the
quality module, which would short-circuit before reaching it, is not detected
here; see the check's specification for the full list of what it cannot see.`,

	BaseSeverity: finding.High,
	Tags:         []string{"auth", "pam", "password", "credentials"},
	Requires:     []fact.ID{fact.PAMID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := pamFact(fs)
		if !p.Installed {
			return notInstalled()
		}

		stacks := p.Primary(fact.PAMPassword)
		if len(stacks) == 0 {
			return noStack(p, fact.PAMPassword)
		}

		found := fact.Find(stacks, fact.PAMPassword, QualityModules...)

		// Positive: an enforcing rule is written. No include we failed to
		// follow can unmake one we read.
		for _, l := range found {
			if l.Enforcing() {
				return catalog.Outcome{
					Result:   finding.Pass,
					Subject:  l.Module,
					Detail:   fmt.Sprintf("%s is in the password stack with control '%s', so a password that fails its rules is refused. Which rules those are is AUTH-0002's question.", l.Module, l.Control),
					Evidence: linesEvidence(p, found),
				}
			}
		}

		if len(found) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: found[0].Module,
				Detail: fmt.Sprintf(
					"%s is present in the password stack but not enforcing: its control is '%s'. PAM ignores the result of an optional module entirely — it runs, decides the password is unacceptable, and the password is set anyway. The rule reads exactly like a working one and there is no output that distinguishes it.",
					found[0].Module, found[0].Control),
				Evidence: linesEvidence(p, found),
			}
		}

		// Drawn from absence, so it is only as good as the includes behind it.
		return unknownIfIncomplete(stacks, catalog.Outcome{
			Result:  finding.Fail,
			Subject: "pam_pwquality.so",
			Detail: fmt.Sprintf(
				"No password quality module is in the password stack (%s). Nothing checks a password on this host: passwd accepts any string a user offers, including their own username and including a single character. There is no warning and nothing in the logs — the only way to observe it is to look here.",
				stackNames(stacks)),
			Evidence: stackEvidence(stacks),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Add pam_pwquality.so to the password stack with an enforcing control.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Install the module if it is missing: 'apt install libpam-pwquality' or 'dnf install libpwquality'. On Red Hat it is normally present already.",
			"Do not hand-edit the shared stack on a system that generates it. Red Hat's system-auth is managed by authselect, 'authselect enable-feature with-pwquality', and a hand edit is overwritten at the next authselect apply, silently, possibly months later. Debian's common-password is managed by pam-auth-update.",
			"Where you do edit it directly, place the rule *before* pam_unix.so in the password stack, with control 'requisite': 'password requisite pam_pwquality.so retry=3'. After pam_unix.so it never runs, because pam_unix has already set the password.",
			"Set the parameters in /etc/security/pwquality.conf rather than as module arguments. The file is the same on every host you manage, survives a stack regeneration, and is what AUTH-0002 reads.",
			"Test before logging out, from a second session: 'passwd' as an unprivileged test account and offer a one-character password. It must be refused. A rule that is present and not enforcing accepts it, which is precisely the failure this check is about.",
		},
		Commands: []string{
			"grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/*",
			"authselect current",
			"passwd testuser",
		},
		Caution: "Editing a PAM stack wrongly can lock every account out of the host, including root, and the failure appears at the next authentication rather than when the file is saved. Keep a root session open while you work, test with a second login before closing it, and on a host you cannot physically reach take a copy of the file first.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
	},

	References: []finding.Reference{
		{Title: "pam_pwquality(8)", URL: "https://man7.org/linux/man-pages/man8/pam_pwquality.8.html"},
		{Title: "pam.conf(5), control flags", URL: "https://man7.org/linux/man-pages/man5/pam.conf.5.html"},
	},
}
