package auth

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// MinPasswordLength is the minimum acceptable pwquality minlen.
//
// Fourteen is CIS's and DISA's number. NIST SP 800-63B asks for eight and
// argues against composition rules entirely, on the grounds that they push
// users toward predictable substitutions. The two are not reconcilable and
// this check takes the stricter one, because the failing direction differs:
// a host with a fourteen-character minimum satisfies both, and one with eight
// satisfies only NIST. The conflict is stated in the finding rather than
// hidden behind the number.
const MinPasswordLength = 14

// creditKeys are pwquality's per-class requirements. A negative value means
// "require at least this many characters of the class"; a positive one means
// "give at most this much credit toward minlen", which is the weaker reading
// and the default.
var creditKeys = []string{"dcredit", "ucredit", "lcredit", "ocredit"}

// Check0002 tests that the password quality parameters are actually strict.
var Check0002 = catalog.Check{
	ID:     "AUTH-0002",
	Module: "AUTH",
	Title:  "Password quality parameters require length and character variety",
	Description: `A quality module with default parameters enforces very little.
pam_pwquality's shipped configuration is a file of comments: every setting is
commented out, so the effective values come from libpwquality's compiled-in
defaults, and a host can have the module correctly installed, correctly
enforcing, and still accept an eight-character password.

Two properties are checked. **Length** is the one that matters most, because it
is the only parameter an offline cracking attack cares about — character
variety adds a few bits and each additional character multiplies the search
space. **Variety** is checked as a secondary constraint because length alone
permits a fourteen-character password that is a single dictionary word repeated.

pwquality expresses variety two ways and they are easy to confuse. 'minclass'
names how many of the four character classes must appear. The four credit
settings — dcredit, ucredit, lcredit, ocredit — are *credits* by default: a
positive value means characters of that class count extra toward minlen, which
is a discount rather than a requirement. Only a **negative** value means "at
least this many of this class". A configuration setting 'dcredit = 1' has
required nothing and looks like it has required a digit.

**Where the value comes from matters.** The module reads
/etc/security/pwquality.conf first and arguments on the PAM line override it.
This check resolves both in that order. Where a parameter is set in neither, it
reports UNKNOWN rather than assuming: libpwquality's built-in default is a
compile-time property that has changed between releases, is not readable from
the filesystem, and guessing the strict value would be as much a guess as
guessing the weak one.`,

	BaseSeverity: finding.Medium,
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

		lines := fact.Find(stacks, fact.PAMPassword, QualityModules...)
		if len(lines) == 0 {
			// AUTH-0001 reports the absence. Failing twice for one missing
			// thing buries the finding that matters under one that repeats it.
			return unknownIfIncomplete(stacks, catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"No password quality module is in the password stack (%s), so its parameters have no subject. AUTH-0001 reports the absence itself.",
					stackNames(stacks)),
			})
		}

		minlen, minlenFrom, haveMinlen := effectiveInt(lines, p.PwQuality, "minlen")
		variety, varietyFrom, haveVariety := varietyConstraint(lines, p.PwQuality)

		ev := linesEvidence(p, lines)
		if s, ok := p.PwQuality.Get("minlen"); ok {
			ev = append(ev, settingEvidence(p, s))
		}

		// Positive: we read a value and it is too weak. Nothing unread can
		// unmake that.
		var faults []string
		if haveMinlen && minlen < MinPasswordLength {
			faults = append(faults, fmt.Sprintf(
				"minlen is %d (%s), below the %d that CIS and DISA require",
				minlen, minlenFrom, MinPasswordLength))
		}
		if haveVariety && variety == "" {
			faults = append(faults, "the character-class settings require nothing: the credit values are positive, which grants a discount toward minlen rather than demanding a character of that class, and minclass is not set")
		}
		if len(faults) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: lines[0].Module,
				Detail: fmt.Sprintf(
					"The password quality parameters do not meet the minimum: %s. NIST SP 800-63B would accept a length of 8 and argues against composition rules altogether; CIS and DISA require 14 with character variety. This check takes the stricter reading because a host that satisfies it satisfies both.",
					strings.Join(faults, "; ")),
				Evidence: ev,
			}
		}

		// A parameter set nowhere we could read is not a parameter we may
		// assume. libpwquality's compiled-in defaults have changed between
		// releases and are not on the filesystem.
		var missing []string
		if !haveMinlen {
			missing = append(missing, "minlen")
		}
		if !haveVariety {
			missing = append(missing, "minclass and the four credit settings")
		}
		if len(missing) > 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Subject:       lines[0].Module,
				Detail: fmt.Sprintf(
					"%s is enforced, but %s %s set neither in /etc/security/pwquality.conf nor as an argument on the PAM line. The effective value then comes from libpwquality's compiled-in default, which is a property of the package build rather than of this host, is not readable from the filesystem, and has changed between releases. Setting it explicitly is worth doing for that reason alone.",
					lines[0].Module, strings.Join(missing, " and "),
					plural(len(missing), "is", "are")),
				Evidence: ev,
			}
		}

		return unknownIfIncomplete(stacks, catalog.Outcome{
			Result:  finding.Pass,
			Subject: lines[0].Module,
			Detail: fmt.Sprintf(
				"Password quality requires at least %d characters (minlen from %s) and %s (from %s).",
				minlen, minlenFrom, variety, varietyFrom),
			Evidence: ev,
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Set minlen and a character-variety requirement explicitly in /etc/security/pwquality.conf.",
		Effort:  "LOW",
		Steps: []string{
			"Set them in /etc/security/pwquality.conf rather than as module arguments. The file survives a stack regeneration by authselect or pam-auth-update, is identical across every host you manage, and is where the next person will look.",
			"Set the length: 'minlen = 14'. This is the parameter that matters to an offline cracking attack — every additional character multiplies the search space, while character variety adds a few bits once.",
			"Require variety with minclass rather than with credits: 'minclass = 4'. It says plainly that all four character classes must appear.",
			"If you use the credit settings instead, make them **negative**: 'dcredit = -1' requires at least one digit. A positive value is a discount toward minlen, not a requirement, and 'dcredit = 1' has demanded nothing while appearing to demand a digit.",
			"Consider 'dictcheck = 1' and 'maxrepeat = 3' as well. Length without them permits a fourteen-character password that is one dictionary word repeated, which is what an attacker's wordlist rules generate first.",
			"Verify from an unprivileged account: 'passwd' and offer a thirteen-character password. It must be refused, with pwquality's own message naming the reason.",
		},
		Commands: []string{
			"grep -Ev '^\\s*(#|$)' /etc/security/pwquality.conf",
			"grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/*",
			"pwscore <<< 'somecandidatepassword'",
		},
		Caution: "Raising the minimum does not affect existing passwords — it applies at the next change — so a host can pass this check and still be full of eight-character passwords set last year. Pair the change with a forced rotation only if the accounts are ones people actually use; forcing it on service accounts breaks whatever holds their credential.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
	},

	References: []finding.Reference{
		{Title: "pwquality.conf(5)", URL: "https://man7.org/linux/man-pages/man5/pwquality.conf.5.html"},
		{Title: "NIST SP 800-63B §5.1.1 — memorized secrets", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"},
	},
}

// varietyConstraint resolves the character-class requirement, returning a
// human phrase for it.
//
// The empty string with ok==true means the settings exist and require nothing,
// which is the trap this check is mostly about: positive credit values look
// like requirements and are discounts.
func varietyConstraint(lines []fact.PAMLine, file fact.SettingsFile) (string, string, bool) {
	if n, from, ok := effectiveInt(lines, file, "minclass"); ok {
		if n >= 4 {
			return "all four character classes (minclass)", from, true
		}
		if n > 0 {
			return "", from, true
		}
	}

	var required []string
	var from string
	var any bool
	for _, key := range creditKeys {
		n, where, ok := effectiveInt(lines, file, key)
		if !ok {
			continue
		}
		any = true
		if from == "" {
			from = where
		}
		if n < 0 {
			required = append(required, fmt.Sprintf("%d %s", -n, creditName(key)))
		}
	}
	if !any {
		return "", "", false
	}
	if len(required) == 0 {
		return "", from, true
	}
	return "at least " + strings.Join(required, ", "), from, true
}

// creditName renders a credit key as the class it governs.
func creditName(key string) string {
	switch key {
	case "dcredit":
		return "digit(s)"
	case "ucredit":
		return "uppercase letter(s)"
	case "lcredit":
		return "lowercase letter(s)"
	default:
		return "other character(s)"
	}
}
