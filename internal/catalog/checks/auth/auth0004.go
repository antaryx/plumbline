package auth

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// nullokArgs are the pam_unix arguments that accept an empty password.
//
// `nullok_secure` is Debian's variant: it accepts an empty password, but only
// from a terminal listed in /etc/securetty. That is narrower than `nullok` and
// it is still an account with no password, so it is reported — with the
// distinction named, because the remediation urgency differs.
var nullokArgs = []string{"nullok", "nullok_secure"}

// Check0004 tests that PAM does not accept an empty password.
var Check0004 = catalog.Check{
	ID:     "AUTH-0004",
	Module: "AUTH",
	Title:  "PAM does not accept an empty password",
	Description: `pam_unix.so's 'nullok' argument means: if the account's
password field in /etc/shadow is empty, authenticate anyway. Without it, an
empty field is a refusal, the account simply cannot log in with a password.
With it, the empty field becomes a valid credential that anybody can supply.

The two halves of this have to be read together, and each is harmless-looking
alone. USERS-0003 reports accounts whose password field is empty. This check
reports whether PAM would accept one. Neither is a login on its own; together
they are an unauthenticated shell, and they are usually introduced by different
people at different times, an installer that ships nullok in the default
stack, and an account created by a script that never set a password.

It is worth checking even where no account currently has an empty field. The
PAM configuration is the durable half: the next account created without a
password is immediately usable by anyone who knows its name, with nothing to
notice at the moment it happens.

**This is about empty passwords, not about reversible storage.** Nothing in PAM
stores a password reversibly, pam_unix hashes with crypt(3) and the algorithm
is AUTH-0005's question. The two are sometimes conflated because Windows
policy names a "store passwords using reversible encryption" setting; the Linux
equivalent of that risk is a weak hash, not this.`,

	BaseSeverity: finding.High,
	Tags:         []string{"auth", "pam", "credentials", "empty-password"},
	Requires:     []fact.ID{fact.PAMID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := pamFact(fs)
		if !p.Installed {
			return notInstalled()
		}

		// Every stack is searched, not only the primary one. nullok on
		// /etc/pam.d/login is as much an empty-password login as nullok in
		// system-auth, and a service that has diverged from the shared stack
		// has diverged exactly here.
		stacks := readable(p)
		if len(stacks) == 0 {
			return noStack(p, fact.PAMAuth)
		}

		var offenders []fact.PAMLine
		for _, l := range fact.Find(stacks, fact.PAMAuth, "pam_unix.so") {
			for _, arg := range nullokArgs {
				if l.HasArg(arg) {
					offenders = append(offenders, l)
					break
				}
			}
		}

		// Positive: we read the argument. Nothing unread can unmake it.
		if len(offenders) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "pam_unix.so",
				Detail: fmt.Sprintf(
					"pam_unix.so accepts an empty password in %d rule%s (%s). An account whose password field in /etc/shadow is empty can then be logged into by anyone who knows its name, with no credential at all. USERS-0003 reports whether any account is currently in that state; this is the half that decides what happens when one is.%s",
					len(offenders), plural(len(offenders), "", "s"),
					offenderFiles(offenders), secureNote(offenders)),
				Evidence: linesEvidence(p, offenders),
			}
		}

		// Drawn from absence, so it is only as good as the includes behind it.
		return unknownIfIncomplete(stacks, catalog.Outcome{
			Result:  finding.Pass,
			Detail:  "No pam_unix.so rule accepts an empty password: nullok appears in none of the auth stacks read. An account whose password field is empty is refused rather than admitted.",
			Subject: "pam_unix.so",
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Remove nullok from every pam_unix.so auth rule, and check for accounts that were relying on it.",
		Effort:  "LOW",
		Steps: []string{
			"Look for the accounts first: 'awk -F: '($2 == \"\") {print $1}' /etc/shadow' lists every account with an empty password field. Removing nullok stops each of them authenticating, which is the intended outcome but should not be a surprise.",
			"Decide what each of those accounts is for. A service account that never logs in should be locked outright ('passwd -l', or a '!' in the field); a human account should be given a password.",
			"Remove the nullok argument from the pam_unix.so auth rules. Red Hat: 'authselect disable-feature with-nullok' rather than editing system-auth by hand. Debian: the argument is in common-auth and pam-auth-update owns that file.",
			"Check the per-service stacks as well as the shared one. /etc/pam.d/login and /etc/pam.d/sshd can carry their own pam_unix rules, and a host that has diverged from the shared stack has usually diverged there.",
			"Confirm afterwards that the accounts you decided to keep can still log in, from a second session, before closing the one you are working in.",
		},
		Commands: []string{
			"grep -rn 'nullok' /etc/pam.d/",
			"awk -F: '($2 == \"\") {print $1}' /etc/shadow",
			"authselect current",
		},
		Caution: "Removing nullok immediately stops every empty-password account from authenticating. On an appliance or an embedded image that is how the console account is meant to work, so enumerate them before making the change, and keep a session open in case one of them was yours.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "AC-2"},
	},

	References: []finding.Reference{
		{Title: "pam_unix(8)", URL: "https://man7.org/linux/man-pages/man8/pam_unix.8.html"},
	},
}

// readable returns every stack that was read, in record order.
//
// AUTH-0004 searches all of them rather than the primary pair: nullok on
// /etc/pam.d/login admits an empty password exactly as nullok in system-auth
// does, and confining the search to the shared stack would report a clean host
// while a per-service file accepted no password at all.
func readable(p fact.PAM) []fact.PAMService {
	var out []fact.PAMService
	for _, s := range p.Services {
		if s.State == fact.FilePresent {
			out = append(out, s)
		}
	}
	return out
}

// offenderFiles names the files the rules are written in, deduplicated.
func offenderFiles(lines []fact.PAMLine) string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		if !seen[l.File] {
			seen[l.File] = true
			out = append(out, fmt.Sprintf("%s:%d", l.File, l.Line))
		}
	}
	return strings.Join(out, ", ")
}

// secureNote distinguishes nullok_secure, which is narrower and still an
// account with no password.
func secureNote(lines []fact.PAMLine) string {
	for _, l := range lines {
		if l.HasArg("nullok_secure") {
			return " One of these uses nullok_secure, which confines the empty-password login to terminals listed in /etc/securetty. That is narrower than nullok and it is still an account that authenticates with nothing."
		}
	}
	return ""
}
