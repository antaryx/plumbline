package auth

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/catalog/checks/logindefs"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// StrongHashes are the pam_unix password-hashing arguments that are acceptable.
//
// yescrypt and gost_yescrypt are memory-hard, which is what makes them
// expensive on the GPU an attacker actually uses rather than only on the CPU.
// sha512 is not memory-hard but its default round count puts it well beyond
// reach of a wordlist attack, and it is what the majority of hardened hosts in
// service use. blowfish is bcrypt, likewise acceptable.
var StrongHashes = []string{"yescrypt", "gost_yescrypt", "sha512", "blowfish"}

// WeakHashes are the arguments that are not.
//
// md5 here means crypt's $1$ MD5, which is unsalted-fast rather than broken as
// a hash — the problem is speed, not collisions. bigcrypt and the implicit DES
// crypt truncate: DES crypt uses the first **eight characters** of the password
// and discards the rest, so a twenty-character passphrase on such a host is an
// eight-character password, and every quality rule above it is decoration.
var WeakHashes = []string{"md5", "bigcrypt", "sha256"}

// Check0005 tests that passwords are hashed with a strong algorithm.
var Check0005 = catalog.Check{
	ID:     "AUTH-0005",
	Module: "AUTH",
	Title:  "Passwords are hashed with a strong algorithm",
	Description: `The hash algorithm decides what a stolen /etc/shadow is worth.
It has no effect on anything an attacker does before that point and complete
effect afterwards, which is why it is worth getting right on a host where
nothing has gone wrong yet.

The difference is arithmetic. MD5-crypt is fast, and fast is the entire
problem: a commodity GPU tries it billions of times a second, so a wordlist
with rules exhausts anything a human chose within hours. SHA-512-crypt runs
5000 rounds by default, which is four orders of magnitude slower and moves the
same attack from hours into an unattractive amount of time. yescrypt, the
current default on Debian and Fedora, is memory-hard: it needs RAM per guess as
well as cycles, which is what defeats the GPU rather than merely inconveniencing
it.

DES crypt is worse than slow-versus-fast. It uses the **first eight characters
of the password and discards the rest**, so a twenty-character passphrase on
such a host is an eight-character password, AUTH-0002's length requirement is
decoration, and the account is brute-forceable regardless of what the user
chose.

The algorithm applies **when a password is set**, not retroactively. Changing
it leaves every existing hash in its old form, so this check reports the policy
and USERS-0006 reports what is actually in /etc/shadow. Both are needed: the
policy is what governs the next password, and the file is what an attacker
steals today.`,

	BaseSeverity: finding.High,
	Tags:         []string{"auth", "pam", "password", "hashing", "credentials"},
	// **PAM only, and login.defs deliberately not.** Requires is the list of
	// facts the check cannot work without, and the runner marks a check
	// UNKNOWN(fact_not_collected) when one of them is missing. login.defs is a
	// *fallback* consulted only when the PAM line names no algorithm, so
	// listing it here would turn a check that can answer from the PAM line
	// alone into one that refuses to — on every bundle recorded before this
	// collector existed, which is every bundle in the corpus. See
	// fromLoginDefs, which tells an absent fact from an absent file.
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

		lines := fact.Find(stacks, fact.PAMPassword, "pam_unix.so")
		if len(lines) == 0 {
			return unknownIfIncomplete(stacks, catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Subject:       "pam_unix.so",
				Detail: fmt.Sprintf(
					"No pam_unix.so rule is in the password stack (%s), so nothing here says how a password is hashed. Either passwords are stored by some other module this check does not read, or the stack is incomplete in a way that would also stop passwords being changed at all.",
					stackNames(stacks)),
				Evidence: stackEvidence(stacks),
			})
		}

		var weak, strong []fact.PAMLine
		var weakNames []string
		for _, l := range lines {
			switch {
			case anyArg(l, StrongHashes...):
				strong = append(strong, l)
			case anyArg(l, WeakHashes...):
				weak = append(weak, l)
				weakNames = append(weakNames, argsFound(l, WeakHashes))
			}
		}

		// Positive: we read the argument. Nothing unread can unmake it.
		if len(weak) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "pam_unix.so",
				Detail: fmt.Sprintf(
					"pam_unix.so hashes passwords with %s (%s). A stolen /etc/shadow from this host is worth far more than it needs to be: MD5-crypt is fast enough that a commodity GPU exhausts a rule-driven wordlist in hours, where SHA-512-crypt's 5000 rounds move the same attack into an unattractive amount of time and yescrypt's memory-hardness defeats the GPU outright. Changing this affects passwords set from now on; USERS-0006 reports what is already in the file.",
					strings.Join(weakNames, ", "), offenderFiles(weak)),
				Evidence: linesEvidence(p, weak),
			}
		}

		if len(strong) > 0 {
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  "pam_unix.so",
				Detail:   fmt.Sprintf("pam_unix.so hashes passwords with %s, so a stolen /etc/shadow is expensive to attack. What is already in the file is USERS-0006's question — the algorithm applies when a password is set, not retroactively.", argsFound(strong[0], StrongHashes)),
				Evidence: linesEvidence(p, strong),
			}
		}

		// No algorithm argument on the PAM line. **The fall-back is
		// /etc/login.defs**, which is now collected — see encryptMethod. This
		// used to be an unconditional UNKNOWN saying that neither source was
		// read, which was true and was a gap: pam_unix.so with no argument is
		// the *shipped* configuration on Debian and Ubuntu, so the check
		// declined to answer on a large fraction of the hosts it runs against.
		return fromLoginDefs(fs, p, lines)
	},

	Remediation: &finding.Remediation{
		Summary: "Set yescrypt or sha512 on the pam_unix.so password rule, then rotate the passwords that were hashed the old way.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Choose the algorithm the distribution's libcrypt supports. yescrypt on Debian 11+, Ubuntu 22.04+ and Fedora; sha512 everywhere else. Setting yescrypt on a host whose libcrypt does not implement it makes password changes fail, and the failure appears at the next 'passwd' rather than when the file is saved.",
			"Change it through the distribution's mechanism: 'authselect' on Red Hat, 'pam-auth-update' on Debian. A hand edit to a generated stack is overwritten at the next regeneration, silently.",
			"Set ENCRYPT_METHOD in /etc/login.defs to match. useradd and chpasswd read that file rather than the PAM stack, so leaving them disagreeing means an account's hash depends on which tool created it.",
			"Rotate the existing passwords. The algorithm applies when a password is set and not before, so every hash written under the old one stays exactly as weak as it was, this step is the one that actually changes what a stolen /etc/shadow is worth.",
			"Confirm the change took effect by looking at a hash you just set: the field's prefix names the algorithm ('$y$' yescrypt, '$6$' SHA-512, '$1$' MD5, no prefix at all DES).",
		},
		Commands: []string{
			"grep -E 'pam_unix.so' /etc/pam.d/* | grep password",
			"grep ENCRYPT_METHOD /etc/login.defs",
			"awk -F: '{print $1, substr($2,1,4)}' /etc/shadow",
		},
		Caution: "Setting an algorithm the host's libcrypt does not support makes every password change fail, and the failure appears the next time somebody runs passwd rather than when you save the file. Verify by changing a throwaway account's password immediately after the edit, while you still have a root session open.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
		{Framework: "nist-800-53-r5", Control: "SC-13"},
	},

	References: []finding.Reference{
		{Title: "crypt(5), hashing methods", URL: "https://man7.org/linux/man-pages/man5/crypt.5.html"},
		{Title: "pam_unix(8)", URL: "https://man7.org/linux/man-pages/man8/pam_unix.8.html"},
	},
}

// anyArg reports whether the rule carries any of the given flag arguments.
func anyArg(l fact.PAMLine, names ...string) bool {
	for _, n := range names {
		if l.HasArg(n) {
			return true
		}
	}
	return false
}

// argsFound names which of the given flags the rule carries.
func argsFound(l fact.PAMLine, names []string) string {
	var out []string
	for _, n := range names {
		if l.HasArg(n) {
			out = append(out, n)
		}
	}
	return strings.Join(out, " and ")
}

// EncryptMethodKey is the login.defs directive that names the hash.
const EncryptMethodKey = "ENCRYPT_METHOD"

// fromLoginDefs answers the hashing question from /etc/login.defs when the PAM
// line does not.
//
// **This is the second of two sources and never the first.** When pam_unix.so
// names an algorithm, that argument wins for anything authenticating through
// PAM whatever login.defs says — so the PAM branch above returns before
// reaching here. ENCRYPT_METHOD is what useradd, chpasswd and passwd(1) read,
// and on a Debian or Ubuntu host, where the shipped pam_unix.so line carries no
// algorithm at all, it is the answer.
//
// Three outcomes, and the third is the honest one:
//
//   - the key is set to something this build recognises: a verdict, naming the
//     file it came from rather than the PAM line, because that is where an
//     operator has to go to change it;
//   - the key is set to something it does not recognise: UNKNOWN. A hash name
//     nobody here has heard of must not be read as strong;
//   - login.defs is absent, unreadable, or has no ENCRYPT_METHOD: UNKNOWN, and
//     the detail says which of those it was. The effective algorithm is then
//     libcrypt's compiled-in default, which is a property of the binary rather
//     than of any file on the host and has changed between releases.
func fromLoginDefs(fs *fact.Set, p fact.PAM, lines []fact.PAMLine) catalog.Outcome {
	l, _, collected := fact.Get[fact.LoginDefs](fs, fact.LoginDefsID)

	unresolved := func(why string) catalog.Outcome {
		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonFactMissing,
			Subject:       "pam_unix.so",
			Detail: fmt.Sprintf(
				"pam_unix.so is in the password stack (%s) with no hashing algorithm argument, and %s. "+
					"The effective algorithm is then libcrypt's compiled-in default, which is a property of "+
					"the binary rather than of any file on this host and has changed between releases. "+
					"Naming the algorithm explicitly on the PAM line removes the ambiguity as well as the doubt.",
				offenderFiles(lines), why),
			Evidence: linesEvidence(p, lines),
		}
	}

	switch {
	case !collected:
		// **The fact is not in this set at all**, which is not the same claim
		// as the file being absent from the host. It happens when an older
		// bundle is re-evaluated by a newer build: the collector that reads
		// login.defs did not exist when the bundle was recorded, so the host
		// may well have had one. Saying "this host has no /etc/login.defs"
		// here would be a statement about a machine nobody looked at.
		return unresolved("this scan carries no reading of /etc/login.defs — the bundle predates the collector that reads it, so re-collect to resolve this")
	case l.State == fact.SourceDenied:
		return unresolved("/etc/login.defs could not be read (permission denied), so its ENCRYPT_METHOD is unknown")
	case !l.Present():
		return unresolved("this host has no /etc/login.defs to fall back to")
	}

	set, ok := l.Effective(EncryptMethodKey)
	if !ok {
		return unresolved("/etc/login.defs sets no ENCRYPT_METHOD")
	}

	method := strings.ToLower(set.Value)
	ev := append(linesEvidence(p, lines), logindefs.Evidence(l, set))

	switch {
	case containsFold(StrongHashes, method):
		return catalog.Outcome{
			Result:  finding.Pass,
			Subject: EncryptMethodKey,
			Detail: fmt.Sprintf(
				"pam_unix.so names no algorithm, so the hash comes from ENCRYPT_METHOD %s in /etc/login.defs "+
					"(line %d), which is strong. A stolen /etc/shadow from this host is expensive to attack. "+
					"Note that this is the shadow suite's setting: it applies to passwords set with passwd, "+
					"useradd and chpasswd, and a PAM stack that later named a weaker algorithm would override "+
					"it for anything authenticating through PAM.%s",
				set.Value, set.Line, logindefs.ShadowedNote(l, EncryptMethodKey)),
			Evidence: ev,
		}
	case containsFold(WeakHashes, method), method == "des", method == "crypt":
		// Positive: we read the value. Nothing unread can unmake it.
		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: EncryptMethodKey,
			Detail: fmt.Sprintf(
				"pam_unix.so names no algorithm, so the hash comes from ENCRYPT_METHOD %s in /etc/login.defs "+
					"(line %d). A stolen /etc/shadow from this host is worth far more than it needs to be: "+
					"MD5-crypt is fast enough that a commodity GPU exhausts a rule-driven wordlist in hours, "+
					"and DES crypt truncates the password to its first eight characters outright. Changing "+
					"this affects passwords set from now on; USERS-0006 reports what is already in the file.%s",
				set.Value, set.Line, logindefs.ShadowedNote(l, EncryptMethodKey)),
			Evidence: ev,
		}
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonParse,
		Subject:       EncryptMethodKey,
		Detail: fmt.Sprintf(
			"pam_unix.so names no algorithm and /etc/login.defs sets ENCRYPT_METHOD to %q (line %d), which "+
				"this build does not recognise. It is not read as strong: a hashing method nobody here has "+
				"heard of may be anything, and reporting a host as protected on the strength of an unknown "+
				"word is the one answer this check must not give.",
			set.Value, set.Line),
		Evidence: ev,
	}
}

// containsFold reports whether want holds s, compared case-insensitively.
// login.defs values are conventionally upper case and PAM arguments lower, and
// both spellings reach here.
func containsFold(want []string, s string) bool {
	for _, w := range want {
		if strings.EqualFold(w, s) {
			return true
		}
	}
	return false
}
