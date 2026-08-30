package fact

import "strconv"

// LoginDefsID names the shadow-suite configuration fact.
const LoginDefsID ID = "auth.login_defs"

// LoginDefsSetting is one `KEY value` line from /etc/login.defs.
//
// Every occurrence is kept, not only the winning one. login.defs is read
// top-to-bottom and the *first* definition of a key wins — the opposite of
// sysctl.d — so a finding that reports a value has to be able to show the
// operator which line is actually in force and which ones below it are dead.
type LoginDefsSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Line  int    `json:"line"`
}

// LoginDefs is /etc/login.defs: the shadow suite's defaults.
//
// **It is what useradd, chage and passwd read, and not what PAM reads.** A host
// can hash one way through the PAM stack and another way through `useradd`,
// which is not a contradiction the tools resolve — it is two programs consulting
// two files. AUTH-0005 reads the PAM line and falls back to here; USERS-0012
// reads here alone, because the aging defaults have no PAM equivalent.
type LoginDefs struct {
	// State is what became of the file.
	State SourceState `json:"state"`
	// Path is where it was looked for.
	Path string `json:"path"`
	// Msg explains a state that is not present.
	Msg string `json:"message,omitempty"`
	// Digest is the sha256 of the bytes read, so a finding can cite evidence
	// an auditor can verify against the bundle's evidence store.
	Digest string `json:"digest,omitempty"`

	// Settings are every `KEY value` line found, in file order.
	Settings []LoginDefsSetting `json:"settings,omitempty"`
}

func (LoginDefs) FactID() ID       { return LoginDefsID }
func (LoginDefs) FactVersion() int { return 1 }

// Present reports whether the file was read.
func (l LoginDefs) Present() bool { return l.State == SourcePresent }

// Effective returns the value in force for a key, and where it was set.
//
// **The first definition wins**, which is login.defs's rule and is worth
// stating because it is the reverse of most configuration this project reads.
// shadow(3)'s parser takes the first match and ignores the rest, so a file that
// says PASS_MIN_DAYS 1 on line 30 and PASS_MIN_DAYS 0 on line 80 has a minimum
// age of one day — and a check that took the last would report the opposite of
// what the host does.
func (l LoginDefs) Effective(key string) (LoginDefsSetting, bool) {
	for _, s := range l.Settings {
		if s.Key == key {
			return s, true
		}
	}
	return LoginDefsSetting{}, false
}

// Shadowed returns the definitions of a key that are never read: everything
// after the first.
//
// A finding names them because a line an operator edited and that has no effect
// is worse than a line they never wrote — they believe the setting is applied.
func (l LoginDefs) Shadowed(key string) []LoginDefsSetting {
	var out []LoginDefsSetting
	seen := false
	for _, s := range l.Settings {
		if s.Key != key {
			continue
		}
		if !seen {
			seen = true
			continue
		}
		out = append(out, s)
	}
	return out
}

// Int returns a key's effective value as an integer.
//
// ok is false when the key is unset or does not hold one integer. A check must
// treat that as UNKNOWN rather than as a zero: PASS_MIN_DAYS reading as 0 means
// a password may be changed twice in a second, and inventing that from an
// unparseable value would be a fabricated FAIL.
func (l LoginDefs) Int(key string) (int, LoginDefsSetting, bool) {
	s, ok := l.Effective(key)
	if !ok {
		return 0, s, false
	}
	n, err := strconv.Atoi(s.Value)
	if err != nil {
		return 0, s, false
	}
	return n, s, true
}
