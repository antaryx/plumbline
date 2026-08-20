package fact

import (
	"sort"
	"strconv"
	"strings"
)

// PAMID names the Pluggable Authentication Modules stack fact.
const PAMID ID = "auth.pam"

// PAMType is a PAM management group. Each is an independent stack, evaluated
// separately, and a module in one says nothing about the others: pam_unix.so
// in `auth` verifies a password, and pam_unix.so in `password` changes one.
// A check that searched all four types at once would report password-quality
// enforcement from a line that only ever runs at login.
type PAMType string

const (
	// PAMAuth verifies the user is who they claim: passwords, tokens, lockout.
	PAMAuth PAMType = "auth"
	// PAMAccount decides whether a verified user may log in now: expiry,
	// time-of-day, and where faillock refuses an already-locked account.
	PAMAccount PAMType = "account"
	// PAMPassword governs *setting* a password: quality, history, hashing.
	PAMPassword PAMType = "password"
	// PAMSession sets up and tears down the session.
	PAMSession PAMType = "session"
)

// FileState is what the collector was able to observe about one PAM file.
type FileState string

const (
	// FilePresent: read successfully.
	FilePresent FileState = "present"
	// FileAbsent: does not exist. For a service file this is the ordinary case
	// on the distribution that uses the other family's names.
	FileAbsent FileState = "absent"
	// FileDenied: permission denied. Nothing may be concluded from it.
	FileDenied FileState = "denied"
	// FileError: the read failed for a reason worth recording verbatim,
	// including a symlink chain that could not be resolved.
	FileError FileState = "error"
)

// PAMLine is one rule in a PAM stack.
//
// The four fields before File are the whole of PAM's syntax:
//
//	<type>  <control>  <module>  <args...>
//
// Control is kept as raw text rather than parsed into a decision table.
// Simulating PAM's control flow means implementing the bracketed
// `[success=1 default=ignore]` jump semantics correctly, and a stack
// simulator that is subtly wrong produces confident verdicts about which
// module runs — which is worse than not having one. What the checks assert is
// presence and arguments; where control flow could defeat that, the check says
// so rather than pretending to have simulated it.
type PAMLine struct {
	Type    PAMType  `json:"type"`
	Control string   `json:"control"`
	Module  string   `json:"module"`
	Args    []string `json:"args,omitempty"`

	// Optional records the leading '-' on the type, which tells PAM not to log
	// an error when the module is not installed. A line marked this way may do
	// nothing at all on a host where the package is missing, and it looks
	// identical to a working one in the file.
	Optional bool `json:"optional,omitempty"`

	// File and Line are where this rule was actually written, which is not the
	// service file whenever an include brought it in. A finding has to send an
	// operator to the file they must edit.
	File string `json:"file"`
	Line int    `json:"line"`
	// Depth is how many includes deep the rule was reached; 0 is the service
	// file itself.
	Depth int `json:"depth,omitempty"`
}

// HasArg reports whether a bare flag argument is present.
func (l PAMLine) HasArg(name string) bool {
	for _, a := range l.Args {
		if a == name {
			return true
		}
	}
	return false
}

// Arg returns the value of a key=value argument.
func (l PAMLine) Arg(name string) (string, bool) {
	prefix := name + "="
	for _, a := range l.Args {
		if strings.HasPrefix(a, prefix) {
			return a[len(prefix):], true
		}
	}
	return "", false
}

// IntArg returns a key=value argument parsed as an integer.
func (l PAMLine) IntArg(name string) (int, bool) {
	v, ok := l.Arg(name)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

// Enforcing reports whether this rule's failure can deny the operation.
//
// `required` and `requisite` both do. `optional` does not: PAM ignores its
// result entirely unless it is the only module in the stack, so a quality
// module marked optional is a password policy that is never applied and reads
// in the file exactly like one that is.
//
// A bracketed control is enforcing when it maps failure to `die` or `bad`, and
// not when it maps failure to `ignore`. Anything else bracketed is reported as
// not enforcing, which is the conservative direction: it produces a finding a
// human reads rather than a PASS drawn from a control expression this code did
// not understand.
func (l PAMLine) Enforcing() bool {
	c := strings.ToLower(strings.TrimSpace(l.Control))
	switch c {
	case "required", "requisite":
		return true
	case "optional", "sufficient", "include", "substack":
		return false
	}
	if strings.HasPrefix(c, "[") {
		return strings.Contains(c, "default=die") || strings.Contains(c, "default=bad")
	}
	return false
}

// PAMInclude is an include directive and, when it failed, why.
//
// PAM has three of them and they are not interchangeable. `@include <file>`
// is a pam.d-only Debian extension that inlines the whole file, every type at
// once. `<type> include <file>` pulls in only the lines of that one type.
// `<type> substack <file>` does the same but scopes any die/done jump to the
// included stack. A collector that treated @include as type-scoped would drop
// three quarters of a Debian host's rules, and one that treated `auth include`
// as whole-file would import password rules into the auth stack.
type PAMInclude struct {
	// Directive is "@include", "include" or "substack".
	Directive string `json:"directive"`
	// Type is the management group an `include`/`substack` was scoped to.
	// Empty for @include, which is not scoped.
	Type PAMType `json:"type,omitempty"`
	// Target is the name as written; Path is where it was looked for.
	Target string `json:"target"`
	Path   string `json:"path"`
	// File and Line locate the directive itself.
	File string `json:"file"`
	Line int    `json:"line"`
	// Reason says why it could not be followed. Empty on a resolved include,
	// which is not recorded here at all.
	Reason string `json:"reason"`
}

// PAMService is one service's fully resolved stack.
type PAMService struct {
	Name  string    `json:"name"`
	Path  string    `json:"path"`
	State FileState `json:"state"`
	Msg   string    `json:"msg,omitempty"`

	// ResolvedPath is where the content actually came from when Path is a
	// symlink. Red Hat's /etc/pam.d/system-auth is a link into
	// /etc/authselect or to system-auth-ac on every stock install, so this is
	// the common case rather than an oddity, and a finding that cited the link
	// would send an operator to edit a file that authselect overwrites.
	ResolvedPath string `json:"resolved_path,omitempty"`

	// Lines is the stack in file order with includes expanded in place.
	Lines []PAMLine `json:"lines,omitempty"`
	// Unresolved lists the includes that could not be followed. While this is
	// non-empty the stack is incomplete, and nothing may be concluded from a
	// module's *absence* from it.
	Unresolved []PAMInclude `json:"unresolved,omitempty"`
}

// Complete reports whether this stack may be relied on to say that a module is
// absent from it.
func (s PAMService) Complete() bool {
	return s.State == FilePresent && len(s.Unresolved) == 0
}

// Layout is which distribution family's PAM arrangement this host uses.
//
// It is not cosmetic. The two families keep the same rules in differently
// named files, and a check that looked only for one family's names would
// report "no password quality is enforced" on every host of the other — a
// wrong verdict produced entirely by packaging, which is the same failure mode
// SERVICES-0003's unit-name list exists to prevent.
type Layout string

const (
	// LayoutRedHat keeps the shared rules in system-auth and password-auth.
	LayoutRedHat Layout = "redhat"
	// LayoutDebian keeps them in common-auth, common-account, common-password
	// and common-session, pulled into each service by @include.
	LayoutDebian Layout = "debian"
	// LayoutUnrecognised means /etc/pam.d exists but neither family's shared
	// files were found. The stack is real and this collector cannot say where
	// its rules live, which is UNKNOWN and never PASS.
	LayoutUnrecognised Layout = "unrecognised"
	// LayoutNone means there is no PAM configuration at all.
	LayoutNone Layout = "none"
)

// PwQualitySetting is one key=value from a pwquality or faillock
// configuration file.
type PwQualitySetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// SettingsFile is a parsed key=value configuration file beside the PAM stack.
//
// pam_pwquality and pam_faillock both take their parameters from two places:
// arguments on the PAM line, and a file in /etc/security. The file is read
// first and the module arguments override it, so neither source alone is the
// effective configuration and a check that read only one would be wrong in
// whichever direction that host happened to use.
type SettingsFile struct {
	Path     string             `json:"path"`
	State    FileState          `json:"state"`
	Msg      string             `json:"msg,omitempty"`
	Settings []PwQualitySetting `json:"settings,omitempty"`
}

// Get returns the last occurrence of a key, which is the one that wins: these
// files are read top to bottom with later assignments replacing earlier ones.
func (f SettingsFile) Get(key string) (PwQualitySetting, bool) {
	var found PwQualitySetting
	var ok bool
	for _, s := range f.Settings {
		if strings.EqualFold(s.Key, key) {
			found, ok = s, true
		}
	}
	return found, ok
}

// PAM is the collected authentication stack.
type PAM struct {
	// Installed reports whether /etc/pam.d exists at all. When false the
	// module's checks are NOT_APPLICABLE: a host without PAM authenticates by
	// some other means this module cannot read, and reporting PASS over it
	// would be assurance about a mechanism never examined.
	Installed bool `json:"installed"`
	// DirState records what happened when /etc/pam.d itself was probed, so
	// "not installed" and "not allowed to look" stay distinguishable.
	DirState FileState `json:"dir_state"`
	DirMsg   string    `json:"dir_msg,omitempty"`

	// Services are the stacks probed, in the collector's fixed order.
	Services []PAMService `json:"services,omitempty"`
	// PwQuality and Faillock are the /etc/security files that hold the other
	// half of those modules' configuration.
	PwQuality SettingsFile `json:"pwquality"`
	Faillock  SettingsFile `json:"faillock"`

	// Digests maps every file read to the SHA-256 of its bytes, so a finding's
	// evidence points at content that can be verified later (ADR-0009).
	Digests map[string]string `json:"digests,omitempty"`
}

func (PAM) FactID() ID       { return PAMID }
func (PAM) FactVersion() int { return 1 }

// Service returns one stack by name.
func (p PAM) Service(name string) (PAMService, bool) {
	for _, s := range p.Services {
		if s.Name == name {
			return s, true
		}
	}
	return PAMService{}, false
}

// present reports whether a named stack was read.
func (p PAM) present(name string) bool {
	s, ok := p.Service(name)
	return ok && s.State == FilePresent
}

// Layout classifies the host's PAM arrangement.
func (p PAM) Layout() Layout {
	switch {
	case !p.Installed:
		return LayoutNone
	case p.present("system-auth") || p.present("password-auth"):
		return LayoutRedHat
	case p.present("common-password") || p.present("common-auth"):
		return LayoutDebian
	default:
		return LayoutUnrecognised
	}
}

// Primary returns the stacks that govern one management group on this host.
//
// It is the layout question made usable: a check asks for the password stacks
// and gets system-auth and password-auth on Red Hat, common-password on
// Debian, and nothing at all where the layout is unrecognised — which is the
// signal to report UNKNOWN rather than to search whatever files happened to be
// there.
func (p PAM) Primary(t PAMType) []PAMService {
	var names []string
	switch p.Layout() {
	case LayoutRedHat:
		names = []string{"system-auth", "password-auth"}
	case LayoutDebian:
		switch t {
		case PAMAuth:
			names = []string{"common-auth"}
		case PAMAccount:
			names = []string{"common-account"}
		case PAMPassword:
			names = []string{"common-password"}
		case PAMSession:
			names = []string{"common-session"}
		}
	default:
		return nil
	}

	var out []PAMService
	for _, n := range names {
		if s, ok := p.Service(n); ok && s.State == FilePresent {
			out = append(out, s)
		}
	}
	return out
}

// Find returns the rules of one type naming any of the given modules, across
// the stacks given, in stack then file order.
func Find(stacks []PAMService, t PAMType, modules ...string) []PAMLine {
	want := map[string]bool{}
	for _, m := range modules {
		want[m] = true
	}

	var out []PAMLine
	for _, s := range stacks {
		for _, l := range s.Lines {
			if l.Type == t && want[l.Module] {
				out = append(out, l)
			}
		}
	}
	return out
}

// Incomplete returns the stacks that may not be relied on to prove a module is
// absent, sorted by name.
//
// A check consults this before drawing any negative conclusion and never
// before drawing a positive one: an include we could not follow might contain
// the pam_pwquality line that decides the verdict, but it cannot unmake one we
// already read. That asymmetry is ADR-0014.
func Incomplete(stacks []PAMService) []PAMService {
	var out []PAMService
	for _, s := range stacks {
		if !s.Complete() {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UnresolvedIncludes returns every include that could not be followed, across
// the stacks given, sorted by file and line.
func UnresolvedIncludes(stacks []PAMService) []PAMInclude {
	var out []PAMInclude
	for _, s := range stacks {
		out = append(out, s.Unresolved...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
