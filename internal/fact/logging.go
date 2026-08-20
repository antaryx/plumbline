package fact

import (
	"io/fs"
	"strconv"
	"strings"
)

// Fact IDs for the logging subsystem.
//
// Two facts rather than one, for the same reason the account databases are
// three: rsyslog and journald are separate daemons with separate files and
// separate readabilities, a host may run either, both or neither, and a single
// fact would let one missing daemon erase what is known about the other.
const (
	RsyslogID  ID = "logging.rsyslog"
	JournaldID ID = "logging.journald"
)

// ---------------------------------------------------------------------------
// rsyslog
// ---------------------------------------------------------------------------

// RsyslogSyntax names which of rsyslog's configuration languages a statement
// was written in.
//
// This distinction is carried in the fact rather than resolved away because a
// check that reports a finding has to quote the line back to the operator in
// the language their file is actually written in. Telling somebody to change
// `action(type="omfwd" ...)` when their file says `*.* @@host` sends them
// looking for a line that does not exist.
type RsyslogSyntax string

const (
	// SyntaxLegacy is the sysklogd-derived format: a selector, whitespace, an
	// action. `*.* @@logs.example.net:514`
	SyntaxLegacy RsyslogSyntax = "legacy"
	// SyntaxLegacyDirective is rsyslog's own `$Name value` form, which is
	// neither sysklogd nor RainerScript. `$FileCreateMode 0640`
	SyntaxLegacyDirective RsyslogSyntax = "legacy-directive"
	// SyntaxRainerScript is the object format rsyslog 6+ documents as
	// preferred. `action(type="omfwd" target="..." protocol="tcp")`
	SyntaxRainerScript RsyslogSyntax = "rainerscript"
)

// RsyslogDirective is one `$Name value` line.
//
// Legacy directives are *positional*: `$FileCreateMode` sets the mode used by
// the file actions that follow it, so a file may legitimately contain several,
// and the last one before a given action is the one that governs it. Every
// occurrence is therefore recorded rather than only the last, because a
// permissive one applies to whatever follows it whatever comes later.
type RsyslogDirective struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// RsyslogObject is one RainerScript statement: action(), module(), global(),
// input(), template(), include().
type RsyslogObject struct {
	// Kind is the statement name, lowercased: "action", "module", "global".
	Kind string `json:"kind"`
	// Params are the name="value" pairs, with names lowercased because
	// RainerScript parameter names are case-insensitive.
	Params map[string]string `json:"params,omitempty"`
	File   string            `json:"file"`
	Line   int               `json:"line"`
}

// Param reads a parameter case-insensitively.
func (o RsyslogObject) Param(name string) (string, bool) {
	v, ok := o.Params[strings.ToLower(name)]
	return v, ok
}

// RsyslogRule is one legacy selector/action line.
type RsyslogRule struct {
	// Selector is the facility.priority expression: "*.*", "authpriv.*",
	// "mail.none;cron.none".
	Selector string `json:"selector"`
	// Action is what the messages are done with: a file path, "@host" for UDP
	// forwarding, "@@host" for TCP, "|/path" for a pipe, ":omusrmsg:*".
	Action string `json:"action"`
	File   string `json:"file"`
	Line   int    `json:"line"`
}

// Rsyslog is the parsed rsyslog configuration.
type Rsyslog struct {
	// Installed reports whether a configuration was found at all. When false,
	// the rsyslog checks are NOT_APPLICABLE rather than FAIL: a host running
	// only journald has not failed to secure rsyslog, it does not have one.
	Installed bool `json:"installed"`
	// Files lists every file read, in read order, primary first.
	Files      []string           `json:"files,omitempty"`
	Directives []RsyslogDirective `json:"directives,omitempty"`
	Objects    []RsyslogObject    `json:"objects,omitempty"`
	Rules      []RsyslogRule      `json:"rules,omitempty"`
	// UnresolvedIncludes records include patterns that matched nothing or
	// could not be read. A check whose answer might live in an unresolved
	// include must resolve to UNKNOWN, not report the default.
	UnresolvedIncludes []string `json:"unresolved_includes,omitempty"`
	// Malformed records lines that looked like configuration and could not be
	// parsed, with their file and line. A file only partly understood is not a
	// file to draw negative conclusions from.
	Malformed []RsyslogDirective `json:"malformed,omitempty"`
	Digests   map[string]string  `json:"digests,omitempty"`
}

func (Rsyslog) FactID() ID       { return RsyslogID }
func (Rsyslog) FactVersion() int { return 1 }

// RemoteDest is one configured remote log destination, normalised across both
// syntaxes so a check does not have to know which one produced it.
//
// Normalising here rather than in a check is deliberate. Which language a
// destination was written in is a property of rsyslog, not a policy question,
// and every check that reads destinations would otherwise repeat the same
// translation — and get it subtly different.
type RemoteDest struct {
	// Target is the host, as written. Ports and any surrounding syntax are
	// stripped from the legacy forms so the two syntaxes report alike.
	Target string `json:"target"`
	// Protocol is "udp", "tcp", "relp", or "unknown" when the configuration
	// does not say. Unknown is not a synonym for udp: omfwd's default is udp,
	// but reporting a default as an observation is the error this project
	// exists to avoid, so the check decides what to do with it.
	Protocol string        `json:"protocol"`
	Syntax   RsyslogSyntax `json:"syntax"`
	// Raw is the statement as written, for evidence.
	Raw  string `json:"raw"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// Remote protocol values.
const (
	ProtoUDP     = "udp"
	ProtoTCP     = "tcp"
	ProtoRELP    = "relp"
	ProtoUnknown = "unknown"
)

// Reliable reports whether this destination's transport survives load and
// restarts. UDP does not: it drops silently under exactly the conditions that
// produce the logs worth keeping.
func (d RemoteDest) Reliable() bool { return d.Protocol == ProtoTCP || d.Protocol == ProtoRELP }

// RemoteDestinations returns every remote destination configured, in file
// order, from both syntaxes.
func (r Rsyslog) RemoteDestinations() []RemoteDest {
	var out []RemoteDest

	for _, rule := range r.Rules {
		action := strings.TrimSpace(rule.Action)
		switch {
		case strings.HasPrefix(action, "@@"):
			out = append(out, RemoteDest{
				Target: hostOf(action[2:]), Protocol: ProtoTCP, Syntax: SyntaxLegacy,
				Raw: rule.Selector + " " + rule.Action, File: rule.File, Line: rule.Line,
			})
		case strings.HasPrefix(action, "@"):
			out = append(out, RemoteDest{
				Target: hostOf(action[1:]), Protocol: ProtoUDP, Syntax: SyntaxLegacy,
				Raw: rule.Selector + " " + rule.Action, File: rule.File, Line: rule.Line,
			})
		}
	}

	for _, o := range r.Objects {
		if o.Kind != "action" {
			continue
		}
		typ, _ := o.Param("type")
		switch strings.ToLower(typ) {
		case "omfwd":
			target, _ := o.Param("target")
			proto := ProtoUnknown
			if p, ok := o.Param("protocol"); ok {
				proto = strings.ToLower(strings.TrimSpace(p))
			}
			out = append(out, RemoteDest{
				Target: target, Protocol: proto, Syntax: SyntaxRainerScript,
				Raw: "action(type=\"omfwd\" target=\"" + target + "\")", File: o.File, Line: o.Line,
			})
		case "omrelp":
			target, _ := o.Param("target")
			out = append(out, RemoteDest{
				Target: target, Protocol: ProtoRELP, Syntax: SyntaxRainerScript,
				Raw: "action(type=\"omrelp\" target=\"" + target + "\")", File: o.File, Line: o.Line,
			})
		}
	}
	return out
}

// hostOf strips a trailing ":port" from a legacy forwarding action.
//
// The IPv6 case is why this is not a one-liner. A bare literal such as
// 2001:db8::1 is all colons, and cutting at the last one would report the
// destination as "2001:db8:" — a target that does not exist, in a finding an
// operator would then go looking for. rsyslog requires brackets around an IPv6
// literal that carries a port, so a port is only stripped when the remainder
// is numeric AND either there is exactly one colon or the host part ends in a
// closing bracket.
func hostOf(s string) string {
	s = strings.TrimSpace(s)

	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s
	}
	if _, err := strconv.Atoi(s[i+1:]); err != nil {
		return s
	}
	host := s[:i]
	if strings.Count(s, ":") == 1 || strings.HasSuffix(host, "]") {
		return host
	}
	// Several colons and no bracket: a bare IPv6 literal, port and all
	// ambiguous. Return it whole rather than mangling it.
	return s
}

// RsyslogFileMode is one place the configuration sets the mode of the log
// files rsyslog creates.
type RsyslogFileMode struct {
	// Mode is the parsed permission value.
	Mode fs.FileMode `json:"mode"`
	// Raw is the value as written, so evidence quotes the file rather than a
	// re-rendering of it.
	Raw string `json:"raw"`
	// Source names the statement it came from, in the syntax the operator will
	// find in their file.
	Source string        `json:"source"`
	Syntax RsyslogSyntax `json:"syntax"`
	File   string        `json:"file"`
	Line   int           `json:"line"`
}

// FileCreateModes returns every statement that sets the creation mode of log
// files, from both syntaxes.
//
// All of them, not the last: legacy `$FileCreateMode` is positional and
// governs the file actions that follow it, so a permissive one applies to
// whatever comes after it regardless of what a later line says.
func (r Rsyslog) FileCreateModes() []RsyslogFileMode {
	var out []RsyslogFileMode

	for _, d := range r.Directives {
		if !strings.EqualFold(d.Name, "FileCreateMode") {
			continue
		}
		if m, ok := parseOctalMode(d.Value); ok {
			out = append(out, RsyslogFileMode{
				Mode: m, Raw: d.Value, Source: "$FileCreateMode", Syntax: SyntaxLegacyDirective,
				File: d.File, Line: d.Line,
			})
		}
	}

	for _, o := range r.Objects {
		v, ok := o.Param("filecreatemode")
		if !ok {
			continue
		}
		if m, ok := parseOctalMode(v); ok {
			out = append(out, RsyslogFileMode{
				Mode: m, Raw: v, Source: o.Kind + "(fileCreateMode=)", Syntax: SyntaxRainerScript,
				File: o.File, Line: o.Line,
			})
		}
	}
	return out
}

// parseOctalMode reads an rsyslog mode value, which is always octal and
// conventionally written with a leading zero.
func parseOctalMode(s string) (fs.FileMode, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(t, 8, 32)
	if err != nil {
		return 0, false
	}
	return fs.FileMode(n) & fs.ModePerm, true
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

// JournaldSetting is one key=value from a journald configuration file.
type JournaldSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	// Section is the INI section the setting appeared under, lowercased.
	// Anything outside [Journal] is recorded but does not take effect.
	Section string `json:"section,omitempty"`
}

// Journald is the parsed journald configuration.
type Journald struct {
	Installed bool     `json:"installed"`
	Files     []string `json:"files,omitempty"`
	// Settings are in read order: the main file first, then drop-ins in
	// lexical order. **The last occurrence wins**, which is the opposite of
	// sshd_config and is worth stating loudly — systemd drop-ins override the
	// main file, and a check that took the first match would report the value
	// the operator's drop-in was written to replace.
	Settings           []JournaldSetting `json:"settings,omitempty"`
	UnresolvedIncludes []string          `json:"unresolved_includes,omitempty"`
	Malformed          []JournaldSetting `json:"malformed,omitempty"`
	Digests            map[string]string `json:"digests,omitempty"`

	// PersistentDirState reports whether /var/log/journal exists, which is
	// what decides the meaning of Storage=auto — journald stores persistently
	// when the directory is present and volatilely when it is not.
	//
	// Without it, "Storage is not configured" would be unanswerable on the
	// large majority of hosts, because auto is the default and its effect is a
	// property of the filesystem rather than of the configuration. One stat
	// turns an UNKNOWN that nobody could act on into a verdict.
	PersistentDirState JournalDirState `json:"persistent_dir_state,omitempty"`
	PersistentDirPath  string          `json:"persistent_dir_path,omitempty"`
}

// JournalDirState is what the collector could observe about /var/log/journal.
//
// Three states rather than the four the CRON module uses, because the two ways
// of not knowing — refused, or a stat that failed oddly — lead to the same
// verdict here: the meaning of Storage=auto is undetermined either way.
type JournalDirState string

const (
	JournalDirPresent JournalDirState = "present"
	JournalDirAbsent  JournalDirState = "absent"
	// JournalDirUnknown covers a refused stat and any other failure. The zero
	// value is also this, so a fact decoded from an older bundle that never
	// recorded the field cannot be mistaken for a positive observation.
	JournalDirUnknown JournalDirState = ""
)

// StoresPersistently reports whether the journal survives a reboot, resolving
// Storage=auto against the directory's presence.
//
// The second return value is false when the answer cannot be determined: the
// keyword says auto (or is absent, which means auto) and the directory could
// not be stat'ed.
func (j Journald) StoresPersistently() (persistent bool, known bool) {
	mode := "auto"
	if s, ok := j.Effective("Storage"); ok {
		mode = strings.ToLower(strings.TrimSpace(s.Value))
	}
	switch mode {
	case "persistent":
		return true, true
	case "volatile", "none":
		return false, true
	case "auto":
		switch j.PersistentDirState {
		case JournalDirPresent:
			return true, true
		case JournalDirAbsent:
			return false, true
		default:
			return false, false
		}
	}
	// An unrecognised value: journald would refuse it, so nothing can be
	// concluded about what is running.
	return false, false
}

func (Journald) FactID() ID       { return JournaldID }
func (Journald) FactVersion() int { return 1 }

// Effective returns the setting that governs, following systemd's precedence:
// the last occurrence in read order wins. Keys are compared
// case-insensitively, as systemd compares them.
func (j Journald) Effective(key string) (JournaldSetting, bool) {
	var found JournaldSetting
	var ok bool
	for _, s := range j.Settings {
		if s.Section != "journal" {
			continue
		}
		if strings.EqualFold(s.Key, key) {
			found, ok = s, true
		}
	}
	return found, ok
}

// Overridden returns every occurrence of a key other than the effective one,
// so a finding can explain why the value in the main file is not the value in
// force.
func (j Journald) Overridden(key string) []JournaldSetting {
	var all []JournaldSetting
	for _, s := range j.Settings {
		if s.Section == "journal" && strings.EqualFold(s.Key, key) {
			all = append(all, s)
		}
	}
	if len(all) <= 1 {
		return nil
	}
	return all[:len(all)-1]
}

// BoolValue interprets a systemd boolean. systemd accepts yes/no, true/false,
// on/off and 1/0.
func BoolValue(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "on", "1":
		return true, true
	case "no", "false", "off", "0":
		return false, true
	}
	return false, false
}
