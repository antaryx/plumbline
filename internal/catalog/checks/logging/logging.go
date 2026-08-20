// Package logging holds the LOGGING module's checks.
//
// The module asks one question in five ways: **when this host is compromised,
// what will still be readable, and by whom?** A local log is deleted by
// whoever takes the host; a world-readable log hands an attacker the schedule
// of everything else; a log forwarded over UDP is dropped at exactly the moment
// load spikes, which is exactly the moment worth recording.
//
// Two daemons, two facts, and a host may run either, both or neither. Checks
// that need rsyslog return NOT_APPLICABLE when it is absent rather than FAIL —
// a host running only journald has not failed to secure rsyslog, it does not
// have one.
package logging

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// rsyslogFact and journaldFact read the module's facts. The runner's
// required-fact gate guarantees they are present and typed before Eval runs.
func rsyslogFact(fs *fact.Set) fact.Rsyslog {
	r, _, _ := fact.Get[fact.Rsyslog](fs, fact.RsyslogID)
	return r
}

func journaldFact(fs *fact.Set) fact.Journald {
	j, _, _ := fact.Get[fact.Journald](fs, fact.JournaldID)
	return j
}

// rsyslogAbsent is the verdict when no rsyslog configuration exists.
func rsyslogAbsent() catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: "No rsyslog configuration found; this host does not run rsyslog. Where journald is the only log daemon, LOGGING-0003 and LOGGING-0004 are the checks that apply.",
	}
}

// journaldAbsent is the verdict when no journald configuration or journal
// directory exists.
func journaldAbsent() catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: "No journald configuration or journal directory found; this host does not appear to run systemd-journald.",
	}
}

// primaryEvidence cites a configuration file with no particular line, for
// statements about what is *not* in it.
func primaryEvidence(files []string, digests map[string]string, excerpt string) finding.Evidence {
	var file string
	if len(files) > 0 {
		file = files[0]
	}
	return finding.NewEvidence(file, 0, excerpt, digests[file])
}

// unresolvedRsyslog converts a would-be negative result into UNKNOWN when an
// include did not resolve.
//
// The same asymmetry as everywhere else in this project: a positive result
// stands — a permissive mode we read is permissive whatever else is missing —
// and only the negative one becomes unknowable, because the statement a check
// is looking for may sit in the file the include was meant to reach.
func unresolvedRsyslog(r fact.Rsyslog, subject string, pass catalog.Outcome) catalog.Outcome {
	if pass.Result != finding.Pass && pass.Result != finding.Fail {
		return pass
	}
	if len(r.UnresolvedIncludes) == 0 {
		return pass
	}
	// A FAIL drawn from a statement we did read is not weakened by a file we
	// did not.
	if pass.Result == finding.Fail {
		return pass
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: finding.ReasonAmbiguousState,
		Subject:       subject,
		Detail: fmt.Sprintf(
			"No violation was found in the %d file(s) that were read, but %d include pattern(s) could not be resolved (%s). The statement this check looks for may be in a file this scan never saw.",
			len(r.Files), len(r.UnresolvedIncludes), strings.Join(r.UnresolvedIncludes, ", ")),
		Evidence: []finding.Evidence{primaryEvidence(r.Files, r.Digests,
			"unresolved include: "+strings.Join(r.UnresolvedIncludes, ", "))},
	}
}

// ruleEvidence cites a statement in whichever syntax it was written in.
//
// Quoting the operator's own language back to them is not cosmetic. A host
// whose file says `*.* @@logs.example.net` and whose finding talks about
// `action(type="omfwd")` sends its reader looking for a line that is not
// there, and at that point they stop trusting the tool.
func destEvidence(r fact.Rsyslog, d fact.RemoteDest, note string) finding.Evidence {
	return finding.NewEvidence(d.File, d.Line,
		fmt.Sprintf("%s  (%s syntax; %s)", d.Raw, d.Syntax, note), r.Digests[d.File])
}

func modeEvidence(r fact.Rsyslog, m fact.RsyslogFileMode, note string) finding.Evidence {
	return finding.NewEvidence(m.File, m.Line,
		fmt.Sprintf("%s %s  (%s syntax; %s)", m.Source, m.Raw, m.Syntax, note), r.Digests[m.File])
}

func settingEvidence(j fact.Journald, s fact.JournaldSetting, note string) finding.Evidence {
	return finding.NewEvidence(s.File, s.Line,
		fmt.Sprintf("%s=%s  (%s)", s.Key, s.Value, note), j.Digests[s.File])
}

// overriddenEvidence cites the occurrences of a journald key that a later
// drop-in replaced, so a reader who edited the main file understands why the
// value they set is not the value reported.
func overriddenEvidence(j fact.Journald, key string) []finding.Evidence {
	var out []finding.Evidence
	for _, s := range j.Overridden(key) {
		out = append(out, settingEvidence(j, s,
			"overridden by a later drop-in; systemd applies the last occurrence, not the first"))
	}
	return out
}

// normalise lowercases and trims a configuration value for comparison.
func normalise(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
