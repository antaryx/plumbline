package logging

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests the transport the remote destinations use.
var Check0005 = catalog.Check{
	ID:     "LOGGING-0005",
	Module: "LOGGING",
	Title:  "Remote log forwarding uses a reliable transport",
	Description: `Forwarding over UDP drops messages silently, and it drops
them hardest under load — which is precisely the condition that produces the
logs worth keeping. A host under attack generates a burst of authentication
failures, and a UDP forwarder discards whatever the socket buffer cannot hold,
with no error anywhere and no gap that anything downstream can detect. The
collector receives a plausible-looking stream that is missing the interesting
part.

Two further properties make UDP the wrong choice here. It is connectionless, so
a collector that is down produces no failure on the sending side at all — the
host carries on believing it is forwarding. And it is trivially spoofable: an
attacker on the path can inject records that the collector will attribute to
this host, which turns the log from evidence into something an adversary can
write to.

TCP fixes the silent-loss problem and makes an unreachable collector visible.
RELP fixes the remaining gap — TCP acknowledges receipt by the kernel, RELP
acknowledges processing by the application — and is the right answer where the
log is genuinely evidentiary.

**Where the protocol is not stated, this check treats it as UDP**, because
that is omfwd's documented default. That is reporting a stable documented
scalar rather than guessing at a compiled-in value, and the finding says which
it is doing.

This check is NOT_APPLICABLE where no remote destination is configured at all.
That absence is LOGGING-0002's finding, reported once rather than twice under
two names.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"logging", "forensics", "network", "tamper-resistance"},
	Requires:     []fact.ID{fact.RsyslogID},
	SinceCatalog: 8,

	Eval: func(fs *fact.Set) catalog.Outcome {
		r := rsyslogFact(fs)
		if !r.Installed {
			return rsyslogAbsent()
		}

		dests := r.RemoteDestinations()
		if len(dests) == 0 {
			// NOT_APPLICABLE is a claim that no destination exists, and an
			// unresolved include makes that claim unsupportable in exactly the
			// way a PASS would be: the destination may be in the file the
			// include was meant to reach.
			if len(r.UnresolvedIncludes) > 0 {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Subject:       "remote logging transport",
					Detail: fmt.Sprintf(
						"No remote destination was found in the %d file(s) read, but %d include pattern(s) could not be resolved (%s), so it cannot be established that there is no transport to assess.",
						len(r.Files), len(r.UnresolvedIncludes), strings.Join(r.UnresolvedIncludes, ", ")),
					Evidence: []finding.Evidence{primaryEvidence(r.Files, r.Digests,
						"unresolved include: "+strings.Join(r.UnresolvedIncludes, ", "))},
				}
			}
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "No remote destination is configured, so there is no transport to assess. LOGGING-0002 reports the absence itself.",
			}
		}

		var (
			unreliable []string
			subjects   []string
			evidence   []finding.Evidence
		)
		for _, d := range dests {
			if d.Reliable() {
				continue
			}
			what := fmt.Sprintf("%s at %s:%d forwards over UDP", d.Target, d.File, d.Line)
			note := "UDP: messages are dropped silently under load and a dead collector produces no error"
			if d.Protocol == fact.ProtoUnknown {
				what = fmt.Sprintf("%s at %s:%d does not state a protocol, and omfwd's documented default is UDP",
					d.Target, d.File, d.Line)
				note = "protocol not stated; omfwd defaults to UDP"
			}
			unreliable = append(unreliable, what)
			subjects = append(subjects, d.Target)
			evidence = append(evidence, destEvidence(r, d, note))
		}

		if len(unreliable) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: strings.Join(subjects, ", "),
				Detail: fmt.Sprintf(
					"%d of the %d remote destination(s) do not use a reliable transport: %s. UDP discards whatever the socket buffer cannot hold, with no error on either side — so the burst of authentication failures that accompanies an attack is exactly what goes missing, and the collector receives a stream that looks complete.",
					len(unreliable), len(dests), strings.Join(unreliable, "; ")),
				Evidence: evidence,
			}
		}

		var described []string
		for _, d := range dests {
			described = append(described, fmt.Sprintf("%s over %s", d.Target, d.Protocol))
			evidence = append(evidence, destEvidence(r, d, "reliable transport"))
		}
		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d remote destination(s) use a reliable transport: %s. Loss is visible rather than silent, and an unreachable collector produces an error on this host rather than nothing at all.",
				len(dests), strings.Join(described, "; ")),
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Move the destination to TCP or RELP, and give it a disk-assisted queue.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Confirm the collector accepts the new transport before changing the sender. A collector listening only on UDP/514 will simply stop receiving, and — because UDP fails silently — nobody will notice until somebody goes looking for a log.",
			"Legacy syntax: change the single '@' to '@@'. '*.* @@logs.example.net:514'.",
			"RainerScript: set 'protocol=\"tcp\"' on the omfwd action, or switch to 'action(type=\"omrelp\" target=\"...\" port=\"2514\")' where the collector supports RELP.",
			"Add a queue, or TCP only moves the loss rather than removing it: 'queue.type=\"linkedlist\" queue.filename=\"fwd\" queue.maxdiskspace=\"1g\" action.resumeRetryCount=\"-1\"' lets the host buffer to disk through a collector outage instead of discarding.",
			"Verify by stopping the collector briefly and confirming this host queues rather than drops, then restarting it and confirming the backlog arrives.",
		},
		Commands: []string{
			"grep -rEn '@@?[a-zA-Z0-9]|omfwd|omrelp' /etc/rsyslog.conf /etc/rsyslog.d/",
			"ss -tnp | grep :514",
		},
		Caution: "TCP forwarding without a queue can block rsyslog when the collector is slow or unreachable, which on some configurations blocks the applications writing to it. Configure a disk-assisted queue and a resume-retry count in the same change — moving to TCP without one trades silent loss for an availability risk.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-9(2)"},
		{Framework: "nist-800-53-r5", Control: "AU-4"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
	},

	References: []finding.Reference{
		{Title: "rsyslog — omfwd", URL: "https://www.rsyslog.com/doc/configuration/modules/omfwd.html"},
		{Title: "RFC 5424 — The Syslog Protocol", URL: "https://www.rfc-editor.org/rfc/rfc5424"},
	},
}
