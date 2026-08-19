package logging

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests whether logs leave the host.
var Check0002 = catalog.Check{
	ID:     "LOGGING-0002",
	Module: "LOGGING",
	Title:  "Logs are forwarded to a remote collector",
	Description: `A log that only exists on the host it describes is not
evidence. It is a file the attacker who took the host can edit, truncate or
delete, and doing so is one of the first things any competent intrusion does —
before anybody knows to go looking. Every other check in this module protects a
record that a local-only configuration allows to be erased.

Forwarding changes what an attacker has to accomplish. To hide from a remote
collector they must compromise the collector too, or the network path to it, and
either is a second operation with its own noise. The forwarded copy is also what
makes correlation across hosts possible at all: an intrusion that touches five
machines is visible in the aggregate long before it is visible on any one of
them.

rsyslog expresses forwarding in either of its two languages, and this check
reads both:

    *.* @@logs.example.net:514                     legacy, TCP
    *.* @logs.example.net:514                      legacy, UDP
    action(type="omfwd" target="..." protocol="tcp")   RainerScript
    action(type="omrelp" target="...")                 RainerScript, RELP

A host that forwards is reported as passing whichever syntax it used. Whether
the transport it chose is reliable is LOGGING-0005's question.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"logging", "forensics", "tamper-resistance"},
	Requires:     []fact.ID{fact.RsyslogID},
	SinceCatalog: 8,

	Eval: func(fs *fact.Set) catalog.Outcome {
		r := rsyslogFact(fs)
		if !r.Installed {
			return rsyslogAbsent()
		}

		dests := r.RemoteDestinations()

		if len(dests) == 0 {
			// The FAIL rests on an absence, so an unresolved include makes it
			// unknowable: the forwarding rule may be in the file the include
			// was meant to reach. This is the same reasoning as the sshd
			// module's canonical UNKNOWN.
			if len(r.UnresolvedIncludes) > 0 {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Subject:       "remote logging",
					Detail: fmt.Sprintf(
						"No forwarding rule was found in the %d file(s) read, but %d include pattern(s) could not be resolved (%s). A forwarding rule may exist in a file this scan never saw.",
						len(r.Files), len(r.UnresolvedIncludes), strings.Join(r.UnresolvedIncludes, ", ")),
					Evidence: []finding.Evidence{primaryEvidence(r.Files, r.Digests,
						"unresolved include: "+strings.Join(r.UnresolvedIncludes, ", "))},
				}
			}
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "remote logging",
				Detail: fmt.Sprintf(
					"None of the %d rsyslog file(s) read configures a remote destination, in either the legacy '@host' form or a RainerScript omfwd or omrelp action. Every log this host writes exists only on this host, where an attacker who takes it can edit or delete the record of how they did so.",
					len(r.Files)),
				Evidence: []finding.Evidence{primaryEvidence(r.Files, r.Digests,
					"no '@' or '@@' rule and no omfwd/omrelp action in any file read")},
			}
		}

		var (
			described []string
			evidence  []finding.Evidence
		)
		for _, d := range dests {
			described = append(described, fmt.Sprintf("%s over %s (%s:%d)",
				d.Target, d.Protocol, d.File, d.Line))
			evidence = append(evidence, destEvidence(r, d, "remote destination"))
		}

		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"%d remote destination(s) are configured: %s. A copy of the log leaves this host, so erasing the local file no longer erases the record.",
				len(dests), strings.Join(described, "; ")),
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Configure a remote destination, using a reliable transport.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Decide where logs go before configuring anything, and confirm the collector will accept from this host — a forwarding rule pointing at a listener that drops the traffic is worse than none, because it looks configured.",
			"Prefer the RainerScript form on any rsyslog 8 host: 'action(type=\"omfwd\" target=\"logs.example.net\" port=\"514\" protocol=\"tcp\" queue.type=\"linkedlist\" queue.filename=\"fwd\" action.resumeRetryCount=\"-1\")'. The queue parameters are what let the host survive a collector outage without losing messages.",
			"The legacy equivalent is '*.* @@logs.example.net:514' — two at-signs for TCP, one for UDP. Both syntaxes work in the same file; use whichever the rest of the file uses rather than mixing.",
			"Encrypt it if the path is not trusted: rsyslog supports TLS through the gtls driver, and RELP with TLS is the sturdiest of the options.",
			"Verify end to end: 'logger -p auth.info plumbline-test' and confirm the line arrives at the collector. Do not assume it works because rsyslog restarted cleanly.",
		},
		Commands: []string{
			"grep -rEn '^\\*\\.\\*|omfwd|omrelp|@@' /etc/rsyslog.conf /etc/rsyslog.d/",
			"logger -p auth.info plumbline-test",
		},
		Caution: "Forwarding sends the contents of your logs — including authentication records and anything an application logged carelessly — across the network to another host. Confirm the transport is encrypted where the path is not trusted, and confirm the collector's own retention and access controls before pointing production hosts at it.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-9(2)"},
		{Framework: "nist-800-53-r5", Control: "AU-4"},
		{Framework: "nist-800-53-r5", Control: "AU-6"},
	},

	References: []finding.Reference{
		{Title: "rsyslog — omfwd", URL: "https://www.rsyslog.com/doc/configuration/modules/omfwd.html"},
	},
}
