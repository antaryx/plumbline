package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// idleTimeoutLimit is the longest effective idle timeout this check accepts,
// in seconds. Fifteen minutes is the CIS figure and the common regulatory one.
const idleTimeoutLimit = 900

// Check0007 tests whether idle SSH sessions are dropped.
//
// It reads two keywords rather than one because neither means anything alone.
// ClientAliveInterval 300 with ClientAliveCountMax 0 never disconnects, and
// ClientAliveCountMax 3 with ClientAliveInterval 0 never probes; a check that
// looked at either in isolation would report a host with no idle timeout as
// configured. The proposition is the product, so the check is the product.
var Check0007 = catalog.Check{
	ID:     "SSHD-0007",
	Module: "SSHD",
	Title:  "Idle SSH sessions are disconnected",
	Description: `An SSH session that is idle is a session nobody is watching.
The laptop is closed, the terminal is behind a browser window, the desk is
empty — and the session is still authenticated, still authorised, and still
able to run anything the user can run. That is the exposure an idle timeout
closes: not an attack on the protocol, but the ordinary case of an unattended
authenticated shell.

Two keywords produce the timeout together. ClientAliveInterval is how often
sshd sends an encrypted keepalive when the channel has been silent;
ClientAliveCountMax is how many go unanswered before the connection is dropped.
The effective idle timeout is their product, and each has a value that disables
the mechanism outright: an interval of 0 means no probe is ever sent, and a
count of 0 means the connection is never terminated no matter how many probes
go unanswered.

The OpenSSH defaults are interval 0 and count 3 — no timeout at all. This check
requires both to be positive and their product to be at most 15 minutes.

Note that this is not the same as TMOUT in the shell. TMOUT ends the shell; the
client-alive mechanism ends the connection, which also covers port forwards and
sessions where no shell was ever started.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "session-management"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: func(fs *fact.Set) catalog.Outcome {
		cfg := configFact(fs)
		if !cfg.Installed {
			return notApplicable()
		}
		// As in SSHD-0002: this check reads two keywords and so cannot use
		// evaluate(), which means it carries the shared gates itself.
		if len(cfg.SyntaxErrors) > 0 {
			return syntaxError(cfg, "ClientAliveInterval")
		}

		interval, iOK := cfg.Effective("ClientAliveInterval")
		count, cOK := cfg.Effective("ClientAliveCountMax")

		// Either keyword could be sitting in a file the Include never
		// resolved, and the timeout is the product of both — so an unresolved
		// Include makes the whole proposition undeterminable, not half of it.
		if (!iOK || !cOK) && len(cfg.UnresolvedIncludes) > 0 {
			var missing []string
			if !iOK {
				missing = append(missing, "ClientAliveInterval")
			}
			if !cOK {
				missing = append(missing, "ClientAliveCountMax")
			}
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Detail: fmt.Sprintf(
					"%s is not set in any readable file, but %d Include directive(s) could not be resolved (%s); the effective idle timeout is the product of both keywords and cannot be determined.",
					strings.Join(missing, " and "), len(cfg.UnresolvedIncludes),
					strings.Join(cfg.UnresolvedIncludes, ", ")),
				Evidence: []finding.Evidence{primaryEvidence(cfg,
					"unresolved Include: "+strings.Join(cfg.UnresolvedIncludes, ", "))},
			}
		}

		intervalN, intervalWhere, out := resolveIdleValue(cfg, "ClientAliveInterval", interval, iOK, defaultClientAliveInterval)
		if out != nil {
			return *out
		}
		countN, countWhere, out := resolveIdleValue(cfg, "ClientAliveCountMax", count, cOK, defaultClientAliveCountMax)
		if out != nil {
			return *out
		}

		var ev []finding.Evidence
		if iOK {
			ev = append(ev, directiveEvidence(cfg, interval))
		} else {
			ev = append(ev, primaryEvidence(cfg, fmt.Sprintf(
				"ClientAliveInterval not present in any parsed file; built-in default %d applies",
				defaultClientAliveInterval)))
		}
		if cOK {
			ev = append(ev, directiveEvidence(cfg, count))
		} else {
			ev = append(ev, primaryEvidence(cfg, fmt.Sprintf(
				"ClientAliveCountMax not present in any parsed file; built-in default %d applies",
				defaultClientAliveCountMax)))
		}
		ev = append(ev, matchScopedEvidence(cfg, "ClientAliveInterval")...)
		ev = append(ev, matchScopedEvidence(cfg, "ClientAliveCountMax")...)

		switch {
		case intervalN <= 0:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "ClientAliveInterval",
				Detail: fmt.Sprintf(
					"ClientAliveInterval is %s, so sshd never probes an idle connection and no session is ever timed out. An authenticated session left unattended stays authenticated indefinitely.",
					intervalWhere),
				Evidence: ev,
			}

		case countN <= 0:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "ClientAliveCountMax",
				Detail: fmt.Sprintf(
					"ClientAliveCountMax is %s, which disables connection termination outright: sshd probes every %d second(s) and never acts on the silence. This is the configuration that most often looks correct — the interval is set, so the setting appears present — while producing no timeout at all.",
					countWhere, intervalN),
				Evidence: ev,
			}

		case intervalN*countN > idleTimeoutLimit:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "ClientAliveInterval",
				Detail: fmt.Sprintf(
					"The effective idle timeout is %d second(s) — ClientAliveInterval %s multiplied by ClientAliveCountMax %s — which exceeds the %d second limit this check applies. An unattended authenticated session stays usable for that long.",
					intervalN*countN, intervalWhere, countWhere, idleTimeoutLimit),
				Evidence: ev,
			}
		}

		// A Match block can disable the timeout for a subset of connections
		// through either keyword.
		loosened := append(
			loosenedInMatch(cfg, "ClientAliveInterval", func(v string) bool {
				n, ok := parseInt(v)
				return ok && (n <= 0 || n*countN > idleTimeoutLimit)
			}),
			loosenedInMatch(cfg, "ClientAliveCountMax", func(v string) bool {
				n, ok := parseInt(v)
				return ok && (n <= 0 || n*intervalN > idleTimeoutLimit)
			})...)
		if len(loosened) > 0 {
			return conditionalFail(cfg, "ClientAliveInterval",
				fmt.Sprintf("configured globally for a %d second idle timeout", intervalN*countN),
				ev[0], loosened, finding.Medium,
				"Sessions matching those blocks are not timed out on the schedule the global setting implies.")
		}

		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"Idle sessions are disconnected after %d second(s): ClientAliveInterval %s multiplied by ClientAliveCountMax %s, within the %d second limit.",
				intervalN*countN, intervalWhere, countWhere, idleTimeoutLimit),
			Evidence: ev,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set ClientAliveInterval 300 and ClientAliveCountMax 3, and check that neither is zero.",
		Effort:  "LOW",
		Steps: []string{
			"Set both in /etc/ssh/sshd_config: 'ClientAliveInterval 300' and 'ClientAliveCountMax 3'. That is a 15-minute idle timeout.",
			"Check specifically that ClientAliveCountMax is not 0. A zero there disables termination entirely while leaving the configuration looking as though a timeout is in force — it is the most common way this setting is wrong.",
			"Confirm the effective values rather than the file: 'sshd -T | grep -i clientalive' resolves Include directives and Match defaults.",
			"Consider TMOUT in /etc/profile.d/ as well. It ends an idle shell; this setting ends an idle connection, and they cover different cases — a session with a port forward and no shell is only covered by this one.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i clientalive",
		},
		Caution: "Long-running work started in a foreground shell — a database migration, a large rsync — will be killed when the connection drops. Tell users to run such work under tmux or screen before shortening the timeout, or the first casualty will be a job somebody has been running for six hours.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-11"},
		{Framework: "nist-800-53-r5", Control: "AC-12"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — ClientAliveInterval", URL: "https://man.openbsd.org/sshd_config#ClientAliveInterval"},
		{Title: "sshd_config(5) — ClientAliveCountMax", URL: "https://man.openbsd.org/sshd_config#ClientAliveCountMax"},
	},
}

// resolveIdleValue reads one of the two keywords, returning its value and a
// phrase describing where it came from. A non-nil outcome means the value
// could not be read and the check must stop there.
func resolveIdleValue(
	cfg fact.SSHDConfig, keyword string, d fact.Directive, found bool, def int,
) (int, string, *catalog.Outcome) {
	if !found {
		return def, fmt.Sprintf("%d by sshd's built-in default (the keyword is not configured)", def), nil
	}
	n, ok := parseInt(d.Value)
	if !ok {
		out := catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonParse,
			Subject:       keyword,
			Detail: fmt.Sprintf(
				"%s has unreadable value %q at %s:%d; sshd accepts a whole number here and would reject this configuration, so the running server may be using a different file.",
				keyword, d.Value, d.File, d.Line),
			Evidence: []finding.Evidence{directiveEvidence(cfg, d)},
		}
		return 0, "", &out
	}
	return n, fmt.Sprintf("%d at %s:%d", n, d.File, d.Line), nil
}
