package services

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0011 tests whether the audited services are sandboxed at the strict
// tier: the whole filesystem read-only, and home directories out of reach.
//
// **It sits above SERVICES-0007 and SERVICES-0008 rather than beside them**,
// and the tiering is the reason it is a third check instead of a stricter bar
// on the first two.
//
// SERVICES-0007 passes at any ProtectSystem other than `no`, which is the right
// bar for the question it asks — a daemon that cannot rewrite /usr cannot
// persist by replacing a binary, and `yes` delivers that. This asks the next
// question, and it is a materially different one: `yes` protects /usr, /boot
// and /efi, `full` adds /etc, and only `strict` mounts the *entire* hierarchy
// read-only and requires the daemon's writable paths to be declared. A host at
// `yes` is protected against the attack SERVICES-0007 describes and can still
// write /var, /srv and /opt.
//
// Raising SERVICES-0007's bar to `strict` instead would have moved a verdict on
// every host in the recorded corpus and turned a passing configuration into a
// failing one without anything changing on the machine. Two checks let a host
// see "protected, and not at the strongest tier", which is one finding and the
// true one.
var Check0011 = catalog.Check{
	ID:     "SERVICES-0011",
	Module: "SERVICES",
	Title:  "Audited system services are sandboxed at the strict tier",

	Description: `systemd's namespace directives come in levels, and the levels
are not degrees of the same thing.

**ProtectSystem** at ` + "`yes`" + ` mounts /usr, /boot and /efi read-only; at
` + "`full`" + ` it adds /etc; at ` + "`strict`" + ` the whole filesystem hierarchy is
read-only except /dev, /proc and /sys, and anything the daemon genuinely writes
has to be named in ReadWritePaths=, StateDirectory= or one of its siblings. The
first two stop a compromised daemon replacing a binary or a configuration file.
Only the third stops it writing anywhere at all, into /var/spool, into /srv,
into an application directory under /opt that nobody thought of.

**ProtectHome** at ` + "`yes`" + ` or ` + "`tmpfs`" + ` makes /home, /root and
/run/user empty and inaccessible. At ` + "`read-only`" + ` the contents are still
readable, which stops a daemon planting an authorized_keys file and does not
stop it stealing a private one. This check accepts read-only because it is a
real restriction and refusing it would push operators toward setting nothing;
the finding says which level each unit is at, so a reader can tell the two
apart.

**Declaring the writable paths is the work, and it is the point.** ` + "`strict`" +
		` is not a switch that can be flipped on a daemon nobody has profiled: a service
that writes a runtime file it never declared fails at the write, which surfaces
as the daemon misbehaving rather than as a unit that refuses to start. That is
why this is a separate finding from SERVICES-0007. The remediation is an
investigation, not a line.

This examines a fixed list of units. See SERVICES-0007 for why the list is
named rather than discovered: reading every unit on the host means reading
every unit *body*, and a bundle would then carry every ExecStart= and every
Environment= on the machine.`,

	// Medium, one below SERVICES-0007 and SERVICES-0008.
	//
	// **A host that fails this and passes those is already protected against
	// the attack the other two describe.** Its daemons cannot rewrite /usr and
	// cannot reach /home; what remains is the writable remainder of the
	// filesystem, which is a real exposure and a smaller one. Rating it level
	// with the checks it builds on would tell an operator that a hardened host
	// and an unsandboxed one have the same problem.
	BaseSeverity: finding.Medium,
	Tags:         []string{"services", "systemd", "sandbox", "hardening", "defence-in-depth"},
	Requires:     []fact.ID{fact.ServiceHardeningID},
	SinceCatalog: 34,

	Eval: func(fs *fact.Set) catalog.Outcome {
		h, _, _ := fact.Get[fact.ServiceHardening](fs, fact.ServiceHardeningID)

		if out := sandboxApplicable(h); out != nil {
			return *out
		}

		p := partitionUnits(h, strictExemptions, strictlySandboxed)

		var passed []string
		for _, s := range p.passed {
			passed = append(passed, fmt.Sprintf("%s (%s, ProtectHome=%s)",
				s.Unit, s.SystemProtection(), s.HomeProtection()))
		}

		// ADR-0014: a unit that was read and is not at the strict tier is a
		// finding whatever else went unread.
		if len(p.failed) > 0 {
			var (
				names []string
				ev    []finding.Evidence
			)
			for _, s := range p.failed {
				names = append(names, fmt.Sprintf("%s (ProtectSystem=%s, ProtectHome=%s)",
					s.Unit, s.SystemProtection(), s.HomeProtection()))
				ev = append(ev, protectUnitEvidence(s))
			}
			detail := fmt.Sprintf(
				"%d audited service%s not sandboxed at the strict tier: %s. Each can still write "+
					"somewhere outside /usr — /var, /srv, /opt or an application directory — or can still "+
					"reach a home directory. %s",
				len(p.failed), plural(len(p.failed), " is", "s are"), join(names), strictWorkNote)
			// The masked and exempted units are named on every verdict, not
			// only on the passing ones: a FAIL that listed two units and stayed
			// silent about a third that was masked would read as a complete
			// account of the host's audited services.
			if len(p.masked) > 0 {
				detail += fmt.Sprintf(" %s %s masked and %s not examined: systemd will not start %s.",
					join(p.masked), plural(len(p.masked), "is", "are"),
					plural(len(p.masked), "is", "are"), plural(len(p.masked), "it", "them"))
			}
			detail += strictExemptions.sentence(p.skipped)
			return catalog.Outcome{
				Result:   finding.Fail,
				Detail:   detail + strictCaveat,
				Evidence: ev,
			}
		}

		if len(p.unread) > 0 {
			var ev []finding.Evidence
			for _, s := range p.unread {
				ev = append(ev, protectUnitEvidence(s))
			}
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonPermission,
				Detail: fmt.Sprintf(
					"%d audited unit file could not be read, so whether every service is at the strict tier "+
						"could not be established.%s", len(p.unread), strictCaveat),
				Evidence: ev,
			}
		}

		// Nothing was verified. The same reasoning SERVICES-0006 states: an
		// exemption list must be able to make a check stop claiming things,
		// never start claiming everything.
		if len(passed) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"No unit on this host was held to this standard: of the units this check audits, %s.%s "+
						"This is the check reporting that it had nothing to examine, not that the host satisfied it.%s",
					describeUnverified(p.skipped, p.masked), strictExemptions.sentence(p.skipped), strictCaveat),
				Evidence: sandboxEvidence(h, p.skipped),
			}
		}

		detail := fmt.Sprintf(
			"%d of the %d audited service%s installed here %s at the strict tier: %s. Their filesystem is "+
				"read-only apart from the paths their unit declares, and home directories are out of reach.",
			len(passed), len(h.Installed()), plural(len(h.Installed()), "", "s"),
			plural(len(passed), "is", "are"), join(passed))
		if len(p.masked) > 0 {
			detail += fmt.Sprintf(" %s %s masked and %s not examined.",
				join(p.masked), plural(len(p.masked), "is", "are"), plural(len(p.masked), "is", "are"))
		}
		detail += strictExemptions.sentence(p.skipped) + strictCaveat
		return catalog.Outcome{
			Result:   finding.Pass,
			Detail:   detail,
			Evidence: protectEvidence(h, passed, p.skipped),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Add ProtectSystem=strict and ProtectHome=yes in a drop-in, after establishing what each service writes.",
		Effort:  "HIGH",
		Steps: []string{
			"**Find out what the service writes before you restrict it.** 'systemd-analyze filesystems <unit>' and 'systemctl show <unit> -p ReadWritePaths,StateDirectory,LogsDirectory,RuntimeDirectory' say what it already declares; the package's own upstream unit is usually the best statement of what it needs.",
			"Create the drop-in rather than editing the shipped unit: 'systemctl edit <unit>'. A package upgrade replaces /usr/lib/systemd/system/<unit> and leaves /etc/systemd/system/<unit>.d/ alone.",
			"Set ProtectSystem=strict and ProtectHome=yes, then declare every path the service legitimately writes with ReadWritePaths=, or better with StateDirectory= and LogsDirectory=, which create the directory with the right ownership as well as permitting it.",
			"'systemctl daemon-reload' and then restart the service, and watch it do its actual work rather than only checking that it started. A missing ReadWritePaths= shows up when the daemon first writes, which may be hours later.",
			"'systemd-analyze security <unit>' scores the result and names what is still open.",
		},
		Commands: []string{
			"systemd-analyze security <unit>",
			"systemctl edit <unit>",
			"systemctl daemon-reload",
		},
		Caution: "ProtectSystem=strict makes the entire filesystem read-only except what the unit declares, and a service that writes an undeclared path fails at the write rather than at the restart, so the failure appears as the daemon misbehaving, possibly long after the change. Establish what the service needs to write before applying this, and restart it under real load rather than only checking that it comes up. ProtectHome=yes hides /home and /root entirely: anything that reads a user's file, a key or a script from there stops working.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SC-39"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "systemd.exec(5). ProtectSystem", URL: "https://man7.org/linux/man-pages/man5/systemd.exec.5.html"},
		{Title: "systemd-analyze(1), security", URL: "https://man7.org/linux/man-pages/man1/systemd-analyze.1.html"},
	},
}

// strictlySandboxed is this check's bar: the whole hierarchy read-only, and
// home directories restricted.
//
// ProtectHome=read-only counts. It is a real restriction — a daemon cannot
// plant an authorized_keys file — and refusing it would push an operator
// toward setting nothing at all. The finding names the level each unit is at,
// so a reader can tell it from `yes`.
func strictlySandboxed(s fact.ServiceSandbox) bool {
	return s.SystemProtection() == fact.ProtectStrict && s.HomeProtected()
}

// strictExemptions carries SERVICES-0007's and SERVICES-0008's exemption, for
// the reason both of them state: cron runs operator-supplied jobs, and a
// read-only filesystem or an inaccessible /home is a restriction on code the
// packager never saw.
//
// **A unit exempt from the weaker check cannot be held to the stronger one.**
var strictExemptions = exemptions{
	{
		unit: "cron.service",
		reason: "runs arbitrary operator-supplied jobs inside its own mount namespace, so a read-only filesystem " +
			"or an inaccessible home directory becomes a restriction on code the packager never saw — the job " +
			"fails, and fails at the job rather than at the restart",
	},
}

// strictWorkNote is the sentence that keeps this finding honest about its own
// remediation.
//
// **Step 2 of this check's requirement, and it belongs in the verdict rather
// than only in the documentation.** An operator reading a FAIL on a scrolling
// terminal may never open the reference page, and `ProtectSystem=strict`
// applied to a daemon nobody has profiled fails at the write — as the service
// misbehaving hours later, not as a unit that refuses to start.
const strictWorkNote = "Establish what each service legitimately writes before applying this: " +
	"under strict, an undeclared path fails at the write rather than at the restart, so a service " +
	"that needs /var or /srv breaks in a way that surfaces as misbehaviour rather than as a failed start. " +
	"'systemd-analyze filesystems' and the package's upstream unit are where that answer is."

// strictCaveat is appended to every verdict this check draws.
const strictCaveat = " This examines ProtectSystem and ProtectHome on a fixed list of units. It says nothing " +
	"about the other services on this host, nor about the other sandboxing directives on these ones, nor about " +
	"what a ReadWritePaths= or a BindPaths= has opened up again — which under strict is where the whole of the " +
	"service's writable surface is declared."
