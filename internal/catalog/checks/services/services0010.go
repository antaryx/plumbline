package services

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0010 tests whether AppArmor is confining anything.
var Check0010 = catalog.Check{
	ID:     "SERVICES-0010",
	Module: "SERVICES",
	Title:  "AppArmor is enforcing at least one profile",

	Description: `Mandatory access control is the layer that survives the other
layers being wrong. Unix permissions decide what an account may do; a profile
decides what a *program* may do, whoever is running it. When a daemon is
compromised, the permissions of the account it runs as are exactly what the
attacker inherits, and a profile is the thing that says "this process reads
its configuration and writes its spool, and nothing else", regardless of what
the account would otherwise have been allowed.

**A profile in complain mode is not confinement.** complain logs the violation
and permits it: it exists so that a profile can be written by watching what a
program actually does. A host with two hundred profiles all in complain looks
protected to anything that counts profiles, and denies nothing. That is the
specific failure this check is shaped around, and it is a common state, it is
what a host that started a profiling exercise and never finished it looks
like.

**Absence of AppArmor is not a failure.** A RHEL or Fedora host confines
processes with SELinux and has no AppArmor at all; reporting that as a finding
would tell an operator to install a second mandatory-access-control layer
beside the one already running. The check reports NOT_APPLICABLE where neither
the kernel interface nor a profile directory exists.

**This asks what the kernel has loaded, which a mounted image cannot answer.**
/sys is a live kernel interface. Scanning an image establishes whether profiles
are installed on disk and nothing about whether any of them is in force, and
the check says so rather than drawing a verdict from the half it has.`,

	// High. It is not the first control an attacker meets, which is why it is
	// not Critical — but it is the one that decides how far a compromised
	// daemon gets, and a host running unconfined is a host where every
	// subsequent finding in this catalog is the whole of the defence.
	BaseSeverity: finding.High,
	Tags:         []string{"services", "apparmor", "mac", "hardening"},
	Requires:     []fact.ID{fact.AppArmorID},
	SinceCatalog: 34,

	Eval: func(fs *fact.Set) catalog.Outcome {
		a, _, _ := fact.Get[fact.AppArmor](fs, fact.AppArmorID)

		// Nothing to confine with. The host may be running SELinux, or may be
		// a container image with no LSM of its own.
		if !a.Installed() {
			return catalog.Outcome{
				Result:  finding.NotApplicable,
				Subject: "apparmor",
				Detail: "This kernel has no AppArmor and no profile directory is installed. " +
					"A host that confines processes with SELinux instead is correctly configured " +
					"and has nothing to answer here.",
			}
		}

		switch a.State {
		case fact.AppArmorDenied:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonPermission,
				Subject:       "apparmor",
				Detail:        "The AppArmor module parameter could not be read. Run as root.",
				Evidence:      []finding.Evidence{finding.NewEvidence(a.Path, 0, a.Msg, "")},
			}
		case fact.AppArmorError:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonParse,
				Subject:       "apparmor",
				Detail:        "The AppArmor module parameter could not be interpreted: " + a.Msg,
				Evidence:      []finding.Evidence{finding.NewEvidence(a.Path, 0, a.Msg, "")},
			}
		case fact.AppArmorDisabled:
			// Positive: we read the parameter and it says N. Nothing unread
			// can unmake that.
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "apparmor",
				Detail: fmt.Sprintf(
					"AppArmor is built into this kernel and switched off (%s reads N), with %d profile(s) "+
						"installed in %s. Nothing on this host is confined by a profile: every process has "+
						"whatever its account has, and the profiles on disk are applied to nothing.",
					a.Path, a.ProfileFiles, a.ProfileDir),
				Evidence: []finding.Evidence{finding.NewEvidence(a.Path, 0, "enabled: N", "")},
			}
		}

		// The LSM is enabled — or absent from the kernel interface while
		// profiles are installed, which is a mounted image. Either way the
		// question is now about what is loaded.
		switch a.ProfilesState {
		case fact.AppArmorDenied:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonPermission,
				Subject:       "apparmor",
				Detail: "AppArmor is enabled, and the loaded-profile list is root-only on this host. " +
					"Whether anything is actually enforced could not be established.",
				Evidence: []finding.Evidence{finding.NewEvidence(a.ProfilesPath, 0, a.ProfilesMsg, "")},
			}
		case fact.AppArmorAbsent:
			// **The mounted-image case, and it must not be a verdict.**
			// /sys is a live kernel interface, so an image has none. What is
			// on disk says nothing about what is loaded, and answering from
			// the disk half alone would report every image scan as confined or
			// as broken depending on which way the guess went.
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Subject:       "apparmor",
				Detail: fmt.Sprintf(
					"%s is not present, so what this kernel has loaded could not be read. "+
						"%d profile(s) are installed in %s, which says what is available and nothing "+
						"about what is in force. This is the expected result when scanning a mounted "+
						"image: ask the running host.",
					a.ProfilesPath, a.ProfileFiles, a.ProfileDir),
			}
		case fact.AppArmorError:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonParse,
				Subject:       "apparmor",
				Detail:        "The loaded-profile list could not be interpreted: " + a.ProfilesMsg,
				Evidence:      []finding.Evidence{finding.NewEvidence(a.ProfilesPath, 0, a.ProfilesMsg, "")},
			}
		}

		if a.Confined() > 0 {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: "apparmor",
				Detail: fmt.Sprintf(
					"AppArmor is enabled and %d of %d loaded profile(s) are enforcing (%s). Processes "+
						"matching those profiles are confined to what the profile permits, whatever their "+
						"account would otherwise allow.",
					a.Confined(), a.Loaded(), modeSummary(a)),
				Evidence: []finding.Evidence{
					finding.NewEvidence(a.ProfilesPath, 0, modeSummary(a), a.Digest),
				},
			}
		}

		// Enabled, and confining nothing. Two shapes, and they read
		// differently to an operator: profiles loaded but all permissive, and
		// no profiles at all.
		if a.Loaded() > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "apparmor",
				Detail: fmt.Sprintf(
					"AppArmor is enabled and none of its %d loaded profile(s) enforces anything (%s). "+
						"complain mode logs a violation and permits it — it exists so a profile can be "+
						"written by watching what a program does, and a host left in it is a host that "+
						"looks confined and denies nothing.%s",
					a.Loaded(), modeSummary(a), unconfiningNames(a)),
				Evidence: []finding.Evidence{
					finding.NewEvidence(a.ProfilesPath, 0, modeSummary(a), a.Digest),
				},
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: "apparmor",
			Detail: fmt.Sprintf(
				"AppArmor is enabled and has no profiles loaded, with %d installed in %s. The LSM is "+
					"running and confining nothing, which is the same exposure as having it switched off.",
				a.ProfileFiles, a.ProfileDir),
			Evidence: []finding.Evidence{
				finding.NewEvidence(a.ProfilesPath, 0, "no profiles loaded", a.Digest),
			},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Enable the apparmor service and put the installed profiles into enforce mode.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Check what is loaded and in what mode before changing anything: 'aa-status'. A host in complain mode is usually mid-way through writing profiles, and the person doing it will want to know.",
			"Start the service and have it load the installed profiles: 'systemctl enable --now apparmor'.",
			"Put a profile into enforce mode with 'aa-enforce /etc/apparmor.d/<profile>'. Move them one at a time on a host with running workloads: a profile written by observing a program under one workload denies what it did not see.",
			"If AppArmor is disabled at the kernel command line, none of the above takes effect until that is removed: look for 'apparmor=0' or a missing 'security=apparmor' in /etc/default/grub, then 'update-grub' and reboot.",
			"Read the denials after enforcing: 'journalctl -k | grep apparmor=\"DENIED\"'. A profile that denies something the program needs shows up here and nowhere else.",
		},
		Commands: []string{
			"aa-status",
			"systemctl enable --now apparmor",
			"aa-enforce /etc/apparmor.d/*",
		},
		Caution: "Enforcing a profile written in complain mode against a workload it never observed will deny that workload. Move profiles to enforce one at a time on a host doing real work, and read the kernel log afterwards, a denial is silent to the program except as a failure it may not report clearly.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-39"},
	},

	References: []finding.Reference{
		{Title: "apparmor(7)", URL: "https://man7.org/linux/man-pages/man7/apparmor.7.html"},
		{Title: "aa-enforce(8)", URL: "https://man7.org/linux/man-pages/man8/aa-enforce.8.html"},
	},
}

// modeSummary renders the loaded profiles by mode, in a fixed order.
func modeSummary(a fact.AppArmor) string {
	if a.Loaded() == 0 {
		return "no profiles loaded"
	}
	parts := make([]string, 0, len(a.Counts))
	for _, m := range a.Modes() {
		parts = append(parts, fmt.Sprintf("%d %s", a.Counts[m], m))
	}
	return strings.Join(parts, ", ")
}

// unconfiningNames names a few of the profiles that confine nothing, so the
// detail is recognisable rather than a count. The fact caps the sample; this
// says so when it was capped.
func unconfiningNames(a fact.AppArmor) string {
	if len(a.Unconfining) == 0 {
		return ""
	}
	names := make([]string, 0, len(a.Unconfining))
	for _, p := range a.Unconfining {
		names = append(names, p.Name)
	}
	out := " Among them: " + strings.Join(names, ", ")
	if a.Loaded()-a.Confined() > len(a.Unconfining) {
		out += fmt.Sprintf(", and %d more", a.Loaded()-a.Confined()-len(a.Unconfining))
	}
	return out + "."
}
