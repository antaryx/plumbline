package remediate

import (
	"strings"

	"github.com/antaryx/plumbline/internal/fact"

	"github.com/antaryx/plumbline/internal/finding"
)

// apparmorFix starts AppArmor and puts the installed profiles into enforce
// mode.
//
// **The two steps answer two different findings and both are emitted.** A host
// with AppArmor switched off needs the service; a host with the service running
// and every profile in complain needs `aa-enforce`. The check reports both as
// one FAIL, so the script does both — each is a no-op on the host that only had
// the other problem, which is what keeps a single action correct for both.
type apparmorFix struct{}

func (apparmorFix) CheckID() string { return "SERVICES-0010" }

func (apparmorFix) Build(f finding.Finding, _ Options) (Action, bool) {
	a := Action{
		CheckID: "SERVICES-0010",
		Title:   titleOf(f, "AppArmor is enforcing at least one profile"),
	}

	note(&a, "**Read aa-status first.** A host with profiles in complain mode is usually")
	note(&a, "mid-way through writing them by watching what a program does, and enforcing")
	note(&a, "a profile against a workload it never observed will deny that workload.")
	note(&a, "On a host doing real work, move profiles one at a time instead of running")
	note(&a, "the aa-enforce line below, then read the denials:")
	note(&a, "  journalctl -k | grep 'apparmor=\"DENIED\"'")

	// **Not `systemctl start`.** enable makes it survive a reboot and start
	// now; a host whose confinement disappears at the next restart has been
	// remediated for as long as nobody power-cycles it.
	command(&a, "systemctl", "enable", "--now", "apparmor")

	// **aa-enforce ships in apparmor-utils, which a minimal host does not
	// install**, and the kernel module being active says nothing about the
	// tooling being present. Unguarded this was worse than a confusing message:
	// the script runs under `set -eu`, so a missing binary exits 127 and takes
	// every action sorted after SERVICES-0010 with it — the operator loses the
	// rest of the run to a package that was never there.
	//
	// The glob is a shell glob and is deliberate: aa-enforce takes profile
	// paths, and the set of profiles installed is what the package manager put
	// there rather than something plumbline should enumerate from a scan that
	// may be hours old. Enforcing a profile that is already enforcing is a
	// no-op, which is what makes this idempotent.
	literal(&a, `if command -v aa-enforce >/dev/null 2>&1; then`)
	literal(&a, "\taa-enforce /etc/apparmor.d/*")
	literal(&a, `else`)
	literal(&a, `	echo "plumbline: aa-enforce not found; install apparmor-utils to enforce the profiles, then run:" >&2`)
	literal(&a, `	echo "plumbline:   aa-enforce /etc/apparmor.d/*" >&2`)
	literal(&a, `fi`)

	// **The kernel command line is the one thing neither command can fix**, and
	// a script that silently left the host unconfined would be worse than one
	// that says so. This is a check, not a change: it prints and does not edit
	// grub, because rewriting a boot configuration from a heuristic is how a
	// machine stops booting.
	literal(&a, `if grep -qE '(^|[[:space:]])apparmor=0([[:space:]]|$)' /proc/cmdline; then`)
	literal(&a, `	echo "plumbline: apparmor=0 is on the kernel command line; the above will not take effect." >&2`)
	literal(&a, `	echo "plumbline: remove it from GRUB_CMDLINE_LINUX in /etc/default/grub, run update-grub, reboot." >&2`)
	literal(&a, `fi`)

	return a, true
}

// ufwFix enables ufw with a default-deny inbound policy.
//
// **It declines a host that is not using ufw**, and that refusal is the point.
// A host whose firewall is nftables or firewalld already has a manager; running
// `ufw enable` beside it produces exactly the two-managers-one-ruleset state
// NETWORK-0003 exists to report, in which the manager that ran last flushes
// what the other installed and whoever maintains the loser's file is editing
// something with no effect.
type ufwFix struct {
	checkID string
	title   string
}

func (u ufwFix) CheckID() string { return u.checkID }

func (u ufwFix) Build(f finding.Finding, _ Options) (Action, bool) {
	other := otherFirewall(f)
	if other != "" {
		// Declined rather than emitted with a warning. This one cannot be made
		// safe by a comment: an operator who ran it would have two managers
		// fighting over the kernel's ruleset, and the failure shows up as
		// intermittent connectivity rather than as an error.
		return Action{}, false
	}

	a := Action{CheckID: u.checkID, Title: titleOf(f, u.title)}

	note(&a, "**This will disconnect you if you are on SSH and port 22 is not allowed.**")
	note(&a, "The allow rule below is why it is here, and 22/tcp is a guess: plumbline")
	note(&a, "knows this host's real sshd port from the SSHD module, and this finding does")
	note(&a, "not carry it. Change the port, or delete the line on a host with no SSH.")
	note(&a, "ufw is proposed because nothing else is configured here; on a host that")
	note(&a, "already uses nftables or firewalld, fix that ruleset instead.")

	command(&a, "ufw", "allow", "22/tcp")
	command(&a, "ufw", "default", "deny", "incoming")
	command(&a, "ufw", "default", "allow", "outgoing")
	// --force because `ufw enable` prompts, and a script that blocks on a
	// prompt inside a pipeline hangs rather than fails. Enabling an already
	// enabled ufw re-applies the rules and changes nothing else.
	command(&a, "ufw", "--force", "enable")

	return a, true
}

// otherFirewall names the non-ufw firewall a finding cited, or "" when the
// finding is about ufw or about nothing being configured at all.
//
// **It reads the evidence rather than the paths alone, and the first version of
// this did not — which was a bug worth keeping the shape of.** A "no firewall
// anywhere" finding cites *every* candidate the collector probed, each with an
// excerpt saying it does not exist, so a rule that matched `/etc/nftables.conf`
// in the path list declined the one host the ufw fix is unambiguously right
// for. Presence has to be read, not the fact that the collector looked.
//
// The check's evidence is the only place that distinction reaches a finding,
// so this reads its excerpt — a display string belonging to another package,
// which is a coupling, and is why the default runs the safe way: an excerpt
// this does not recognise counts as *present*. A format change therefore makes
// the fix decline more often, and declining is the harmless direction.
func otherFirewall(f finding.Finding) string {
	for _, e := range f.Evidence {
		if !sourceFound(e) {
			continue
		}
		switch {
		case strings.Contains(e.Source, "/ufw"):
			// ufw's own files. Not another manager.
		case strings.Contains(e.Source, "nftables"):
			return "nftables"
		case strings.Contains(e.Source, "iptables"):
			return "iptables"
		case strings.Contains(e.Source, "firewalld"):
			return "firewalld"
		}
	}
	return ""
}

// sourceFound reports whether a cited firewall source was actually there.
//
// Conservative by construction: only the excerpts that say plainly that nothing
// was found count as absent, and everything else — including a shape this build
// has never seen — counts as a firewall in play.
func sourceFound(e finding.Evidence) bool {
	switch {
	case e.Source == "":
		return false
	case strings.HasPrefix(e.Excerpt, "does not exist"):
		return false
	case strings.HasPrefix(e.Excerpt, string(fact.SourceAbsent)):
		return false
	}
	return true
}

func init() {
	register(apparmorFix{})
	register(ufwFix{
		checkID: "NETWORK-0001",
		title:   "A host-based firewall is configured",
	})
	register(ufwFix{
		checkID: "NETWORK-0002",
		title:   "The firewall's default inbound policy denies",
	})
}
