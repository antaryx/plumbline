package services

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// CleartextUnits are the units that carry credentials over the network in the
// clear, under every name the major distributions ship them as.
//
// The list is names rather than a pattern because a pattern would be wrong in
// both directions: "telnet" matches telnet-client packages that listen for
// nothing, and no pattern catches rsh's three separate daemons. Each entry
// here is a unit that, when enabled, results in a listening socket that
// accepts a password nobody had to break to read.
//
// Socket units are listed alongside service units because socket activation is
// how these daemons are normally shipped now: telnet.socket is enabled and
// telnet@.service is started per connection, so the .service alone is never
// enabled and checking only for it would find nothing on a host running
// telnet.
var CleartextUnits = []string{
	// telnet: the entire session, password included, in plaintext.
	"telnet.socket", "telnet.service",
	"telnetd.socket", "telnetd.service",
	"inetutils-telnetd.socket", "inetutils-telnetd.service",
	// The BSD r-commands: cleartext, and authenticating on .rhosts, which is
	// to say on the client's assertion of who it is.
	"rsh.socket", "rsh.service",
	"rlogin.socket", "rlogin.service",
	"rexec.socket", "rexec.service",
	"rshd.socket", "rlogind.socket", "rexecd.socket",
	// FTP: password in the clear on the control channel.
	"vsftpd.service", "proftpd.service", "pure-ftpd.service", "ftp.service",
	// TFTP: no authentication at all.
	"tftp.socket", "tftp.service", "tftpd.service", "tftpd-hpa.service",
}

// Check0001 tests that no cleartext-credential network service is enabled.
var Check0001 = catalog.Check{
	ID:     "SERVICES-0001",
	Module: "SERVICES",
	Title:  "No cleartext-credential network service is enabled",
	Description: `telnet, rsh, rlogin, rexec, FTP and TFTP transmit
authentication material as plaintext across the network. A password captured
this way requires no cryptanalysis and no vulnerability: anyone positioned on
the path, a switch, a router, a compromised host on the same segment, a cloud
provider's virtual network, reads it as it goes past, along with everything
typed in the session afterwards.

The r-commands are worse still. rsh and rlogin authenticate on .rhosts and
hosts.equiv, which is to say they authenticate on the client's own claim about
who it is and which host it is calling from. There is no secret involved at
all; the trust relationship is the credential, and it is forgeable by anyone
who can spoof a source address or take over a trusted host.

Every one of these has had a drop-in replacement for a quarter of a century.
The reason they survive is not that anybody chose them: they are enabled by a
package installed for its client tools, or inherited by an image nobody has
rebuilt, or left over from a migration that finished years ago. That is exactly
why they are worth checking rather than assuming.

This check reads systemd's enablement symlinks, so it reports what will start
at boot. A daemon started by hand and never enabled does not appear here, and
neither does one run from inetd or xinetd, which are separate mechanisms this
module does not read.`,

	BaseSeverity: finding.High,
	Tags:         []string{"services", "systemd", "cleartext", "network", "legacy"},
	Requires:     []fact.ID{fact.ServicesID},
	SinceCatalog: 9,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := servicesFact(fs)
		if !s.Systemd {
			return notSystemd()
		}

		if enabled := s.AnyEnabled(CleartextUnits...); len(enabled) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: enabled[0],
				Detail: fmt.Sprintf(
					"%s %s enabled and will start at boot. %s authentication over the network in plaintext: any host on the path reads the password as it goes past, and everything typed afterwards with it. There is a drop-in replacement for each of these and has been for twenty-five years.",
					join(enabled),
					plural(len(enabled), "is", "are"),
					plural(len(enabled), "It carries", "They carry")),
				Evidence: enabledEvidence(s, enabled),
			}
		}

		// The conclusion is drawn from absence, so it is only as good as the
		// directory listings behind it.
		return unknownIfIncomplete(s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"None of the %d cleartext-credential units this check knows about is enabled.%s",
				len(CleartextUnits), describeStatuses(s, CleartextUnits)),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Disable and mask the cleartext service, and remove the package that ships it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out whether anything still uses it before switching it off. 'ss -tnp' shows current connections to the port; the daemon's own log, or 'journalctl -u <unit>', shows who has connected recently. A service nobody has used in a month is safe to remove; one in daily use needs its callers migrated first.",
			"Disable it: 'systemctl disable --now <unit>'. This removes the enablement symlink and stops it in one step.",
			"Mask it as well: 'systemctl mask <unit>'. Disabling stops it starting at boot; masking stops anything starting it at all, including another unit that names it as a dependency and including a package upgrade that re-runs its preset.",
			"Remove the package outright where you can, 'apt purge telnetd' or 'dnf remove telnet-server', which is the only step that also removes the binary. Note that the *client* package is a separate one and is usually worth keeping.",
			"Migrate the callers: ssh replaces telnet, rsh and rlogin; scp, sftp or rsync-over-ssh replaces FTP. For TFTP, which exists to serve boot images to devices with no room for a TLS stack, confine it to an isolated provisioning network rather than trying to secure the protocol.",
		},
		Commands: []string{
			"systemctl list-unit-files --state=enabled | grep -Ei 'telnet|rsh|rlogin|rexec|ftp'",
			"systemctl disable --now telnet.socket",
			"systemctl mask telnet.socket",
		},
		Caution: "Masking a unit that something else Requires= makes that dependency fail, which on a hard dependency takes the depending unit down with it. Check 'systemctl list-dependencies --reverse <unit>' before masking anything you did not install yourself.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-17"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
	},

	References: []finding.Reference{
		{Title: "systemd.unit(5), [Install] and enablement symlinks", URL: "https://man7.org/linux/man-pages/man5/systemd.unit.5.html"},
		{Title: "RFC 4251. SSH Protocol Architecture (§9.1, why cleartext protocols were replaced)", URL: "https://www.rfc-editor.org/rfc/rfc4251"},
	},
}
