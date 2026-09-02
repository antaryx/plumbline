package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0012 tests the key-exchange methods the server will negotiate.
var Check0012 = catalog.Check{
	ID:     "SSHD-0012",
	Module: "SSHD",
	Title:  "No deprecated key exchange method is offered",
	Description: `Key exchange establishes the shared secret everything else in
the session depends on. It is the one negotiation where a weakness is not
partial: an adversary who can recover the exchanged secret reads and modifies
the session regardless of how strong the cipher and MAC were.

Two families fail:

- **The 1024-bit MODP groups**, diffie-hellman-group1-sha1 and its relatives.
  Logjam (2015) showed that a single expensive precomputation against a fixed
  1024-bit group makes individual exchanges cheap thereafter, and that the
  small number of groups in widespread use makes that precomputation worth
  doing. The prudent assumption is that it has been done.
- **SHA-1 key exchanges**, group14-sha1, group-exchange-sha1, and the gss-
  variants. RFC 9142 deprecates SHA-1 for SSH key exchange, and OpenSSH removed
  these from its default list in 8.2.

A note on scope: the Terrapin attack (CVE-2023-48795) is a weakness in the
handshake's sequence-number handling rather than in any algorithm on this list,
and it is fixed by OpenSSH 9.6's strict-KEX extension rather than by a
configuration change. This check does not detect it, a host with a perfectly
acceptable KexAlgorithms list can still be vulnerable if the binary predates
9.6. Version-based detection belongs to a vulnerability feed, not here.

When KexAlgorithms is absent this check returns UNKNOWN rather than PASS, for
the reason set out in algorithms.go.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "cryptography", "remote-access"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: algSpec{
		Keyword: "KexAlgorithms",
		Noun:    "key exchange",
		Weak:    weakKex,
		Base:    finding.High,
		Consequence: "a client that offers one of these will be given it, and an adversary who recovers " +
			"the exchanged secret reads and modifies the whole session no matter how strong the " +
			"cipher and MAC negotiated on top of it were",
		Assurance: "every session this host will agree to carry establishes its secret with a method that has no known practical attack",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set an explicit KexAlgorithms list of SHA-2 curve and large-group methods.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Set an explicit list in /etc/ssh/sshd_config: 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256'.",
			"Where the host must keep a DH group-exchange method, also remove the small moduli from /etc/ssh/moduli: 'awk \\'$5 >= 3071\\' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv /etc/ssh/moduli.tmp /etc/ssh/moduli'. Leaving 1024-bit moduli in that file undoes much of the point of the list.",
			"Confirm the sshd binary is 9.6 or later, so the strict-KEX mitigation for Terrapin (CVE-2023-48795) is present. That is a version question, not a configuration one, and this check does not answer it: 'sshd -V' or the package version.",
			"On RHEL 8+ and Fedora, check 'update-crypto-policies --show', the system policy governs this list too.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i '^kexalgorithms'",
			"ssh -Q kex",
		},
		Caution: "Key exchange is the first thing negotiated, so a client that supports nothing on the list fails before authentication with 'no matching key exchange method found' and no indication of which host setting caused it. This is the algorithm list most likely to break old automation; check it against every client that reaches this host, including backup agents and monitoring probes.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-8"},
		{Framework: "nist-800-53-r5", Control: "SC-12"},
		{Framework: "nist-800-53-r5", Control: "SC-13"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). KexAlgorithms", URL: "https://man.openbsd.org/sshd_config#KexAlgorithms"},
		{Title: "RFC 9142. Key Exchange (KEX) Method Updates for SSH", URL: "https://www.rfc-editor.org/rfc/rfc9142"},
		{Title: "Logjam / Weak Diffie-Hellman", URL: "https://weakdh.org/"},
	},
}
