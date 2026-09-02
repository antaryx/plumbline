# Legal disclaimer

Ships with the tool and is printed by `plumbline eval --format evidence`.

## Plumbline produces evidence, not conclusions

Plumbline reports observable configuration state. It does not determine, certify
or attest that any system is secure, compliant, or fit for any purpose. Those
are judgements for qualified people with knowledge of your environment, threat
model and obligations.

## Not a compliance assessment

Where a check references a control identifier from a framework such as NIST
SP 800-53 or a DISA STIG, that reference indicates a topical relationship only.
It is not:

- an assessment of compliance with that framework,
- an endorsement or certification by NIST, DISA, CIS, the PCI Security
  Standards Council, ISO, the IEC, the AICPA, or any other body,
- evidence that any requirement has been satisfied.

Most frameworks cover policy, personnel, physical security and organisational
process, none of which any process running on a host can evaluate. Plumbline
therefore reports **coverage counts**, never a compliance percentage. See
`docs/COMPLIANCE-DATA-POLICY.md`.

## Coverage and limitations

- A `PASS` means a specific condition was tested and met at a moment in time on
  the host as it presented itself. It is not an assurance of security.
- An `UNKNOWN` means Plumbline could not determine the answer. It is not a
  `PASS`, and treating it as one defeats the purpose of the distinction.
- Plumbline runs in userspace. It cannot detect a compromised kernel, and it
  cannot defend against an attacker who already has root on the scanned host.
- Coverage is reported alongside every score for this reason. A high posture at
  low coverage means very little.

## Remediation

Remediation output is a proposal for human review. `scan --fix` prints a shell
script, and `--write-script` saves one. Plumbline never runs either, and it
never edits the host it audits.

Reviewing that script before you run it is your responsibility, not Plumbline's.
The generated commands act as root. Some can remove your own access to a host:
the firewall proposal can end an SSH session, and a systemd sandboxing directive
can stop a daemon from writing a path it needs. Read every command, understand
what it does on your system, and test it somewhere that does not matter first.

The maintainer accepts no liability for hosts locked out, services broken, or
downtime caused by running a generated script. See the Warranty section below
and the LICENSE.

## Authorised use only

Some modules (from v2, the `PRIVESC` module) map privilege-escalation surface.
Use them only on systems you own or are explicitly authorised to assess.
Unauthorised use may be a criminal offence in your jurisdiction.

## Warranty

Plumbline is provided under the Apache License 2.0, without warranty of any kind. The
licence disclaims all warranties and all liability; see `LICENSE` for the full
text, which governs over anything said here.
