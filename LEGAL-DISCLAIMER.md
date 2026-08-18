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

Remediation output is a suggestion for human review. Plumbline never applies
changes, and there is no `--fix` flag by design. Suggested commands may be
inappropriate for your environment, and some can remove your own access to a
host. Review every command, understand it, and test it somewhere that does not
matter first.

## Authorised use only

Some modules (from v2, the `PRIVESC` module) map privilege-escalation surface.
Use them only on systems you own or are explicitly authorised to assess.
Unauthorised use may be a criminal offence in your jurisdiction.

## Warranty

Plumbline is provided under the Apache License 2.0, without warranty of any
kind. See `LICENSE` for the full terms.
