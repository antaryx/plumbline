# ADR-0003 — No compliance percentages, ever

**Status:** accepted · **Date:** 2026-08-18

## Context

The predecessor design computed
`ComplianceScore = PassedControls / TotalApplicableControls × 100` for eight
frameworks, producing output like "87% PCI-DSS compliant".

Two problems. **It is meaningless:** PCI-DSS covers policy, personnel, physical
security and segmentation; a process on one host cannot assess most of it. The
denominator silently excludes everything untestable, so the percentage is
computed against a subset the reader cannot see. **It is dangerous:** someone
will paste that number into an audit response.

Separately, shipping the mapping data for CIS, PCI-DSS, ISO 27001 and SOC 2
under Apache-2.0 conflicts with those bodies' licences.

## Decision

No compliance percentage is ever emitted. Output is counts plus an explicit
coverage statement:

> Of PCI-DSS v4.0, Plumbline tests 34 requirements at host level: 29 pass,
> 5 fail. This is host-level technical coverage only and is not an assessment
> of compliance.

Only public-domain frameworks ship (NIST 800-53, DISA STIG), as bare control
identifiers with no control text. Restricted frameworks are supported through
user-supplied mapping packs the user holds a licence for. Full rules in
`docs/COMPLIANCE-DATA-POLICY.md`; `LEGAL-DISCLAIMER.md` ships with the tool.

## Consequences

- Loses a feature competitors advertise, and some users will want the number
- The honest framing needs more words than a percentage does
- Requires a mapping-pack format and loader (v2) instead of shipping data
- Removes takedown risk entirely
- The evidence pack is what auditors actually want, so this is a better product
  as well as a safer one
