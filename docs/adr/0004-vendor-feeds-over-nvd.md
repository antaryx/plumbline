# ADR-0004 — Vendor security data, not NVD version matching

**Status:** accepted · **Date:** 2026-08-18 · **Applies from:** v2.0.0

## Context

The predecessor design correlated vulnerabilities by enumerating installed
packages, matching name and version against NVD, and mapping CVSS to severity.

Debian, Ubuntu, RHEL and SUSE **backport security fixes without changing the
upstream version number**. `openssl 3.0.2-0ubuntu1.15` is not vulnerable to
what NVD says `openssl 3.0.2` is. A naive matcher reports it anyway, so on a
normal Ubuntu LTS server this design emits hundreds of false criticals — and
every one destroys trust in the other 250 checks.

Secondary: NVD's CPE data for OS packages is inconsistent, there is no reliable
package-name to CPE mapping, and version-range logic is subtle.

## Decision

OS packages are never matched against NVD directly. Use vendor security data,
which encodes "fixed in this distro version": Debian Security Tracker and DSA,
Ubuntu USN and OVAL, Red Hat OVAL and VEX, SUSE OVAL, Alpine `secdb`. OSV
aggregates language ecosystems.

Version comparison implements `dpkg` and RPM `evr` semantics natively, fuzz-tested
against the real tools.

The database ships as a signed, versioned release asset built by a scheduled
job and fetched by `plumbline db fetch`. Never fetched during a scan.

Every finding states the vendor's fixed-version and links the vendor advisory,
because "fixed in 3.0.2-0ubuntu1.15" is the actionable fact, not the CVSS score.

**Release gate:** publish a measured false-positive comparison against a naive
NVD matcher on stock Ubuntu, Debian and Alpine hosts. If the numbers are not
clearly better, the feature does not ship. That comparison is the feature's
entire justification.

## Consequences

- One parser per vendor, each with its own format churn — the ongoing cost
- Coverage limited to distros with a feed; others get inventory without claims,
  stated as such
- Larger build pipeline (scheduled DB builds, signing, retention)
- Far fewer false positives, which is the whole point
- Vendor feeds require network, so DB fetch is a separate command and the scan
  path stays offline
