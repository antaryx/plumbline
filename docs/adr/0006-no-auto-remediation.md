# ADR-0006 — Plumbline never applies a change

**Status:** accepted · **Date:** 2026-08-18

## Context

Every hardening tool eventually gets asked for a `--fix` flag, and it is
genuinely useful about 95% of the time.

The other 5% is a tool running as root, acting on a heuristic verdict, on a
machine the author cannot see, rewriting `/etc/ssh/sshd_config` or a firewall
rule — and locking the operator out of a host in another country. Recovery
requires physical or console access that many users do not have.

The asymmetry decides it: the upside is convenience, the downside is
unrecoverable loss of access to production infrastructure.

## Decision

Plumbline never applies a change. There is no `--fix` flag and there never will
be, in any version.

From v2 it *generates* remediation: a reviewable Bash or Ansible script with
every command commented with its finding ID. The user reads it and runs it.

Every remediation that can affect access carries a mandatory `Caution` field,
and remediation steps include verification before anything destructive — the
reference check tells the operator to confirm a non-root login path works in a
*separate session* first.

## Consequences

- Loses a feature users ask for, repeatedly
- The answer must be given consistently and with the reasoning, or it gets
  re-litigated every six months — hence this ADR
- Removes an entire class of catastrophic failure, and with it the support
  burden and liability that come from having locked someone out of production
- Generated scripts are auditable artifacts, which is better for change control
  than an opaque in-tool mutation anyway
