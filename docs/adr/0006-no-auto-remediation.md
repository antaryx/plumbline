# ADR-0006 — Plumbline never applies a change

**Status:** accepted, amended 2026-08-31 (see Amendment) · **Date:** 2026-08-18

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

## Amendment, 2026-08-31

The Decision above says "there is no `--fix` flag and there never will be, in
any version". A `--fix` flag exists as of the remediation engine, and the
sentence is left in place rather than edited because the reasoning around it is
what still governs.

What the flag does is print. `scan --fix` renders a shell script to the report
and `--write-script` saves it to a file. Plumbline executes none of it, edits
nothing on the host it audits, and has no code path that applies a plan. The
asymmetry in the Context section is untouched: the downside being guarded
against is a root process rewriting configuration on a machine the author
cannot see, and generating a script the operator reads first does not create it.

Two things the wording got wrong are worth recording.

The original assumed a `--fix` flag necessarily means applying changes. The
distinction that matters is between generating and applying, not between having
the flag and not having it, and naming the flag after the thing operators
already look for is better than making them find `--write-script` by reading
the manual.

It also assumed a script is safe because a human reads it. Mostly true, and it
failed once: the generated `SERVICES-0011` drop-in set `ProtectSystem=strict`
on daemons that then could not write `/run` or `/var`, and the six-line warning
above it did not stop anyone. That fix is withdrawn, and the rule it produced is
in `internal/remediate/systemd.go`: a proposal can be too dangerous to make when
the operator's realistic behaviour on receiving it is to run it. Generating is
still not applying, but it is not free either.
