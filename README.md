# Plumbline

*Hang a line. See what's true.*

A deterministic, offline, evidence-first host security auditor for Linux.

> **Status: v0.1.0 — pre-release, no stability guarantees.** The walking
> skeleton is complete: the OS seam, facts, bundles, the collector runner,
> scoring, the JSON renderer and the CLI, with one collector and one check
> proving the shape end to end. Offline operation and hostile-input survival
> are tests rather than promises.
>
> `findings/v1`, flag names, exit codes and check IDs are contracts from here.
> Everything in Go stays `internal/` and may change without notice (ADR-0007).
>
> Next: `docs/BUILD-RUNBOOK-v0.2.md`, work package WP-15 — the shared
> filesystem walker, which blocks the `FILESYS` module.

## What makes it different

Plumbline splits auditing in two. **Collectors** touch the OS and produce typed
**facts**; **checks** are pure functions from facts to **findings**. A scan
captures a portable fact bundle, and findings are derived from it.

That single decision buys things a live-evaluating scanner cannot have:

- **Re-audit the past.** Evaluate a six-month-old bundle against today's check
  catalog, offline, without touching the host.
- **Diff across time.** `plumbline diff march.plb today.plb`.
- **Separate trust domains.** Collect on a locked-down production host,
  analyse anywhere.
- **Real test coverage.** Checks run against fixture trees, so a catalog of
  hundreds of checks stays verifiable.

And it says `UNKNOWN` when it cannot tell, instead of reporting `PASS`.

## Development

```bash
make verify      # fmt, vet, tests, architectural invariants
make test-race
```

Go 1.23+. No other tooling needed to run the tests.

## Documentation

**Start here**

| Document | Purpose |
|---|---|
| `CLAUDE.md` | Working agreement and hard rules — read before any change |
| `docs/PROJECT-BRIEF.md` | Identity, scope, non-goals, differentiation |
| `docs/ARCHITECTURE.md` | Layers, the OS seam, collection, evaluation, safety |
| `docs/GLOSSARY.md` | Vocabulary — small, disproportionately useful |

**Building**

| Document | Purpose |
|---|---|
| `docs/BUILD-RUNBOOK-v0.2.md` | Sequenced, session-sized work packages |
| `docs/DATA-MODEL.md` | Facts, findings, bundles — normative |
| `docs/CHECK-AUTHORING.md` | How to add a check |
| `docs/FIXTURES.md` | Fixture format and the test corpus |
| `docs/CLI-SPEC.md` | Commands, flags, precedence, exit codes |
| `schema/findings-v1.schema.json` | The public API |
| `schema/bundle-v1.schema.json` | Bundle manifest |

**Policy**

| Document | Purpose |
|---|---|
| `docs/THREAT-MODEL.md` | Plumbline's own attack surface — gates running as root |
| `docs/COMPLIANCE-DATA-POLICY.md` | What may and may not be shipped |
| `docs/VERSIONING.md` | Four version numbers and their contracts |
| `docs/DEPLOYMENT.md` | Build, sign, publish, install, upgrade |
| `docs/ROADMAP.md` | Three stable majors |
| `docs/adr/` | Decisions that would be expensive to reverse |
| `LEGAL-DISCLAIMER.md` | Evidence, not conclusions |

**Background**

`docs/audit/argus-design-audit.md` — the audit of the predecessor design that
produced this project. Useful context for why several things are the way they
are.

## Reference implementation

`internal/collect/collectors/sshd/sshd.go` and
`internal/catalog/checks/sshd/sshd0002.go`, with nine fixtures under
`testdata/fixtures/`. Deliberately over-commented. Copy their shape.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
