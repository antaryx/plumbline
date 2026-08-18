# Contributing to Plumbline

Thanks for considering it. This document is the human counterpart to
`CLAUDE.md`, which is the agent-facing version of the same rules.

---

## Before you start

Read, in order:

1. `CLAUDE.md` — the invariants, and why they are not negotiable
2. `docs/DATA-MODEL.md` — facts, findings, bundles
3. `docs/CHECK-AUTHORING.md` — if you are adding a check
4. `internal/catalog/checks/sshd/sshd0002.go` — the reference implementation

For anything larger than a bug fix, open an issue first. A pull request that
arrives without a prior conversation may be rejected on scope grounds, and
neither of us enjoys that.

---

## Development

```bash
git clone https://github.com/antaryx/plumbline
cd plumbline
make verify     # fmt, vet, tests, architectural invariants
make test-race
```

Go 1.23+. No other tooling required to run the tests.

---

## The two invariants

Both are enforced by `make invariants`, and CI blocks on them.

**1. Only `internal/system` touches the OS.** No `os.ReadFile`, `os.Stat`,
`exec.Command`, `/proc` reads or network calls anywhere else. Every check
becomes untestable the moment this erodes, and untestable checks are how a
security tool starts shipping confident wrong answers.

**2. Checks are pure.** A check may not import `context`, `time`, `net`,
`math/rand` or `internal/system`. It takes a `*fact.Set` and returns an
`Outcome`. Purity is what makes findings deterministic and fixture-testable.

If a change seems to require breaking either rule, that is a design
conversation, not a workaround. Open an issue.

---

## The rule behind the rules

**A check that cannot verify something must never report `PASS`.**

Returning `UNKNOWN` is always correct when you do not know. Returning `PASS`
because a file was missing, unreadable, or unparseable tells an operator their
system is fine when it may not be — and, unlike a crash, there is no symptom
that would ever prompt them to look again.

The `sshd-unresolved-include` fixture is the canonical case: the keyword is
absent from every readable file, but an `Include` matched nothing, so the value
may live somewhere we never saw. A lesser tool reports the documented default
and is confidently wrong.

---

## Adding a check

Full procedure in `docs/CHECK-AUTHORING.md`. In brief:

1. Confirm the facts you need already exist. If not, the collector is a
   separate pull request — do that first.
2. Allocate the next free ID in the module. IDs are permanent: never
   renumbered, never reused, never repurposed. They appear in users'
   suppression files.
3. Handle all five result states. Explain unreachable ones in a comment.
4. Write fixtures: at minimum one `PASS`, one `FAIL`. CI enforces both.
5. Write the table test, asserting the detail string as well as the verdict —
   a correct verdict with a misleading explanation is its own bug.
6. Bump `catalog.Version`.
7. `make verify`, paste the output in the pull request.

---

## Commits and branches

- [Conventional Commits]: `feat:` `fix:` `check:` `docs:` `test:` `refactor:`
  `chore:`. `check:` is for catalog changes and must touch `catalog.Version`.
- One branch per unit of work: `feat/wp-08-collector-registry`.
- Small commits. Message says *why*; the diff already says what.
- Rebase, do not merge. History stays linear.

[Conventional Commits]: https://www.conventionalcommits.org/

---

## What gets rejected

Not to be discouraging — these are the recurring ones, and knowing them saves
you the work:

| Rejected | Why |
|---|---|
| A check without fixtures | Unverified security checks are worse than none |
| A check that returns `PASS` on an unreadable source | See above |
| Direct OS access outside `internal/system` | Breaks the test strategy for everything |
| Compliance mapping to CIS, PCI-DSS, ISO 27001 or SOC 2 | Licensing — `docs/COMPLIANCE-DATA-POLICY.md` |
| Any reproduction of control text from a standard | Same |
| A `--fix` flag, or anything that applies a change | Permanent product decision |
| A new dependency without prior discussion | This binary runs as root |
| Speculative scaffolding — empty packages, TODO stubs | Looks like a decision that was never made |
| A flag, config key or output field nobody asked for | Surface area is permanent (`docs/VERSIONING.md`) |
| Renumbering or reusing a check ID | Breaks users' suppression files silently |
| Regenerating golden bundles without explaining each changed line | This is where a "quick fix" rewrites the definition of PASS |

---

## Reporting a wrong verdict

The most valuable contribution, and it needs no code. Use the **False positive
/ wrong verdict** issue template. Every accepted report becomes a permanent
fixture, so the same mistake cannot recur.

Include the daemon's own view of its configuration (`sshd -T`, `sysctl name`)
where possible, not just the file contents — the gap between the two is often
exactly where the bug lives.

---

## Security issues

Do not open a public issue. See `SECURITY.md`.

---

## Licence

Contributions are accepted under the Apache License 2.0. By opening a pull
request you confirm you have the right to submit the work under that licence.
There is no CLA.
