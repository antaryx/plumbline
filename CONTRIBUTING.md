# Contributing to Plumbline

Thanks for considering it. **This document is the working agreement for this
repository, and it is not optional reading.** The rules below are cited by name
from the source — a comment saying *"enforced by rule 3"* means rule 3 of this
document — because they are cheap to violate, expensive to discover, and fatal
to the project if they erode.

---

## The one-paragraph model

Plumbline splits auditing into two halves. **Collectors** touch the operating
system and produce typed **facts**. **Checks** are pure functions from facts to
**findings**. Nothing else touches the OS; nothing in a check is allowed to be
non-deterministic.

This is what makes 112 checks testable from fixtures instead of from a thousand
virtual machines, and every rule below protects it. **If a task seems to require
breaking that split, the task has been misunderstood** — say so rather than
working around it.

---

## Before you start

Read, in order:

1. This document — the invariants, and why they are not negotiable
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

Go 1.24 is the floor `go.mod` states; releases are built with 1.25, because Go
supports only its two newest majors and a binary that runs as root is the last
one to build with an unmaintained toolchain. No other tooling is required.

---

## The hard rules

These are not style preferences. **Violating any of them is a defect even if the
code compiles and the tests pass.** They are numbered, the numbers are stable,
and source comments cite them by number.

**1. Only `internal/system` touches the OS.** No `os.Open`, `os.ReadFile`,
`os.Stat`, `exec.Command`, `/proc` reads or network calls anywhere else. Every
check becomes untestable the moment this erodes, and untestable checks are how a
security tool starts shipping confident wrong answers. *Enforced by
`make check-system-seam`.*

**2. Checks are pure.** A check may not import `context`, `time`, `net`,
`math/rand` or `internal/system`. It receives a `*fact.Set` and returns a
`catalog.Outcome`. Purity is what makes findings deterministic and
fixture-testable. *Enforced by `make check-check-purity`.*

**3. A check never guesses.** If the required facts do not determine the answer,
return `UNKNOWN` with a reason code. Returning `PASS` when you could not verify
something is the single worst bug this codebase can contain — it converts
ignorance into false assurance, and the user has no way to detect it. See
*[The rule behind the rules](#the-rule-behind-the-rules)* below.

**4. Check IDs are permanent.** Never renumber, never reuse a retired ID, never
change what an existing ID means. They appear in users' suppression files and in
bundles on disk. Allocate the next free number in the module.

**5. Every check needs fixtures.** At minimum one producing `PASS` and one
producing `FAIL`. Add `NOT_APPLICABLE` and `UNKNOWN` cases wherever the check can
reach them. A check without both is not done. *Enforced by
`make check-fixture-coverage`.*

**6. Never invent a schema.** `internal/finding` and `internal/fact` define the
output contract, mirrored in `schema/findings-v1.schema.json`. Adding a field is
a schema change: raise it, do not do it silently.

**7. No new dependencies without asking.** This binary runs as root. Every
import is supply-chain surface. Standard library unless there is a stated
reason. The dependency count is a published control — see
`docs/SUPPLY-CHAIN.md`.

**8. No shell.** `Exec` takes `argv []string`. Never construct a command string,
never invoke `sh -c`.

**9. Never claim a task is done without running `make verify`** and pasting its
output. "It should work" is not a status report.

**10. No auto-remediation.** Plumbline generates fix instructions. It never
applies them. `scan --fix` proposes a script and executes nothing
(`docs/adr/0006-no-auto-remediation.md`).

Rules 1, 2 and 5 are enforced by `make invariants` and CI blocks on them. The
rest are enforced by review, which is why they are written down.

If a change seems to require breaking one, that is a design conversation, not a
workaround. Open an issue.

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

## Result states — when to use which

| State | Use when | Never use when |
|---|---|---|
| `PASS` | You read the value and it meets the requirement | You could not read it |
| `FAIL` | You read the value and it does not meet the requirement | The subject does not exist |
| `NOT_APPLICABLE` | The subject genuinely is not present (no sshd installed) | You merely could not find it |
| `SKIPPED` | Deliberately not run — profile, filter, privilege policy | Anything the runner decides; checks rarely emit this |
| `UNKNOWN` | Permission denied, unparseable, truncated, ambiguous, contradictory | As a lazy default — always attach a reason code |

---

## Working style

- **Do not scaffold ahead.** No empty packages, TODO stubs, or files for work
  that has not started. An empty `internal/report/` is worse than nothing: it
  looks like a decision that was never made.
- **Do not add flags, config keys or output fields that nobody asked for.**
  Surface area is permanent; `docs/VERSIONING.md` explains why.
- **When a spec is ambiguous, stop and ask.** Do not resolve ambiguity by
  choosing. A wrong guess in a security check ships a wrong verdict, and it will
  survive review because it looks confident.
- **When you disagree with the design, say so before implementing it.** The
  design has been audited once already and was wrong in six places; it can be
  wrong again.
- **Read before writing.** `docs/DATA-MODEL.md` and `docs/FIXTURES.md` are
  normative. If your code disagrees with them, your code is wrong until the
  document is changed deliberately.

---

## What "done" means

A change is done when all of the following are true and you have said so
explicitly in the pull request:

- [ ] `make verify` passes; output pasted
- [ ] New checks have `PASS` and `FAIL` fixtures at minimum
- [ ] `catalog.Version` bumped if the catalog changed
- [ ] No new dependencies, or the addition was agreed in advance
- [ ] No new files outside the change's stated scope
- [ ] The stated acceptance criteria, quoted and each marked

Anything less is "in progress", and saying otherwise wastes a review cycle.

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

Contributions are accepted under the Apache License 2.0. By opening a pull request
you confirm you have the right to submit the work under that licence. There is
no CLA.
