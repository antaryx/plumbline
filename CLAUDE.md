# CLAUDE.md — working agreement for this repository

You are building **Plumbline**, a deterministic host security auditor for Linux.
Read this file fully before your first edit in any session. It exists because
the invariants below are cheap to violate, expensive to discover, and fatal to
the project if they erode.

---

## 1. The one-paragraph model

Plumbline splits auditing into two halves. **Collectors** touch the operating
system and produce typed **facts**. **Checks** are pure functions from facts to
**findings**. Nothing else touches the OS; nothing in a check is allowed to be
non-deterministic. This is what makes 110 checks testable from fixtures instead
of requiring a thousand virtual machines, and every rule below protects it.

If a task seems to require breaking this split, you have misunderstood the
task. Stop and say so rather than working around it.

---

## 2. Hard rules

These are not style preferences. Violating any of them is a defect even if the
code compiles and the tests pass.

1. **Only `internal/system` touches the OS.** No `os.Open`, `os.ReadFile`,
   `os.Stat`, `exec.Command`, `/proc` reads, or network calls anywhere else.
   Enforced by `make check-system-seam`.

2. **Checks are pure.** A check may not import `context`, `time`, `net`,
   `math/rand`, or `internal/system`. It receives a `*fact.Set` and returns a
   `catalog.Outcome`. Enforced by `make check-check-purity`.

3. **A check never guesses.** If the required facts do not determine the
   answer, return `UNKNOWN` with a reason code. Returning `PASS` when you could
   not verify something is the single worst bug this codebase can contain — it
   converts ignorance into false assurance, and the user has no way to detect
   it.

4. **Check IDs are permanent.** Never renumber, never reuse a retired ID, never
   change what an existing ID means. They appear in users' suppression files and
   in bundles on disk. Allocate the next free number in the module.

5. **Every check needs fixtures.** At minimum one producing `PASS` and one
   producing `FAIL`. Add `NOT_APPLICABLE` and `UNKNOWN` cases wherever the
   check can reach them. A check without both is not done.

6. **Never invent a schema.** `internal/finding` and `internal/fact` define the
   output contract, mirrored in `schema/findings-v1.schema.json`. Adding a
   field is a schema change: raise it, do not do it silently.

7. **No new dependencies without asking.** This binary runs as root. Every
   import is supply-chain surface. Standard library unless there is a stated
   reason.

8. **No shell.** `Exec` takes `argv []string`. Never construct a command
   string, never invoke `sh -c`.

9. **Never claim a task is done without running `make verify` and pasting its
   output.** "It should work" is not a status report.

10. **No auto-remediation.** Plumbline generates fix instructions. It never
    applies them. There is no `--fix` flag and there never will be.

---

## 3. Where things live

```
cmd/plumbline/            main; ~20 lines, everything testable is in cli/
internal/system/          the only OS seam
  system.go               the interface
  live/                   real host, with --root prefixing
  fake/                   fixture-backed, used by every test
  localfile.go            operator-named files (the bundle); NOT on the
                          interface, so --root can never apply — ADR-0011
internal/fact/            typed facts + FactSet + fact errors
internal/collect/         Collector, registry (DAG), runner (budgets, isolation)
internal/collect/collectors/  one package per collector
internal/catalog/         Check type, catalog registry, evaluation runner
internal/catalog/checks/  one package per module: sshd, auth, kernel, ...
internal/finding/         Finding, Result, Severity, Evidence — the schema
internal/sanitize/        control-character neutralisation (T-03); a security
                          control, not formatting
internal/bundle/          .plb read/write, integrity, evidence store
internal/score/           posture and coverage; both can be undefined
internal/render/json/     findings/v1 — the public API
internal/cli/             cobra commands, flag precedence, the exit ladder
internal/version/         tool, catalog and schema versions
schema/                   findings-v1 and bundle-v1; findings-v1 IS the API
testdata/fixtures/        one directory per fixture
tools/fixturegate/        the PASS+FAIL fixture gate (rule 5, mechanised)
docs/                     specifications; read before implementing
docs/adr/                 decisions that would be expensive to reverse
```

Hostile-input fixtures are **generated at test time**, not committed: a FIFO, a
40-deep symlink chain and a 100 MB file are not file contents. See
`internal/system/live/hostile_test.go`.

**Reference implementation:** `internal/catalog/checks/sshd/sshd0002.go` plus
`internal/collect/collectors/sshd/sshd.go` and their tests. When anything is
unclear about how to write a check or a collector, copy the shape of these
first and consult `docs/CHECK-AUTHORING.md` second. They are deliberately
over-commented for this purpose.

---

## 4. How to add a check

1. Read `docs/CHECK-AUTHORING.md` and the per-check spec in
   `docs/checks/<ID>.md` if one exists.
2. Confirm the facts you need already exist in `internal/fact`. If not, the
   collector is a separate work package — do that first, in its own commit.
3. Allocate the next free ID in the module. Check `catalog.IDs()`.
4. Write the check. Handle all five result states explicitly; if one is
   unreachable, say why in a comment.
5. Write fixtures under `testdata/fixtures/`, one directory per scenario, named
   `<module>-<scenario>`.
6. Write the table test. Assert result, severity, unknown reason, and a
   substring of the detail — a correct verdict with a misleading explanation is
   its own bug.
7. Bump `catalog.Version` in `internal/catalog/catalog.go`.
8. `make verify`. Paste the output.

---

## 5. Result states — when to use which

| State | Use when | Never use when |
|---|---|---|
| `PASS` | You read the value and it meets the requirement | You could not read it |
| `FAIL` | You read the value and it does not meet the requirement | The subject does not exist |
| `NOT_APPLICABLE` | The subject genuinely is not present (no sshd installed) | You merely could not find it |
| `SKIPPED` | Deliberately not run — profile, filter, privilege policy | Anything the runner decides; checks rarely emit this |
| `UNKNOWN` | Permission denied, unparseable, truncated, ambiguous, contradictory | As a lazy default — always attach a reason code |

The `sshd-unresolved-include` fixture is the canonical `UNKNOWN`: the keyword
is absent from every file we could read, but an `Include` matched nothing, so
the value might live somewhere we never saw. A lesser tool reports `PASS` from
the documented default. Plumbline says it does not know.

---

## 6. Commit and branch conventions

- Conventional Commits: `feat:`, `fix:`, `check:`, `docs:`, `test:`, `refactor:`,
  `chore:`. `check:` is for catalog changes and must touch `catalog.Version`.
- One branch per work package: `feat/wp-04-sshd-collector`.
- Small commits. One check, one collector, or one refactor per commit.
- Commit messages state *why*, not *what* — the diff already says what.

---

## 7. Working style

- **Do not scaffold ahead.** Do not create empty packages, TODO stubs, or files
  for work packages that have not started. An empty `internal/report/` is worse
  than nothing: it looks like a decision that was never made.
- **Do not add flags, config keys, or output fields that no work package asked
  for.** Surface area is permanent; `docs/VERSIONING.md` explains why.
- **When a spec is ambiguous, stop and ask.** Do not resolve ambiguity by
  choosing. A wrong guess in a security check ships a wrong verdict, and it will
  survive review because it looks confident.
- **When you disagree with the design, say so before implementing it.** The
  design has been audited once already and was wrong in six places; it can be
  wrong again.
- **Read before writing.** `docs/DATA-MODEL.md` and `docs/FIXTURES.md` are
  normative. If your code disagrees with them, your code is wrong until the doc
  is changed deliberately.

---

## 8. What "done" means

A work package is done when all of the following are true and you have said so
explicitly:

- [ ] `make verify` passes; output pasted
- [ ] New checks have PASS and FAIL fixtures at minimum
- [ ] `catalog.Version` bumped if the catalog changed
- [ ] No new dependencies, or the addition was agreed in advance
- [ ] No new files outside the work package's stated scope
- [ ] The work package's own acceptance criteria, quoted and each marked

Anything less is "in progress", and saying otherwise wastes a review cycle.
