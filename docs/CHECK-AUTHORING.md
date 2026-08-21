# CHECK AUTHORING — Plumbline

How to add a check. The reference implementation is
`internal/catalog/checks/sshd/sshd0002.go`; read it alongside this document,
and when the two disagree, the code is what runs.

---

## 1. Before you write anything

Answer these four questions. If you cannot, the check is not ready.

1. **What exactly is being tested?** Not "SSH is secure" — "the effective
   global value of `PermitRootLogin` is `no`". If you cannot state the
   predicate in one sentence, split the check.
2. **Which facts determine the answer?** They must already exist in
   `internal/fact`. If they do not, the collector is a separate work package
   and a separate commit. Do not add collection logic to a check.
3. **What does the daemon do when the setting is absent?** Most checks get this
   wrong. `PermitRootLogin` unset means `prohibit-password`, not "insecure" and
   not "fine". Look it up in the manual page, cite it in a comment.
4. **When can this check not know?** Every path to `UNKNOWN` you fail to
   identify becomes a false `PASS` in production.

---

### Start from the template

Copy [`checks/_TEMPLATE.md`](checks/_TEMPLATE.md) to `docs/checks/<ID>.md` and
fill it in **before** writing Go:

```bash
cp docs/checks/_TEMPLATE.md docs/checks/SSHD-0021.md
```

The four questions above are the ones it makes you answer in writing, and
answering them in prose first is the cheapest place to discover that a check is
really two checks, or that the daemon's default is not what you assumed. A spec
that cannot be written is a check that should not be.

Every check in `docs/checks/` was written this way, and the file becomes the
per-check reference that ships with the tool.

---

## 2. Allocate an ID

`MODULE-NNNN`, four digits, next free number in the module. IDs are permanent
identifiers in the same class as CVE IDs: never renumbered, never reused after
retirement, never repurposed. They live in users' suppression files and in
bundles on disk.

```bash
grep -rho 'ID:     "SSHD-[0-9]*"' internal/catalog/checks/sshd/ | sort | tail -1
```

---

## 3. Write the check

```go
var Check0002 = catalog.Check{
    ID:           "SSHD-0002",
    Module:       "SSHD",
    Title:        "Root login over SSH is disabled",
    Description:  `Why this matters, in prose, for CHECK-REFERENCE.md.`,
    BaseSeverity: finding.High,
    Requires:     []fact.ID{fact.SSHDConfigID},
    SinceCatalog: 1,

    Eval: func(fs *fact.Set) catalog.Outcome { /* pure */ },

    Remediation: &finding.Remediation{ /* ... */ },
    Mappings:    []finding.ControlRef{ /* public-domain frameworks only */ },
    References:  []finding.Reference{ /* the manual page */ },
}
```

### What the runner does for you

You do not implement any of this, and you must not duplicate it:

- **Required facts are guaranteed present.** `Requires` is enforced before
  `Eval` runs. A missing or errored fact becomes `UNKNOWN` with the right reason
  code automatically. This is why `fact.Get` in the reference check ignores its
  error returns.
- **Panics become `UNKNOWN(internal_error)`.** One bad check never kills a scan.
  In CI, any panic over the fixture corpus is a test failure.
- **Identity and fingerprint are filled in.** Do not set them.
- **Remediation is attached only on `FAIL`.** Declare it once on the check.

### What `Eval` must do

Return exactly one `Outcome`, having considered every reachable result state.

```go
Eval: func(fs *fact.Set) catalog.Outcome {
    cfg, _, _ := fact.Get[fact.SSHDConfig](fs, fact.SSHDConfigID)

    if !cfg.Installed {
        return catalog.Outcome{
            Result: finding.NotApplicable,
            Detail: "No sshd configuration found; the SSH server is not configured on this host.",
        }
    }
    // ...
}
```

---

## 4. Choosing the result state

| State | Use when |
|---|---|
| `PASS` | You read the value and it meets the requirement |
| `FAIL` | You read the value and it does not |
| `NOT_APPLICABLE` | The subject genuinely is not present |
| `SKIPPED` | Rarely emitted by checks; the runner decides this |
| `UNKNOWN` | Permission denied, unparseable, truncated, ambiguous, contradictory |

**The rule that matters:** if you cannot verify it, you do not know it. A check
that returns `PASS` because the file was missing has told the operator their
system is fine when it may not be, and there is no way for them to find out.

`SSHD-0002` returns `UNKNOWN` when the keyword is absent *and* an `Include`
failed to resolve — the value may live in a file that was never read. A less
careful check reports the documented default and is confidently wrong. That
distinction is the reason this project exists; preserve it in every check.

---

## 5. Writing the detail string

The detail is what a human reads at 02:00. It states what was **observed**, not
what the check does.

| Bad | Good |
|---|---|
| "PermitRootLogin should be no" | "PermitRootLogin is set to `yes` at /etc/ssh/sshd_config:3; root may log in directly, including with a password." |
| "Check failed" | "PermitRootLogin is not configured; sshd applies its built-in default of `prohibit-password`, which permits root login with a key." |
| "Insecure configuration" | "PermitRootLogin has unrecognised value `maybe` at /etc/ssh/sshd_config:1; sshd would reject this configuration, so the running server may be using a different file." |

Include the file and line. Include the observed value. Explain the consequence
in a clause, not a lecture.

---

## 6. Evidence

Every `FAIL` and every `UNKNOWN` carries evidence. A finding without it is a
rumour, and an auditor cannot use it.

```go
Evidence: []finding.Evidence{finding.NewEvidence(
    d.File, d.Line,
    fmt.Sprintf("%s %s", d.Keyword, d.Value),
    cfg.Digests[d.File])}
```

Use `finding.NewEvidence`, not an `Evidence` literal. It does two things a
literal does not:

- **Neutralises the untrusted strings.** A filename may contain ESC, and
  `\x1b[2J\x1b[H  All checks passed` in an excerpt clears the operator's
  terminal and forges a verdict (`THREAT-MODEL.md` T-03). The catalog runner
  sanitises again on the way out, so a literal is not *unsafe* — but it is the
  wrong habit to copy.
- **Attaches the digest of the file the line came from.** The bytes are stored
  in the bundle at `evidence/<sha256>.blob`, so an auditor who disputes an
  excerpt can re-read the source. Evidence with no digest cannot be verified
  against anything, which makes it an assertion rather than evidence.

The digest comes from the fact (`cfg.Digests`), because a check is pure and
cannot hash a file itself (ADR-0009). If the fact you are reading does not carry
digests yet, that is a collector work package, not something to work around.

Add evidence that explains a *surprising* verdict. `SSHD-0002` attaches
Match-scoped occurrences when it fails, so an operator who can plainly see
`PermitRootLogin no` in their file is told why it does not count. Without that,
they conclude the tool is broken and stop using it — which is the correct
response to a tool that appears to contradict the file in front of them.

---

## 7. Remediation

```go
Remediation: &finding.Remediation{
    Summary:  "Set PermitRootLogin to no and reload sshd.",
    Effort:   "LOW",
    Steps:    []string{ /* what a human does */ },
    Commands: []string{ /* what they can copy, after reading */ },
    Caution:  "Applying this while your only access is a root SSH session will lock you out.",
},
```

Rules:

- **Steps and commands, not one or the other.** Steps teach, commands save time.
- **A verification step before anything destructive.** The reference check tells
  the operator to confirm a non-root path works *in a separate session* first.
- **`Caution` is mandatory for anything touching remote access, authentication,
  firewalling or the bootloader.** These are the ways a hardening tool locks
  someone out of a machine in another country.
- **Never a command that cannot be reviewed.** No piped downloads, no `sed -i`
  over a file whose format you have not parsed.
- Plumbline never runs any of this. There is no `--fix` flag.

---

## 8. Mappings

Only public-domain frameworks: NIST SP 800-53 Rev 5, DISA STIG. Bare control
identifiers only — **never control text**. See `COMPLIANCE-DATA-POLICY.md`;
this is a licensing constraint, not a stylistic one, and CIS / PCI-DSS /
ISO 27001 / SOC 2 mappings must not be added to the catalog.

---

## 9. Fixtures and tests

See `FIXTURES.md`. Minimum: one `PASS`, one `FAIL`. CI enforces it.

The test evaluates the **whole vertical slice** — real collector against a
fixture tree, then the real check — because most check bugs are actually
collector bugs. Never hand-build a `fact.Set` in a check test.

```go
{
    fixture:        "sshd-match-trap",
    result:         finding.Fail,
    severity:       finding.High,
    detailContains: "may log in directly",
},
```

Assert a substring of the detail as well as the verdict. A correct verdict with
a misleading explanation is its own class of bug, and it is invisible to a test
that only checks the result enum.

---

## 10. Finish

```bash
make verify
```

Then bump `catalog.Version` in `internal/catalog/catalog.go`, and commit with a
`check:` prefix.

Checklist before you call it done:

- [ ] All five result states considered; unreachable ones explained in a comment
- [ ] The daemon's real default is encoded and cited
- [ ] Every `UNKNOWN` path has a reason code
- [ ] Detail states observed values with file and line
- [ ] Evidence on every `FAIL` and `UNKNOWN`, built with `finding.NewEvidence`
- [ ] Evidence carries a digest where the fact provides one
- [ ] `Caution` present if the fix can lock someone out
- [ ] PASS and FAIL fixtures exist; NOT_APPLICABLE and UNKNOWN where reachable
- [ ] `make verify` output pasted
- [ ] `catalog.Version` bumped
- [ ] `docs/checks/<ID>.md` written from
      [`checks/_TEMPLATE.md`](checks/_TEMPLATE.md)
