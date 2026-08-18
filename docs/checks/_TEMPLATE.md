# <CHECK-ID> — <one-line title>

> Copy this file to `docs/checks/<CHECK-ID>.md` and fill it in **before**
> writing the check. If you cannot complete §2 and §5, the check is not ready
> to implement — you will discover the ambiguity halfway through and resolve it
> by guessing, which is how wrong verdicts ship.

| Field | Value |
|---|---|
| **ID** | `MODULE-NNNN` |
| **Module** | |
| **Base severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Tags** | |
| **Facts required** | |
| **Since catalog** | |
| **Platforms** | |

## 1. What is tested

One sentence, precise. Not "SSH is secure" but "the effective global value of
`PermitRootLogin` is `no`". If it needs two sentences, split the check.

## 2. Why it matters

The actual risk, in plain terms. What an attacker gains, or what the operator
loses, when this is wrong. This text becomes the check's `Description` and
appears in `CHECK-REFERENCE.md`, so write it for a reader who does not already
agree with you.

## 3. Source of truth

Where the value comes from, and — critically — **what the software does when
the setting is absent**. Cite the manual page or source. Getting the default
wrong is the most common way a check produces a confidently wrong verdict.

| | |
|---|---|
| Source | e.g. `/etc/ssh/sshd_config` and its includes |
| Daemon default when unset | |
| Reference | manual page section, upstream docs URL |

## 4. Distribution variations

Known differences in file location, format, packaging default, or naming.
One row per distro you have actually checked; do not fill in from memory.

| Distro | Variation | Verified? |
|---|---|---|

## 5. Verdict table

Every reachable state, with the exact condition. This is the specification the
implementation must satisfy.

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | | | |
| FAIL | | | |
| NOT_APPLICABLE | | — | |
| UNKNOWN | | — | reason code |
| SKIPPED | usually runner-decided | — | |

## 6. Where this check cannot know

List every path to `UNKNOWN`: unreadable source, unparseable value, include
that did not resolve, value overridden by a scope the check cannot evaluate,
daemon default that depends on build flags.

**Every path you fail to identify here becomes a false PASS in production.**

## 7. Known false positives

Configurations that are legitimate but will fail this check, and how a user
should respond (usually: a suppression with a justification). Populated over
time from issue reports; feeds `FALSE-POSITIVES.md`.

## 8. Remediation

| | |
|---|---|
| Summary | |
| Effort | LOW / MEDIUM / HIGH |
| Steps | numbered, human-followable, verification before anything destructive |
| Commands | reviewable, no piped downloads, no blind in-place edits |
| **Caution** | **mandatory** if applying this can remove the operator's own access |

## 9. Control mappings

Public-domain frameworks only — NIST SP 800-53 Rev 5, DISA STIG. Bare
identifiers, never control text. See `COMPLIANCE-DATA-POLICY.md`.

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|

Minimum: one PASS, one FAIL. Add NOT_APPLICABLE and UNKNOWN where reachable.
See `FIXTURES.md` §4.1 for the cases people forget.
