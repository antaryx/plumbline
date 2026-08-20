# USERS-0009 — Passwords that can authenticate have a bounded maximum age

| Field | Value |
|---|---|
| **ID** | `USERS-0009` |
| **Module** | USERS |
| **Base severity** | LOW |
| **Tags** | users, credentials, password-policy |
| **Facts required** | `users.shadow`, `users.passwd` |
| **Since catalog** | 5 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every account that can actually authenticate with a password has field 5 of
`/etc/shadow` set to 365 or fewer days.

"Can actually authenticate" means the entry is not locked, its password field is
not empty, and it holds a stored hash — `fact.ShadowEntry.Authenticates()`.

## 2. Why it matters — and why the frameworks disagree

**Read this section before treating a finding from this check as a defect.**

Field 5 is the number of days a password may be kept before the system requires
a new one. `shadow-utils` writes `99999` by default — a little over 273 years,
which means never — and an empty field means the same thing more explicitly.

Three current, actively maintained sources of guidance take three different
positions:

| Source | Position |
|---|---|
| **NIST SP 800-63B** §5.1.1.2 | Verifiers **SHOULD NOT** require periodic password changes. Force a change only on evidence of compromise. |
| **CIS Benchmarks** | Maximum age **≤ 365 days**. |
| **DISA STIG** | Maximum age **≤ 60 days**. |

None of these is a misreading of the others. NIST's position rests on evidence
that forced rotation produces predictable transformations of one password —
`Summer2024!` becomes `Summer2025!` — rather than genuinely new secrets, and
that the resulting user behaviour is worse than the risk the rotation was
supposed to mitigate. CIS and DISA are written for environments where the
compensating controls NIST assumes (breach-corpus screening, monitoring for
compromise) are not necessarily present.

**Plumbline's position:** report the setting against the CIS threshold, at LOW
severity, and state the disagreement in the finding itself. The threshold is
CIS's because that is what most audits are run against. The severity is LOW
because a check whose premise is contested should not be shouting. The
disagreement is in the detail string because a tool that silently picked one
framework would be making a policy decision on the reader's behalf and
presenting it as a fact about their host.

An organisation following NIST should **suppress this check deliberately**, with
a reason recorded in the suppression file. That is a decision with an audit
trail. Having the tool make it for them silently is not.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/shadow` field 5 (max age), gated on field 2 (the crypt field) |
| Daemon default when unset | An empty field means no maximum. `PASS_MAX_DAYS` in `/etc/login.defs` supplies the value for *newly created* accounts only; it does not alter existing ones |
| Reference | `shadow(5)`, `chage(1)`, `login.defs(5)` |

## 4. Distribution variations

The `99999` default is universal across `shadow-utils`, so an unconfigured host
of any distribution fails this check identically.

`/etc/login.defs` `PASS_MAX_DAYS` differs — Debian ships 99999, RHEL 9 ships 99999,
Ubuntu ships 99999 — and in every case it governs only accounts created after it
was changed. **A host with a correct `login.defs` and old accounts still fails,
correctly**, which is the single most common surprise with this control. This
check reads the per-account field, which is the one that is actually enforced.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every authenticating account has max age ≤ 365 | — | how many accounts, and that NIST takes the opposite position |
| FAIL | an authenticating account has max age > 365 | LOW | the account, its value, that 99999 means "never" where applicable, and the framework conflict |
| FAIL | an authenticating account has an empty max age field | LOW | that an empty field means the password never expires |
| NOT_APPLICABLE | no account can authenticate with a password | — | that every entry is locked, empty or hashless |
| UNKNOWN | `/etc/shadow` unreadable | `insufficient_privileges` | which fact was unavailable |
| UNKNOWN | no violation found, but shadow or passwd is incomplete | `unparseable_source` / `ambiguous_system_state` | which file, and the line numbers |

## 6. Where this check cannot know

- **whether rotation is the right control for this host.** See §2. The check
  reports the file's contents; it cannot tell you which framework applies to you
- **whether the password is actually used.** An account with a hash may
  authenticate only over SSH with `PasswordAuthentication no` set, in which case
  the stored password is unreachable and its expiry governs nothing. SSHD-0002's
  facts are not consulted here
- **`PASS_MAX_DAYS` in `/etc/login.defs`**, which is not yet collected — that
  fact belongs to the AUTH work package. This check therefore cannot say whether
  a failing account is a leftover from before the default was corrected
- **directory-supplied accounts**, whose aging policy lives in the directory
- **when the password was last changed** (field 3), so it cannot report how
  close to expiry an account is, only whether a limit exists

## 7. Known false positives

The largest category is not a false positive but a policy disagreement, covered
in §2: a NIST-aligned organisation will see FAILs for a control it has
deliberately chosen not to implement, and should suppress the check.

The genuine false positive is a **service account with a stored hash that is
never used for password authentication** — the credential is unreachable, so its
expiry is irrelevant. The correct fix is usually to lock the account (`passwd
-l`), which removes it from this check's scope entirely and is a real
improvement rather than a suppression.

## 8. Remediation

| | |
|---|---|
| Summary | Decide which framework applies, then set a maximum age or suppress this check deliberately. |
| Effort | LOW |
| Steps | decide first whether rotation is intended at all; inspect with `chage -l`; set with `chage -M 365 <name>`; set `PASS_MAX_DAYS` for future accounts; confirm with `chage -l` |
| Commands | `chage -l <name>`, `awk -F: '$2 !~ /^[!*]/ && $2 != "" {print $1, $5}' /etc/shadow` |
| **Caution** | **Required.** Setting a maximum shorter than the time already elapsed since the last change expires the password *immediately*. On a service account that authenticates non-interactively, it simply stops working, with no interactive prompt to reveal why. |

## 9. Control mappings

- `nist-800-53-r5` IA-5
- `nist-800-53-r5` IA-5(1)

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | `root` and `alice` at max 365; locked accounts at 99999 | PASS |
| `users-aging` | `root` at 99999, `alice` with an empty field, `bob` at 20, `daemon` locked at 99999 | FAIL naming root and alice only |
| `users-locked-only` | every account locked | NOT_APPLICABLE |
| `users-unprivileged` | `/etc/shadow` unreadable | UNKNOWN, `insufficient_privileges` |
| `users-malformed` | compliant values, unparseable shadow lines | UNKNOWN, `unparseable_source` |
