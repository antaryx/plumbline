# USERS-0010 — Passwords that can authenticate have a minimum age set

| Field | Value |
|---|---|
| **ID** | `USERS-0010` |
| **Module** | USERS |
| **Base severity** | LOW (escalates to MEDIUM, see §5) |
| **Tags** | users, credentials, password-policy |
| **Facts required** | `users.shadow`, `users.passwd` |
| **Since catalog** | 5 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Two propositions over every account that can actually authenticate with a
password:

1. Field 4 of `/etc/shadow` — the minimum age — is at least 1 day.
2. The minimum age is not **greater than** the maximum age.

"Can actually authenticate" means the entry is not locked, its password field is
not empty, and it holds a stored hash — `fact.ShadowEntry.Authenticates()`.

## 2. Why it matters

Field 4 is the number of days that must pass before a password may be changed
again, and its purpose is narrower than it looks: **it is what makes password
history mean anything**. With a minimum of zero, a user told to choose a new
password can run `passwd` as many times as the history depth and arrive back at
the password they started with, in one sitting, without violating any policy.
A minimum of one day makes that cost a day per cycle, which is enough to make it
pointless.

The second proposition is a different kind of failure and does not depend on
history at all. An account whose minimum exceeds its maximum is **locked out by
construction**: the password expires and login demands a change, and `passwd`
refuses the change because the minimum has not elapsed. The user cannot recover
without an administrator, and nothing in the login message explains why. That is
an availability failure produced by a policy setting, which is why it is
reported separately and at a higher severity.

The inequality is strict on purpose. With `min == max` the change is permitted
on exactly the day the password expires — tight, but it works. Only `min > max`
leaves a window in which a change is both required and refused.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/shadow` fields 4 and 5, gated on field 2 (the crypt field) |
| Daemon default when unset | An empty field means no minimum. `PASS_MIN_DAYS` in `/etc/login.defs` supplies the value for *newly created* accounts only |
| Reference | `shadow(5)`, `chage(1)`, `pam_pwhistory(8)` |

## 4. Distribution variations

`shadow-utils` writes 0 by default everywhere, so an unconfigured host of any
distribution fails the first proposition identically.

What differs is whether the setting has any effect. The minimum age protects
password history, and history is only enforced where `pam_pwhistory` or
`pam_unix`'s `remember=` option is configured. Debian and Ubuntu ship neither by
default; RHEL 8 and later enable `pam_pwhistory` through `authselect` profiles
on many installations. **On a host with no history configured, this control
protects nothing** — which is why the base severity is LOW.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every authenticating account has min ≥ 1 and min ≤ max | — | how many accounts were examined |
| FAIL | an authenticating account has min 0 or an empty min field | LOW | the account and its value, and that history can be cycled in one sitting |
| FAIL | an authenticating account has min > max | **MEDIUM** | the account, both values, and that it is locked out by construction |
| NOT_APPLICABLE | no account can authenticate with a password | — | that every entry is locked, empty or hashless |
| UNKNOWN | `/etc/shadow` unreadable | `insufficient_privileges` | which fact was unavailable |
| UNKNOWN | no violation found, but shadow or passwd is incomplete | `unparseable_source` / `ambiguous_system_state` | which file, and the line numbers |

The MEDIUM escalation is a per-outcome `Severity` override, not a second base
severity: a finding that contains **any** locked-out account is reported at
MEDIUM, and the missing-minimum accounts are reported in the same finding rather
than being swallowed by the escalation.

## 6. Where this check cannot know

- **whether password history is enforced on this host.** `pam_pwhistory` and
  `pam_unix remember=` live in the PAM stack, which this module does not
  collect; that fact belongs to the AUTH work package. Until it exists, this
  check cannot distinguish a host where the minimum matters from one where it is
  inert, and reports the setting either way at LOW
- **`PASS_MIN_DAYS` in `/etc/login.defs`**, for the same reason, so it cannot say
  whether a failing account predates a corrected default
- **whether the password is used at all.** As with USERS-0009, an account whose
  password is unreachable — key-only SSH, for instance — has an aging policy that
  governs nothing
- **directory-supplied accounts**, whose policy lives in the directory

## 7. Known false positives

An account that is deliberately rotated on demand — a break-glass credential, or
one an incident-response process changes twice in a day — should **not** carry a
minimum age, and the finding against it is correct about the file but wrong
about the intent. Suppress it with a justification.

Where no password history is configured (§4), every FAIL of the first
proposition is technically correct and practically inert. The right response is
usually to configure history rather than to suppress the check, since the
minimum without history and history without the minimum are each half a control.

## 8. Remediation

| | |
|---|---|
| Summary | Set a minimum age of at least one day, and never above the maximum. |
| Effort | LOW |
| Steps | inspect both fields together with `chage -l`; `chage -m 1 <name>`; where min exceeds max fix both at once with `chage -m 1 -M 365 <name>`; set `PASS_MIN_DAYS` for future accounts; confirm password history is actually enforced or the setting protects nothing |
| Commands | `chage -l <name>`, `awk -F: '$2 !~ /^[!*]/ && $2 != "" {print $1, $4, $5}' /etc/shadow` |
| **Caution** | **Required.** Do not set a minimum on an account whose password may need urgent rotation. An incident response that has to change a credential twice in one day will be refused by `passwd`, and the account will have to be edited by an administrator instead. |

## 9. Control mappings

- `nist-800-53-r5` IA-5
- `nist-800-53-r5` IA-5(1)

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | `root` and `alice` at min 1 | PASS |
| `users-aging` | `root` at min 0, `alice` with an empty field, `bob` at min 30 / max 20, `daemon` locked | FAIL at MEDIUM, all three named, `daemon` absent |
| `users-locked-only` | every account locked | NOT_APPLICABLE |
| `users-unprivileged` | `/etc/shadow` unreadable | UNKNOWN, `insufficient_privileges` |
| `users-malformed` | compliant values, unparseable shadow lines | UNKNOWN, `unparseable_source` |
