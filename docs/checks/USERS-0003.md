# USERS-0003 — No account has an empty password

| Field | Value |
|---|---|
| **ID** | `USERS-0003` |
| **Module** | USERS |
| **Base severity** | CRITICAL |
| **Tags** | users, authentication, credentials |
| **Facts required** | `users.shadow`, `users.passwd` |
| **Since catalog** | 4 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

No entry in `/etc/shadow` has an empty password field.

## 2. Why it matters

An empty password field means the account authenticates with **no password at
all**. Wherever the PAM stack consults shadow — console login, `su`, and any
service configured to use it — pressing return is sufficient.

This is not a theoretical state. It is produced by `passwd -d`, by automated
provisioning that intended to set a password later, and by restoring a partial
backup.

It is distinct from a locked account, and the distinction is the whole check: a
lock token (`!`, `!!`, `*`) means **no** password can ever match, which is safe;
an empty field means **every** password matches, which is the opposite. A
parser that treated them alike would report the safe state as the dangerous one
and the dangerous one as safe.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/shadow`, field 2 |
| Daemon default when unset | Not applicable |
| Reference | `shadow(5)`, `crypt(5)` |

**The fact carries no hash.** Only the properties a check judges — empty,
locked, which crypt scheme — are recorded, and the hash and salt are discarded
inside the collector. See ADR-0015.

## 4. Distribution variations

None in the file format. Whether an empty field actually permits login depends
on the PAM stack: `pam_unix` with `nullok` accepts it, and without `nullok`
refuses it. Modern Debian and Ubuntu removed `nullok` from the default stack;
several other distributions and most container base images have not.

**This check reports the state regardless of the PAM stack**, because the
account is one `nullok` away from being open and because the PAM configuration
is a separate fact this module does not have. WP-24 (AUTH) collects the PAM
stack, and a future refinement may raise or lower the severity accordingly.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | no entry has an empty password field | — | how many entries were examined |
| FAIL | at least one entry has an empty password field | CRITICAL | which accounts, and that this is the opposite of a locked entry |
| UNKNOWN | `/etc/shadow` was unreadable | — | `insufficient_privileges` — resolved by the runner's required-fact gate |
| UNKNOWN | the file contains no entries | — | `ambiguous_system_state` |
| UNKNOWN | no violation found, but shadow or passwd has unparseable lines | — | `unparseable_source` / `ambiguous_system_state` |
| SKIPPED | runner-decided | — | — |

## 6. Where this check cannot know

- **`/etc/shadow` unreadable.** This is the module's main `UNKNOWN` path and
  the expected outcome of an unprivileged scan. It is resolved by the runner's
  required-fact gate, which reports `insufficient_privileges` and cites
  `/etc/shadow` as evidence. `users.shadow` is listed first in `Requires` so
  the gate reports the interesting fact rather than an incidental one
- unparseable lines in either file → the negative result becomes `UNKNOWN`
- **an empty password field in `/etc/passwd` itself** is not covered. On a
  shadowed system field 2 of `/etc/passwd` is always `x`; a host that is not
  shadowed at all is outside this check and would need its own
- whether `nullok` is set in the PAM stack — see §4
- accounts supplied by a directory service have no entry here

## 7. Known false positives

A host whose PAM stack omits `nullok` refuses empty-password logins even though
the field is empty. The state is still wrong and one configuration change away
from being exploitable; suppress with a justification if the PAM stack is
verified and pinned.

## 8. Remediation

| | |
|---|---|
| Summary | Set a password on the account, or lock it if it should not authenticate. |
| Effort | LOW |
| Steps | decide whether the account is used by a person or a daemon; `passwd -l` for a service account, `passwd` for a person; verify with `passwd -S`; check `lastlog` for use while it was open |
| Commands | `passwd -S <name>`, `passwd -l <name>` |
| **Caution** | **Required.** Locking an account a service authenticates as stops that service; locking root can remove the console recovery path. |

## 9. Control mappings

- `nist-800-53-r5` IA-5
- `nist-800-53-r5` IA-2
- `nist-800-53-r5` AC-2

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | hashes and lock tokens, no empty fields | PASS |
| `users-nopassword` | `www-data` and `alice` have empty fields, beside locked entries | FAIL, only the empty ones named |
| `users-unprivileged` | `/etc/shadow` refused | UNKNOWN(`insufficient_privileges`) |
| `users-malformed` | shadow has an unparseable line | UNKNOWN(`unparseable_source`) |
