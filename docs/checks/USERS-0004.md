# USERS-0004 — Password hashes use a modern algorithm

| Field | Value |
|---|---|
| **ID** | `USERS-0004` |
| **Module** | USERS |
| **Base severity** | HIGH |
| **Tags** | users, authentication, credentials, cryptography |
| **Facts required** | `users.shadow`, `users.passwd` |
| **Since catalog** | 4 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every stored password hash uses a crypt scheme that still resists offline
cracking.

## 2. Why it matters

A password hash is only as good as the work it costs to test a guess. The old
schemes cost almost nothing on modern hardware: DES crypt considers only the
first eight characters of a password and falls to exhaustive search in minutes,
and MD5-crypt runs at billions of guesses per second on a commodity GPU. A file
full of those hashes is a list of passwords with a short delay attached.

**Changing the system's hashing scheme does not rewrite existing hashes.** Each
account keeps whatever it was hashed with until its password is next changed,
so a host that switched years ago can still be carrying MD5 hashes for accounts
nobody has touched — which are exactly the accounts nobody is watching.

## 3. Source of truth

| | |
|---|---|
| Source | `/etc/shadow`, field 2, `$id$` prefix |
| Daemon default when unset | Not applicable |
| Reference | `crypt(5)` |

| Prefix | Scheme | Verdict |
|---|---|---|
| none (13 chars) | DES crypt | weak |
| `$1$` | MD5-crypt | weak |
| `$5$` | SHA-256-crypt | weak |
| `$2a$` `$2b$` `$2y$` | bcrypt | strong |
| `$6$` | SHA-512-crypt | strong |
| `$7$` | scrypt | strong |
| `$y$` | yescrypt | strong |
| `$gy$` | gost-yescrypt | strong |
| anything else | unrecognised | **neither** — see §6 |

SHA-256 is classed weak alongside MD5 deliberately: it is fast and not
memory-hard, and every distribution that offers it also offers SHA-512 at no
cost.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| Debian 12+, Ubuntu 22.04+, Fedora | Default `yescrypt` | Not verified on live hosts |
| RHEL family | Default `SHA-512` | Not verified on live hosts |
| Long-lived hosts of any distribution | Carry hashes from whatever was default when each password was last set | — |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every stored hash uses a strong scheme | — | how many hashes were assessed |
| FAIL | at least one uses a known-weak scheme | HIGH | which accounts, **which scheme each uses**, and that changing the system default does not rewrite an existing hash |
| NOT_APPLICABLE | no account stores a hash at all | — | that every entry is locked or empty, so there is no algorithm in use to assess |
| UNKNOWN | `/etc/shadow` was unreadable | — | `insufficient_privileges` |
| UNKNOWN | a scheme identifier is not recognised, and nothing is known-weak | — | `ambiguous_system_state` |
| SKIPPED | runner-decided | — | — |

**Locked and empty accounts are skipped, not failed.** They store no hash;
counting a locked account as a weak hash would report a safe state as a
failure, and the empty case is USERS-0003's.

## 6. Where this check cannot know

- **an unrecognised scheme is neither weak nor strong.** A scheme newer than
  this build looks exactly like a corrupted field, and calling it either would
  be an invention. Where nothing else is weak, the result is `UNKNOWN`; where
  something is, the FAIL stands and the unrecognised entries are named
  alongside it
- `/etc/shadow` unreadable → `UNKNOWN(insufficient_privileges)`
- **the cost parameters are not judged.** `$6$` with `rounds=1000` is far
  weaker than `$6$` with the default 5000, and `$2b$04$` is a bcrypt with a
  cost low enough to matter. This check judges the scheme; a refinement judging
  work factors would need the fact to carry them, and the fact deliberately
  carries as little of the hash as it can (ADR-0015)
- the strength of the passwords themselves is unknowable from a hash, which is
  the point of a hash

## 7. Known false positives

Hosts that must interoperate with a legacy system requiring a specific scheme.
The exposure is real; suppress with a justification.

## 8. Remediation

| | |
|---|---|
| Summary | Change the affected passwords so they are re-hashed with the system's current scheme. |
| Effort | MEDIUM |
| Steps | confirm `ENCRYPT_METHOD` in `/etc/login.defs`; force a change per affected account with `passwd` or `chage -d 0`; lock accounts nobody logs into instead; re-run the audit |
| Commands | `grep ENCRYPT_METHOD /etc/login.defs`, `chage -d 0 <name>` |
| **Caution** | **Required.** `chage -d 0` on a service account that authenticates non-interactively locks it out silently at its next authentication. |

## 9. Control mappings

- `nist-800-53-r5` IA-5(1)
- `nist-800-53-r5` SC-13

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `users-clean` | SHA-512 and yescrypt | PASS |
| `users-weakhash` | root on MD5, alice on DES | FAIL, both named with their scheme |
| `users-locked-only` | every account locked | NOT_APPLICABLE |
| `users-unprivileged` | `/etc/shadow` refused | UNKNOWN(`insufficient_privileges`) |
