# LOGGING-0002 — Logs are forwarded to a remote collector

| Field | Value |
|---|---|
| **ID** | `LOGGING-0002` |
| **Module** | LOGGING |
| **Base severity** | MEDIUM |
| **Tags** | logging, forensics, tamper-resistance |
| **Facts required** | `logging.rsyslog` |
| **Since catalog** | 8 |
| **Platforms** | Linux, all distributions running rsyslog |

## 1. What is tested

At least one remote destination is configured, in either syntax:

```
*.* @@logs.example.net:514                          legacy, TCP
*.* @logs.example.net:514                           legacy, UDP
action(type="omfwd" target="..." protocol="tcp")    RainerScript
action(type="omrelp" target="...")                  RainerScript, RELP
```

Whether the transport is adequate is LOGGING-0005's question. A UDP destination
passes this check.

## 2. Why it matters

A log that exists only on the host it describes is not evidence. It is a file
the attacker who took the host can edit, truncate or delete, and doing so is one
of the first things any competent intrusion does — before anybody knows to go
looking. **Every other check in this module protects a record that a local-only
configuration allows to be erased.**

Forwarding changes what an attacker must accomplish. To hide from a remote
collector they must compromise the collector too, or the network path to it, and
either is a second operation with its own noise. The forwarded copy is also what
makes cross-host correlation possible at all: an intrusion touching five
machines is visible in the aggregate long before it is visible on any one.

## 3. Source of truth

| | |
|---|---|
| Source | legacy rules whose action begins `@` or `@@`; `omfwd` and `omrelp` actions |
| Daemon default when unset | No forwarding. rsyslog forwards nowhere unless told to |
| Reference | rsyslog `omfwd` documentation |

## 4. Distribution variations

No distribution ships forwarding configured, so this fails on every stock host —
correctly. Where it is configured, Debian-family hosts more often use the legacy
`@@host` form and RHEL-family hosts more often use `omfwd`, which is why the
check reads both rather than the one its author happened to have.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | one or more destinations configured | — | each target, its transport, and its file and line |
| FAIL | no destination in any file read | MEDIUM | that the log exists only on this host |
| NOT_APPLICABLE | rsyslog is not configured | — | — |
| UNKNOWN | none found, but an include did not resolve | `ambiguous_system_state` | which include failed |
| UNKNOWN | the configuration could not be read | `insufficient_privileges` | which fact was unavailable |

## 6. Where this check cannot know

- **whether the collector receives anything.** A destination pointing at a
  listener that drops the traffic passes this check and is worse than none,
  because it looks configured. Only an end-to-end test answers that
- **whether the transport is encrypted.** `omfwd` over TLS and over plaintext
  TCP are indistinguishable to this check, and forwarding authentication logs
  in the clear across an untrusted path is its own exposure
- **journald's remote forwarding.** `systemd-journal-upload` is a separate
  mechanism this module does not collect, so a host forwarding that way is
  reported as not forwarding
- **whether the destination is reachable**, or whether the queue is configured
  to survive an outage rather than discard

## 7. Known false positives

A host that forwards through `systemd-journal-upload`, a vendor agent, or a
sidecar reading the journal directly. Each is real remote logging that this
check cannot see; suppress with the mechanism named.

## 8. Remediation

| | |
|---|---|
| Summary | Configure a remote destination, using a reliable transport. |
| Effort | MEDIUM |
| Steps | confirm the collector will accept from this host first; prefer `action(type="omfwd" ... protocol="tcp" queue.type="linkedlist" queue.filename="fwd" action.resumeRetryCount="-1")`; the legacy equivalent is `*.* @@host:514`; encrypt where the path is untrusted; **verify with `logger` end to end** rather than assuming a clean restart means it works |
| Commands | `grep -rEn '^\*\.\*\|omfwd\|omrelp\|@@' /etc/rsyslog.conf /etc/rsyslog.d/`, `logger -p auth.info plumbline-test` |
| **Caution** | **Required.** Forwarding sends the contents of your logs — authentication records and anything an application logged carelessly — across the network to another host. Confirm the transport is encrypted where the path is not trusted, and confirm the collector's own retention and access controls before pointing production hosts at it. |

## 9. Control mappings

- `nist-800-53-r5` AU-9(2)
- `nist-800-53-r5` AU-4
- `nist-800-53-r5` AU-6

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `logging-compliant` | `omfwd` over TCP | PASS |
| `logging-legacy` | `*.* @@host:514` | PASS |
| `logging-weak` | `*.* @host:514` — UDP, but still a destination | PASS |
| `logging-nodefault` | local files only | FAIL, MEDIUM |
| `logging-rsyslog-absent` | journald only | NOT_APPLICABLE |
| `logging-unresolved-include` | none found, include matched nothing | UNKNOWN, `ambiguous_system_state` |
