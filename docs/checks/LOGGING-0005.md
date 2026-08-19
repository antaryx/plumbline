# LOGGING-0005 — Remote log forwarding uses a reliable transport

| Field | Value |
|---|---|
| **ID** | `LOGGING-0005` |
| **Module** | LOGGING |
| **Base severity** | MEDIUM |
| **Tags** | logging, forensics, network, tamper-resistance |
| **Facts required** | `logging.rsyslog` |
| **Since catalog** | 8 |
| **Platforms** | Linux, all distributions running rsyslog |

## 1. What is tested

Every configured remote destination uses TCP or RELP. A destination whose
protocol is not stated is treated as UDP, because that is `omfwd`'s documented
default.

## 2. Why it matters

Forwarding over UDP drops messages silently, and it drops them hardest **under
load** — precisely the condition that produces the logs worth keeping. A host
under attack generates a burst of authentication failures, and a UDP forwarder
discards whatever the socket buffer cannot hold, with no error anywhere and no
gap anything downstream can detect. The collector receives a plausible-looking
stream that is missing the interesting part.

Two further properties make UDP wrong here:

- It is **connectionless**, so a collector that is down produces no failure on
  the sending side at all. The host carries on believing it is forwarding.
- It is **trivially spoofable**. An attacker on the path can inject records the
  collector will attribute to this host, turning the log from evidence into
  something an adversary can write to.

TCP fixes the silent loss and makes an unreachable collector visible. RELP
closes the remaining gap — TCP acknowledges receipt by the kernel, RELP
acknowledges processing by the application — and is the right answer where the
log is genuinely evidentiary.

## 3. Source of truth

| | |
|---|---|
| Source | the transport of each destination: `@` vs `@@` in legacy syntax, `protocol=` on `omfwd`, `omrelp` |
| Daemon default when unset | **`omfwd` defaults to UDP**, documented and stable |
| Reference | rsyslog `omfwd` documentation, RFC 5424 |

Treating an unstated protocol as UDP is reporting a documented scalar default,
not guessing at a value compiled into a binary — and the finding says which it
is doing, naming the default rather than presenting UDP as an observation.

## 4. Distribution variations

None. The syntax and the default are rsyslog's, not the distribution's.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every destination uses TCP or RELP | — | each target and its transport |
| FAIL | any destination uses UDP | MEDIUM | each one, and that the loss is silent and worst under load |
| FAIL | any destination states no protocol | MEDIUM | that `omfwd` defaults to UDP, distinctly from an explicit UDP setting |
| NOT_APPLICABLE | no remote destination configured | — | that LOGGING-0002 reports the absence |
| UNKNOWN | none found, but an include did not resolve | `ambiguous_system_state` | that the absence itself cannot be established |
| UNKNOWN | the configuration could not be read | `insufficient_privileges` | which fact was unavailable |

The NOT_APPLICABLE case is deliberate: the absence of forwarding is a real
finding and it is LOGGING-0002's. Reporting it here as well would put the same
defect in front of the reader twice under two names, and they would fix one and
see the other still open.

**That NOT_APPLICABLE is itself gated on unresolved includes**, because "there
is no transport to assess" is a claim about absence exactly as a PASS would be.

## 6. Where this check cannot know

- **whether the transport is encrypted.** TCP and TCP-with-TLS are
  indistinguishable here, and plaintext TCP still exposes the log contents on
  the wire — it fixes reliability, not confidentiality
- **whether a queue is configured.** TCP without a disk-assisted queue moves the
  loss rather than removing it, and can block rsyslog when the collector is
  slow. The remediation covers it; the check does not assert it
- **whether the collector is reachable**, or whether it accepts the protocol
  configured
- **RELP's own configuration.** `omrelp` is treated as reliable on the strength
  of the module alone

## 7. Known false positives

A deliberately UDP-only path to a collector on a trusted local segment, chosen
for throughput. That is a real trade-off; the finding describes it correctly and
should be suppressed with the reasoning recorded.

## 8. Remediation

| | |
|---|---|
| Summary | Move the destination to TCP or RELP, and give it a disk-assisted queue. |
| Effort | MEDIUM |
| Steps | **confirm the collector accepts the new transport first** — a UDP-only listener will simply stop receiving, silently; legacy: change `@` to `@@`; RainerScript: set `protocol="tcp"` or switch to `omrelp`; **add a queue**, or TCP only moves the loss; verify by stopping the collector briefly and confirming this host queues rather than drops |
| Commands | `grep -rEn '@@?[a-zA-Z0-9]\|omfwd\|omrelp' /etc/rsyslog.conf /etc/rsyslog.d/`, `ss -tnp \| grep :514` |
| **Caution** | **Required.** TCP forwarding without a queue can block rsyslog when the collector is slow or unreachable, which on some configurations blocks the applications writing to it. Configure a disk-assisted queue and a resume-retry count in the same change — moving to TCP without one trades silent loss for an availability risk. |

## 9. Control mappings

- `nist-800-53-r5` AU-9(2)
- `nist-800-53-r5` AU-4
- `nist-800-53-r5` SC-8

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `logging-compliant` | `omfwd` with `protocol="tcp"` | PASS |
| `logging-legacy` | `*.* @@host:514` | PASS |
| `logging-weak` | `*.* @host:514` — UDP | FAIL, MEDIUM |
| `logging-nodefault` | no destination at all | NOT_APPLICABLE |
| `logging-rsyslog-absent` | journald only | NOT_APPLICABLE |
| `logging-unresolved-include` | none found, include matched nothing | UNKNOWN, `ambiguous_system_state` |
