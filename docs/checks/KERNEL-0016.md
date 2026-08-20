# KERNEL-0016 — TCP SYN cookies are enabled

| Field | Value |
|---|---|
| **ID** | `KERNEL-0016` |
| **Module** | KERNEL |
| **Base severity** | LOW |
| **Tags** | kernel, network, denial-of-service, availability |
| **Facts required** | `kernel.sysctl` |
| **Since catalog** | 3 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

The running value of `net.ipv4.tcp_syncookies` is `1` or greater.

## 2. Why it matters

A SYN flood fills a listening socket's backlog with half-open connections from
addresses that never complete the handshake. The queue is finite, so once it is
full the service refuses legitimate connections while using almost no resources
on the attacker's side.

SYN cookies remove the queue from the equation: when the backlog overflows the
kernel stops storing connection state and encodes it in the sequence number it
returns, reconstructing the connection only if the client completes the
handshake. The cost is that a few TCP options cannot be carried in a cookie, so
the kernel enables them only under overflow rather than always.

**Severity is LOW deliberately.** This is availability hardening — it grants an
attacker nothing, it removes a cheap way to deny service. Rating it alongside a
privilege escalation would mis-rank an operator's triage queue, which is a real
cost paid by every user of the tool.

## 3. Source of truth

| | |
|---|---|
| Source | `/proc/sys/net/ipv4/tcp_syncookies` |
| Daemon default when unset | The parameter always exists where `CONFIG_SYN_COOKIES` is set. Kernel default is `1`. |
| Reference | `Documentation/networking/ip-sysctl.rst` |

`0` off. `1` cookies used when the backlog overflows. `2` cookies used
unconditionally.

## 4. Distribution variations

| Distro | Variation | Verified? |
|---|---|---|
| All mainstream distributions | Ship `1`; it is the kernel default | Not verified on live hosts |

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | running value is 1 | — | that the kernel falls back to cookies on overflow |
| PASS | running value is 2 | — | that cookies are unconditional and that this disables some TCP options for every connection |
| FAIL | running value is 0 | LOW | that a SYN flood can deny service using very little bandwidth |
| NOT_APPLICABLE | the parameter does not exist | — | that this kernel does not expose it |
| UNKNOWN | unreadable | — | `insufficient_privileges` |
| UNKNOWN | not an integer | — | `unparseable_source` |
| SKIPPED | runner-decided | — | — |

`2` passes rather than being preferred: it is stricter but costs TCP options on
every connection, and a check that demanded it would push operators toward a
worse default.

## 6. Where this check cannot know

- unreadable parameter → `UNKNOWN(insufficient_privileges)`
- non-integer value → `UNKNOWN(unparseable_source)`
- parameter absent (kernel built without `CONFIG_SYN_COOKIES`) →
  `NOT_APPLICABLE`
- whether anything upstream — a load balancer, a SYN proxy, a scrubbing service
  — already absorbs floods before they reach this host. Such a host is
  adequately protected and will still fail this check

## 7. Known false positives

Hosts behind a SYN-proxying load balancer, and hosts whose listening sockets
are unreachable from any untrusted network. Both are legitimate suppressions
with a justification.

## 8. Remediation

| | |
|---|---|
| Summary | Set `net.ipv4.tcp_syncookies` to 1 and persist it in `/etc/sysctl.d/`. |
| Effort | LOW |
| Steps | apply with `sysctl -w`, persist in a drop-in, verify. Leave the value at 1 rather than 2 unless there is a specific reason |
| Commands | `sysctl -w net.ipv4.tcp_syncookies=1` |
| **Caution** | Not required. |

## 9. Control mappings

- `nist-800-53-r5` SC-5

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `kernel-hardened` | value 1 | PASS |
| `kernel-weak` | value 0 | FAIL / LOW |
| `kernel-partial` | value 2 | PASS |
| `kernel-denied` | exists, unreadable | UNKNOWN(`insufficient_privileges`) |
