# LOGGING-0004 — journald forwards to syslog where rsyslog is present

| Field | Value |
|---|---|
| **ID** | `LOGGING-0004` |
| **Module** | LOGGING |
| **Base severity** | LOW |
| **Tags** | logging, forensics, integration |
| **Facts required** | `logging.journald`, `logging.rsyslog` |
| **Since catalog** | 8 |
| **Platforms** | Linux, systemd distributions also running rsyslog |

## 1. What is tested

On a host where rsyslog is configured, `ForwardToSyslog` is **explicitly** set
to a true value under `[Journal]`.

## 2. Why it matters

On a host running both daemons, journald is where records arrive and rsyslog is
what sends them anywhere else. If journald does not hand them over, rsyslog's
forwarding rules (LOGGING-0002) receive nothing from the journal — **and the
host looks correctly configured from either file alone**.

That is the failure worth catching: two configurations that are each defensible
and that do not connect. An operator who set up remote logging in rsyslog and
sees LOGGING-0002 passing has every reason to believe records are leaving. The
gap is visible only by reading the two files together, which is what this check
does.

### Why an absent setting is FAIL and not UNKNOWN

journald's default for `ForwardToSyslog` has changed across systemd versions —
`yes` historically, `no` in current releases — and Plumbline does not read the
systemd version.

The proposition tested is therefore *"forwarding is explicitly configured"*, and
that is fully decided by the files: it is not set, so it is not explicitly
configured. Relying on an unstated default that has already flipped once is not
a configuration. The finding says the default is version-dependent rather than
asserting which way it falls, so nothing is guessed in either direction. This is
the same shape as CRON-0003.

## 3. Source of truth

| | |
|---|---|
| Source | `ForwardToSyslog=` under `[Journal]`, and whether rsyslog is configured |
| Daemon default when unset | Version-dependent; deliberately not relied upon |
| Reference | `journald.conf(5)` |

Precedence is last-wins across drop-ins, as for LOGGING-0003.

## 4. Distribution variations

Debian and Ubuntu install rsyslog by default and ship `ForwardToSyslog`
commented out, so a stock install of either fails. Fedora and RHEL 8+ do not
install rsyslog by default, so this check is NOT_APPLICABLE on a stock install
of either.

## 5. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | explicitly true | — | the file and line |
| FAIL | explicitly false, with rsyslog configured | LOW | that rsyslog's rules are sending an empty stream |
| FAIL | not set, with rsyslog configured | LOW | that the default is version-dependent and both files look correct in isolation |
| NOT_APPLICABLE | rsyslog is not configured | — | that a journald-only host has nothing to forward to |
| UNKNOWN | a value systemd would reject | `unparseable_source` | the values systemd accepts |
| UNKNOWN | the configuration could not be read | `insufficient_privileges` | which fact was unavailable |

## 6. Where this check cannot know

- **whether rsyslog is actually running.** The check reads rsyslog's
  *configuration*; a host with an unused rsyslog.conf and a masked unit gets a
  FAIL for a connection nobody wants. Removing rsyslog is the better fix there,
  and it makes this NOT_APPLICABLE
- **whether records arrive.** `imjournal` and the `/run/systemd/journal/syslog`
  socket are the mechanism, and either can be broken independently of this
  setting
- **the systemd version**, which is what decides the default this check refuses
  to rely on
- **`ForwardToWall`, `ForwardToKMsg`, `ForwardToConsole`** — related keys with
  different purposes, not read here

## 7. Known false positives

A host where rsyslog is installed but deliberately unused — a package
dependency nobody removed. The finding is correct about the files; removing
rsyslog is the better response than suppressing it.

## 8. Remediation

| | |
|---|---|
| Summary | Set `ForwardToSyslog=yes` explicitly, or remove rsyslog if it is not being used. |
| Effort | LOW |
| Steps | decide which daemon owns forwarding first — removing an unused rsyslog is often the right fix; set the value explicitly **even if the current default already does what you want**, since it has changed once; restart journald; **verify with `logger` that the line reaches the rsyslog-written file**, not only `journalctl` |
| Commands | `systemd-analyze cat-config systemd/journald.conf \| grep -i forwardtosyslog`, `logger -p auth.info plumbline-test` |
| **Caution** | **Required.** Turning forwarding on doubles log volume on a host that also persists the journal, and on a busy host that can fill `/var` faster than anybody expects. Check `SystemMaxUse` and the rsyslog side's rotation before making the change. |

## 9. Control mappings

- `nist-800-53-r5` AU-6
- `nist-800-53-r5` AU-9(2)

## 10. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `logging-compliant` | `ForwardToSyslog=yes` in a drop-in | PASS |
| `logging-legacy` | `ForwardToSyslog=yes` in the main file | PASS |
| `logging-weak` | `ForwardToSyslog=no` with rsyslog present | FAIL, LOW |
| `logging-nodefault` | unset with rsyslog present | FAIL, LOW |
| `logging-rsyslog-absent` | journald only | NOT_APPLICABLE |
| `logging-absent` | neither daemon | NOT_APPLICABLE |
