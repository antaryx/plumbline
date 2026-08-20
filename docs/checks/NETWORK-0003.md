# NETWORK-0003 — Exactly one firewall configuration is in force

| Field | Value |
|---|---|
| **ID** | `NETWORK-0003` |
| **Module** | NETWORK |
| **Base severity** | MEDIUM |
| **Tags** | network, firewall, configuration-conflict |
| **Facts required** | `network.firewall` |
| **Since catalog** | 10 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

The active firewall configurations are all of **one kind**.

## 2. Two configurations do not add up

They overwrite each other, and which one survives depends on unit start order
rather than on anything anybody wrote down.

The mechanism is the same in every combination. ufw and firewalld are
**managers**: each owns the ruleset, and each begins by flushing what is there
and installing its own. A saved ruleset — `nftables.conf`, an iptables-save
file — is loaded verbatim by its own unit. Whichever runs last wins outright,
and the others' rules are simply not in the kernel afterwards.

**The danger is not that the host ends up unprotected.** It usually does not;
one of the two is generally sane. The danger is that somebody **edits the wrong
file**: they add an allow rule to `nftables.conf`, reload it, watch the service
report success, and the rule is gone at the next boot when ufw flushes the
table. Or they remove a rule believing they have closed a port that firewalld is
still opening. Every subsequent change is made against a model of the host that
is wrong, and nothing in the tooling says so — each tool reports its own view
correctly.

This is the same shape as the trap CRON-0003 names: a configuration file that
is maintained, believed, and inert.

## 3. What counts as one configuration

**Two files of the same kind are one configuration.** `rules.v4` and `rules.v6`
are the IPv4 and IPv6 halves of a single iptables ruleset, loaded together.
Counting them as two would fail this check on every host that filters IPv6.

**A manager plus a saved ruleset counts as two**, because it is. The manager
flushes the table the ruleset installed; the ruleset file keeps existing, keeps
being edited, and stops meaning anything.

Only *active* configurations are counted (NETWORK-0001 §3): a comments-only
`nftables.conf` beside an enabled ufw is one configuration, not two, which is
what keeps a stock Debian package install from producing a finding.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | exactly one kind is active | — | which, and that the file an operator edits is the one that governs |
| FAIL | two or more kinds are active | MEDIUM | which combination, **and the specific mechanism** — two managers cannot coexist at all; a manager flushes a saved ruleset |
| NOT_APPLICABLE | no firewall is configured | — | that NETWORK-0001 reports the absence |
| UNKNOWN | a candidate file could not be read | `insufficient_privileges` | that the refused file could be a second configuration |

The FAIL is unguarded: a file we could not read could only *add* to the count,
never reduce it, so an incomplete read cannot invalidate a conflict we found.

## 5. Where this check cannot know

- **which one is actually in effect.** That depends on unit start order and on
  what is enabled, neither of which is in this fact. The remediation's first
  step is to find out, because the answer is often not the one the team believes
- **whether the two rulesets agree.** If they were identical the conflict would
  be harmless. Comparing them means understanding two rule languages well
  enough to prove semantic equivalence, which is a different project
- **`iptables-nft`.** On a modern host `iptables` is a shim over nftables, so
  the two *backends* are one. This check is about two **configuration files**
  being maintained, which is a conflict regardless of the backend beneath them

## 6. Known false positives

A host mid-migration, where both configurations are deliberately present while
the new one is validated. Correct, temporary, and worth suppressing with an
expiry — the finding exists precisely so that the temporary state does not
become permanent unnoticed.

## 7. Remediation

| | |
|---|---|
| Summary | Choose the tool the distribution manages, migrate the other's rules into it, and remove the loser outright. |
| Effort | MEDIUM |
| Steps | **Find out which one is actually in effect first** — compare `nft list ruleset` against each file; choose by what the distribution manages; migrate the loser's rules **from the file**, since they are not loaded and will not appear in the kernel; disable **and mask** the losing unit; remove the losing file, because an inert firewall configuration is one somebody will eventually edit believing it works; verify from another host |
| Commands | `nft list ruleset`, `systemctl is-enabled ufw firewalld nftables iptables`, `ufw status verbose` |
| **Caution** | **Required.** Removing the configuration that turns out to be the one in effect opens every port it was closing, invisibly until something is scanned. Establish which is loaded before disabling either. |

## 8. Control mappings

- `nist-800-53-r5` CM-6
- `nist-800-53-r5` SC-7

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `network-nftables` | one saved ruleset | PASS |
| `network-both` | ufw **and** firewalld, each individually sound | FAIL, MEDIUM |
| `network-none` | no firewall configured | NOT_APPLICABLE |
| `network-denied` | the one file present is unreadable | UNKNOWN, `insufficient_privileges` |
