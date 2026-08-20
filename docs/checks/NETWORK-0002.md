# NETWORK-0002 — The firewall's default inbound policy denies

| Field | Value |
|---|---|
| **ID** | `NETWORK-0002` |
| **Module** | NETWORK |
| **Base severity** | HIGH |
| **Tags** | network, firewall, default-deny |
| **Facts required** | `network.firewall` |
| **Since catalog** | 10 |
| **Platforms** | Linux, all distributions |

## 1. What is tested

Every active firewall configuration's default disposition for unmatched
inbound traffic is drop or reject.

## 2. The default is what the firewall is

A firewall is a list of exceptions to a default, and everything else is detail.

**Default-accept with a list of blocks is a deny list.** It protects against
the ports somebody thought of on the day they wrote it and against nothing
else. Every port a future package opens is reachable the moment it opens; every
service moved to a new port is reachable at the new one. The ruleset does not
have to be wrong for this — it only has to be finished.

**Default-deny with a list of allows fails closed.** A new listening socket is
unreachable until somebody decides otherwise, which converts "we did not think
of it" from an exposure into an inconvenience. That is the whole value of a host
firewall, and a default-accept ruleset does not have it however many rules it
contains.

## 3. Where the default is written, per tool

| Tool | Source | Deny looks like |
|---|---|---|
| nftables | the `input` chain | `policy drop;` / `policy reject;` |
| iptables | the saved `:INPUT` line | `:INPUT DROP [0:0]` |
| ufw | `/etc/default/ufw` | `DEFAULT_INPUT_POLICY="DROP"` |
| firewalld | `DefaultZone` in `firewalld.conf` | any zone **except** `trusted` |

Two of these are worth spelling out.

**nftables writes the chain across two lines** as often as one:

```
chain input {
    type filter hook input priority 0;
    policy drop;
```

A parser reading only the hook's own line finds no policy and reports UNKNOWN
on a correctly configured host — an answer that reads as caution and is wrong.
The collector searches forward from the hook to the end of the statement.

**firewalld has no policy keyword at all.** Every zone it ships rejects what it
does not explicitly allow **except `trusted`**, whose target is ACCEPT. So on
firewalld the default zone's *name* is the policy, and it is the one setting an
operator can get catastrophically wrong in a single word — `firewall-cmd
--set-default-zone=trusted` disables the firewall while leaving the service
reporting as running.

## 4. Verdict table

| Result | Condition | Severity | Detail must state |
|---|---|---|---|
| PASS | every active configuration's input default is deny | — | the file and the text the policy was read from |
| FAIL | any active configuration's input default is accept | HIGH | which file, **and for firewalld what `trusted` means** |
| UNKNOWN | a configuration is active but no policy could be read from it | `unparseable` | that neither the secure nor the insecure guess is available from here |
| NOT_APPLICABLE | no firewall is configured | — | that NETWORK-0001 reports the absence |
| UNKNOWN | a candidate file could not be read | `insufficient_privileges` | that the refused file could hold the accept policy |

NOT_APPLICABLE rather than FAIL for the no-firewall case: "the default policy
denies" is not a false statement about a host with no firewall, it is a
sentence with no subject. NETWORK-0001 reports the absence once, and a module
that failed three times for one missing thing would bury the finding that
matters under two that repeat it.

## 5. Where this check cannot know

- **whether the ruleset is loaded.** As NETWORK-0001 §6
- **what the allow list permits.** A default-deny chain that accepts every port
  passes here. What should be allowed is a property of the workload
- **the forward and output chains.** Only inbound is tested; a router's forward
  policy is a different question with a different right answer
- **per-zone rules on firewalld.** The default zone's target is read; the
  services and ports opened within it are not
- **a policy set imperatively.** `iptables -P INPUT DROP` typed at a shell and
  never saved is invisible to a file-based read, and is also gone at the next
  reboot

## 6. Known false positives

A router or NAT gateway whose inbound policy is deliberately permissive on an
internal interface while filtering happens on the forward chain. The
observation is correct; the architecture is the exception.

## 7. Remediation

| | |
|---|---|
| Summary | Set the input chain's default to drop, then add allow rules for what this host offers. |
| Effort | MEDIUM |
| Steps | Enumerate what must keep working; **write the allow rules first, with the default still at accept** — they have no effect yet, which is why this order is safe; change the default last; do not forget `iif lo accept` and an established-connection accept, whose absence looks like a network fault rather than a firewall one; verify from another host |
| Commands | `ufw default deny incoming`, `nft list chain inet filter input`, `firewall-cmd --get-default-zone` |
| **Caution** | **Required.** Changing the default to drop with no ssh allow rule disconnects you immediately. Missing loopback and established accepts break local services and every outbound reply, and both failures look like the network is broken rather than the firewall. |

## 8. Control mappings

- `nist-800-53-r5` SC-7
- `nist-800-53-r5` AC-4

## 9. Fixtures

| Fixture | Scenario | Expected |
|---|---|---|
| `network-nftables` | `policy drop` on its own line under the hook | PASS |
| `network-ufw` | `DEFAULT_INPUT_POLICY="DROP"` in a second file | PASS |
| `network-accept` | `policy accept` with a list of blocks | FAIL, HIGH |
| `network-none` | no firewall configured | NOT_APPLICABLE |
| `network-denied` | the one file present is unreadable | UNKNOWN, `insufficient_privileges` |
