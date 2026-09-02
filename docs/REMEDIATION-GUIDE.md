# Remediation guide

How to take a generated script from `scan --fix` and apply it to a host without
breaking it.

`USAGE.md` covers the flags. This covers the operational part: what to read
first, what to stage, what can lock you out, and how to undo it.

## The short version

```bash
sudo plumbline scan --fix --write-script fix.sh   # generate
less fix.sh                                       # read, all of it
sudo sh fix.sh                                    # apply, when you have decided to
sudo plumbline scan --json | jq '.summary'        # confirm
```

Plumbline does not run the script. It renders shell and stops. Everything after
the first line above is your decision on your host.

18 of the 112 checks have a registered fix. The rest fall back to advisory text
you get from `plumbline explain CHECK-ID`.

## 1. Generate against the host you intend to change

The script is built from one scan's evidence. It names the paths that scan
found, and evidence is capped, so a finding covering four hundred
world-writable files carries five example paths and says so. The script acts on
what it was given.

Generate it on the host you are fixing, not on a similar one. A script built
from a staging box and run on production is a script acting on paths that may
not exist there and missing paths that do.

```bash
sudo plumbline scan --fix --write-script /root/fix-$(hostname -s)-$(date +%F).sh
```

The file lands `0700`, owner-only and executable.

## 2. Read it

The structure is fixed, so you can skim it the same way every time.

```sh
#!/bin/sh
# Proposed by plumbline. Nothing here has been run.
set -eu

UNITDIR=/etc/systemd/system

plumbline_backup() { ... }        # helpers, emitted only when used

# CRON-0001 — The system crontab is owned by root and writable only by root
#   ... why this matters, and what it costs you
chown root:root -- /etc/crontab
chmod 600 -- /etc/crontab
```

Sections sort by check ID. Each has a comment block naming the check and
explaining the change before the commands that make it. Read the comments. They
carry the cautions that did not fit in the terminal report.

At most five helper functions appear, and only when something below calls one:

| Helper | What it does |
|---|---|
| `plumbline_backup` | Copies a file to `<path>.bak` once, before the first change |
| `plumbline_sysctl_set` | Rewrites a key in a sysctl file in place, or appends it if absent |
| `plumbline_logindefs_set` | Same, for `/etc/login.defs`, replacing the first match |
| `plumbline_dropin` | Writes a whole systemd drop-in and creates its directory |
| `plumbline_json_set` | Edits `/etc/docker/daemon.json` through python3, refusing if python3 is absent |

None of them appends blindly. That is what makes the script safe to run twice.

## 3. Sort the sections by what they can cost you

Not every action carries the same risk. Split the script rather than running it
whole on a host you care about.

### Safe to run unattended

Ownership and mode changes. They take effect immediately, they affect no running
process, and `plumbline_backup` does not apply because nothing is rewritten.

`CRON-0001`, `CRON-0002`, `FILESYS-0003`, `FILESYS-0004`.

The one cost worth knowing: `CRON-0001` sets `/etc/crontab` to `0600`. Anything
parsing it as a non-root user stops being able to. A monitoring agent that reads
the schedule is the usual case.

### Takes effect immediately, easy to reverse

Kernel parameters and `login.defs` defaults.

`KERNEL-0004`, `KERNEL-0016`, `KERNEL-0030`, `AUTH-0005`, `USERS-0012`.

Sysctl actions do both halves. `sysctl -w` changes the running kernel, a line
goes into `/etc/sysctl.d/99-plumbline-hardening.conf`, and `sysctl --system`
runs once at the end. Neither half alone is enough: the live setting dies at
reboot, and the file alone does nothing until then.

`AUTH-0005` sets `ENCRYPT_METHOD SHA512`. It changes nothing about the hashes
already in `/etc/shadow`, because the algorithm is chosen when a password is
set. Existing accounts keep what they have until their next password change. The
script says so and shows you how to expire them if you want the old hashes
retired. Do not expire the account you are logged in as without a second way
in.

### Read every line before running

These five can end your session or break a workload.

**`NETWORK-0001` and `NETWORK-0002`, the firewall.** The script sets a
default-deny inbound policy and allows `22/tcp`. Port 22 is a guess. The finding
that triggers the action does not carry the real sshd port, even though the
`SSHD` module knows it. If your sshd listens elsewhere, edit the allow rule
before you run this or you will be locked out. The action also reaches for `ufw`
because nothing else is configured. On a host already running nftables or
firewalld, delete the section and fix that ruleset instead.

**`KERNEL-0026`, IPv6 router advertisements.** Refusing them on a host that gets
its IPv6 address by SLAAC removes that address. Run `ip -6 addr show` first. An
address marked `dynamic mngtmpaddr` came from a router advertisement, which
means this action will take it away.

**`AUTH-0004`, empty passwords in PAM.** Removing `nullok` stops any account
with an empty password field from authenticating. That is the point, and it is
also a lockout if one of those accounts is how somebody gets in. `USERS-0003`
reports which accounts have one. Check it before you run this.

**`CONTAINERS-0001`, Docker user namespace remapping.** The remapped daemon uses
a separate storage root. Existing containers, images and volumes are not
migrated and become invisible to it until re-imported. Do not run this on a host
with running workloads without planning the migration first. It also needs a
daemon restart, because `dockerd` reads the setting only at startup.

**`SERVICES-0006`, `SERVICES-0007`, `SERVICES-0008`, the systemd drop-ins.**
These write `NoNewPrivileges`, `ProtectSystem=full` and `ProtectHome` for named
units. They do nothing until the unit restarts, which the script deliberately
does not do. Restarting a daemon is an operator decision with a maintenance
window attached, not something a script should take.

`ProtectHome` in particular changes what a daemon can read. A service that
legitimately reads a path under `/home` stops working when you restart it, and
the failure appears at restart time rather than when the file is written.

**`SERVICES-0010`, AppArmor.** Guarded. If `aa-enforce` is missing the script
prints an instruction to stderr and carries on rather than exiting. Enforcing a
profile can stop a program doing something it was doing before. Check
`journalctl -k | grep apparmor` afterwards.

## 4. Apply it

```bash
sudo sh fix.sh
```

The script runs under `set -eu`, so the first failure stops it. Sections sort by
check ID, which means a failure part-way leaves the sections before it applied
and the sections after it untouched. That is recoverable and it is not atomic.
Know which section failed before you re-run.

Running it a second time is safe. Every action rewrites in place rather than
appending, and `plumbline_backup` only copies a file if no `.bak` exists yet, so
a second run does not overwrite your original with the already-modified version.

## 5. Confirm it worked

Re-scan and compare, rather than trusting the script's exit code.

```bash
sudo plumbline collect -o after.plb
plumbline diff before.plb after.plb
```

That needs a bundle from before you started. Collect one at step 1:

```bash
sudo plumbline scan --fix --write-script fix.sh --save-bundle before.plb
```

`diff` prints `RESOLVED` for each check the script repaired. Anything still
failing either had no registered fix or the fix did not do what it claimed, and
the second is worth reporting.

## 6. Roll back

Rollback is per action, because the script is not a transaction.

| What changed | How to undo it |
|---|---|
| A file the script rewrote | `mv /path/file.bak /path/file` |
| A sysctl setting | Delete the key from `/etc/sysctl.d/99-plumbline-hardening.conf`, then `sysctl --system`. The running value needs `sysctl -w` back to the old one, or a reboot |
| A systemd drop-in | `rm /etc/systemd/system/<unit>.d/50-plumbline-*.conf`, then `systemctl daemon-reload`, then restart the unit |
| `daemon.json` | `mv /etc/docker/daemon.json.bak /etc/docker/daemon.json`, then restart the daemon |
| A ufw rule | `ufw --force reset`, then reapply whatever you had. There is no `.bak` for firewall state |
| A mode or ownership change | No backup. The original values are in the bundle you collected before the run |

The last two rows are why step 5 tells you to save a bundle first. A `.plb` from
before the change records the modes, owners and configuration the host had, and
it stays readable forever.

## 7. What it will not fix

The closing block counts these:

```
  1 check covered by this script; review it, then run it as root.
  19 checks still failing with no automated fix; see the warnings above.
```

The second number is checks that failed with no registered fix. They are not
hidden. `plumbline explain CHECK-ID` gives the full procedure for each, and the
SARIF output carries the same text with `"source": "advisory"`.

Some are unfixable on purpose rather than unfinished. `SERVICES-0011` wants
`ProtectSystem=strict` on a daemon. Deciding which paths that daemon still needs
to write is an enumeration a configuration scan does not have, and a blanket
drop-in took out `dbus` and `systemd-journald` when it was tried. It generates
nothing and will keep generating nothing until a collector records what each
unit writes.

That is the rule the whole engine follows. A fix that needs information the scan
does not have is not generated at all. You get the advisory text and you make
the decision.

## 8. A sequence that works

```bash
# 1. Baseline and generate, in one pass.
sudo plumbline scan --save-bundle before.plb --fix --write-script fix.sh

# 2. Read it. All of it.
less fix.sh

# 3. Split off anything from the "read every line" list above and hold it back.

# 4. Apply the rest.
sudo sh fix.sh

# 5. Confirm.
sudo plumbline collect -o after.plb
plumbline diff before.plb after.plb

# 6. Handle the held-back sections one at a time, in a window, with a way back in.
```

Step 6 is the one people skip. The firewall and the PAM sections are the ones
that end sessions, and they are exactly the sections that look shortest.
