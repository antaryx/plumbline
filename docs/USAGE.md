# Usage

Every command, with examples that do something real. `docs/CLI-SPEC.md` is the
normative reference for flags, precedence and exit codes. This is the guided
tour.

## The shape of the tool

Auditing splits in two. Every command is one half or both:

```
collect   →   .plb bundle   →   eval   →   findings
(touches the host)            (pure, offline, repeatable)
```

`scan` fuses them. The split is why a bundle collected on a production host can
be analysed somewhere safer, and why one collected last quarter can be re-judged
by today's catalog.

## scan: collect and evaluate in one pass

```bash
sudo plumbline scan                          # this host, human-readable
sudo plumbline scan --root /mnt/image        # a mounted image or container root
sudo plumbline scan --save-bundle host.plb   # keep the evidence it used
```

`--root` works because nothing asks the kernel about itself. That is the same
reason the tool is offline. A mounted image audits exactly like a live host.

## collect and eval: the split, used deliberately

```bash
sudo plumbline collect -o host.plb    # the expensive half, on the host
plumbline eval host.plb               # ~10 ms, anywhere, no privileges
```

Use it when the host is sensitive and you want to collect there but analyse
elsewhere. Use it when the host is slow and you would rather pay once. Use it
when you want to know what today's checks say about last month's machine.

`collect` takes no selection flags beyond `--profile`. A bundle collected with
today's checks in mind cannot answer tomorrow's question.

> A `.plb` is an evidence bundle: the facts observed. A findings document
> (`--json > out.json`) holds verdicts already drawn from those facts and cannot
> be re-evaluated or diffed. Hand one to `eval` or `diff` and it says so, and
> names the flag that writes the file it wanted.

## Output formats

```bash
plumbline scan                        # terminal report (default)
plumbline scan --json                 # findings/v1, the public API
plumbline scan --format sarif -o x.sarif
plumbline scan --output report.txt    # never coloured, whatever the terminal
```

`findings/v1` is schema-validated in CI and is what you should parse. The
terminal report is not. Its layout can change in a patch release, which is why
there are two renderers rather than one with a flag.

## Profiles: scope the question

```bash
plumbline profiles                    # what this binary carries
sudo plumbline scan --profile cis-l1
sudo plumbline scan --profile ./mine.json
```

This build carries two: `default`, the whole catalog at 112 checks, and
`cis-l1`, an 87-check Level 1 server baseline.

Checks outside the profile come back `SKIPPED` rather than being omitted, and
they leave the posture denominator. An 87-check baseline reports coverage
against 87 checks instead of looking poorly covered.

A profile selects from the catalog and can never add to it. A finding that
exists only under one profile is one nobody else can reproduce.

## explain: read the catalog from your terminal

```bash
plumbline explain SSHD-0002
plumbline explain filesys-0010        # case-insensitive
```

What the check tests and why, which facts it reads, what each result state means
for it, and the remediation in full. Offline, unprivileged, no bundle.

## scan --fix: propose a repair, run nothing

```bash
sudo plumbline scan --fix                          # print the script to stdout
sudo plumbline scan --fix --write-script fix.sh    # and write it to a file
```

**Plumbline never runs the script.** It is a read-only tool. `--fix` renders
shell to stdout and stops there. Nothing in the scanner executes a remediation
command, at any point, under any flag. The boundary is structural rather than a
policy: `internal/remediate` has no access to the `System` interface, which is
the only thing in the codebase that can touch the OS. The generator cannot run
what it writes even by mistake.

Running the script is your decision, on your host, at a time you choose.

### What you get

A `#!/bin/sh` script under `set -eu`, with one commented section per finding:

```sh
#!/bin/sh
# Proposed by plumbline. Nothing here has been run.
#
# Review it, then run it as root. It is safe to run twice: every step
# either leaves a value that is already correct alone or replaces it
# in place, and every file it edits is backed up once before the first
# change.
set -eu

# CRON-0001 — The system crontab is owned by root and writable only by root
#   0600 also closes CRON-0005. Anything that parses /etc/crontab as a non-root
#   user stops being able to.
#   The path below came from this scan's evidence, which is capped.
#   List every one on the host with: ls -l /etc/crontab
chown root:root -- /etc/crontab
chmod 600 -- /etc/crontab
```

Sections sort by check ID, so two runs against the same host produce the same
script in the same order. Helper functions are emitted only when something below
uses them. Every generated script is parsed by `sh -n` in CI.

### It is idempotent

Run it twice and the second run changes nothing the first did not. This is a
property of how each action is written, not a claim about shell in general.

A `sysctl.d` appender rewrites an existing key rather than stacking a second
one. The `login.defs` editor runs an `awk` pass that replaces the first match,
because appending a duplicate below it produces a file whose parser never
reaches your line. A systemd drop-in is written whole rather than appended to.
Every file the script edits is backed up once, before the first change.

### The closing block

```
[=] Proposed remediation script

  Nothing below has been run.
  1 check covered by this script; review it, then run it as root.
  19 checks still failing with no automated fix; see the warnings above.
```

The second count is the one to read. A check with no registered fix falls back
to the advisory remediation in the catalog, which you get from
`plumbline explain CHECK-ID`, and it is counted here rather than quietly
omitted.

Some checks have no generated fix on purpose. `SERVICES-0011` wants
`ProtectSystem=strict` on a daemon, and deciding which paths that daemon still
needs to write is an enumeration a configuration scan does not have. Generating
a blanket drop-in took out `dbus` and `systemd-journald` during development. It
now generates nothing and says so.

### --write-script

```bash
sudo plumbline scan --fix --write-script /root/fix-$(hostname)-$(date +%F).sh
```

Writes the same script to a path instead of leaving it in your scrollback. The
file is created `0700`, owner-only and executable. It is a root remediation plan
for one specific host, so it gets the same treatment as a bundle. `--write-script`
requires `--fix`.

### Read it before you run it

The script is generated from what the scan could see, which is not everything.
Two failure modes are worth naming.

**It can cut you off from the host.** The firewall action sets a default-deny
inbound policy and guesses port 22 for SSH, because the finding that triggers it
does not carry the real sshd port. The generated comment says so, directly above
the command. On a host where sshd listens elsewhere, running this unread ends
your session.

**It proposes tooling that may not fit.** The firewall action reaches for `ufw`
because nothing else is configured. On a host already running nftables or
firewalld, fix that ruleset instead and delete the section.

A generated script is a first draft written by something that read your
configuration files. It is not a change plan approved by someone who knows what
the host does. Test it somewhere you can afford to lose.

## diff: what changed

```bash
plumbline diff march.plb today.plb
```

Four buckets. Unchanged findings are not printed:

| | |
|---|---|
| **RESOLVED** | was failing, now passes |
| **NEW FAILURE** | was fine, now fails |
| **NEWLY SUPPRESSED** | somebody accepted it |
| **REGRESSED** | a suppression lapsed, the one nobody remembers to look for |

Both arguments must be bundles. Diffing findings documents would compare two
sets of conclusions rather than two states of a host.

## Suppressions: accept a risk without hiding it

```bash
plumbline scan --suppress accepted.json
```

```json
{
  "schema": "suppressions/v1",
  "rules": [
    {
      "fingerprint": "b3d91d425b9d86f87f1ccc229a1f8379",
      "check_id": "SSHD-0003",
      "subject": "/etc/ssh/sshd_config",
      "justification": "Password auth required for the console jump host; compensating control is the bastion ACL. Reviewed 2026-08-01 by the platform team.",
      "expires_at": "2026-12-31T00:00:00Z"
    }
  ]
}
```

A suppressed finding becomes `SKIPPED`. It keeps its severity, its detail and
its evidence, records what it would have said, and appears under
`[=] Accepted risks` with the justification. It stops counting against posture
and stops tripping `--fail-on`. It does not disappear.

`justification` is required and may not be blank. `expires_at` is optional and
is measured against the scan's own start time rather than the wall clock, so an
archived bundle re-evaluates identically forever.

There is no auto-discovered filename. An explicit path is the deterministic
choice for a tool that decides whether a host is safe.

Get a fingerprint from `--json`:

```bash
plumbline scan --json | jq -r '.findings[] | select(.result=="FAIL") | "\(.fingerprint)  \(.check_id)  \(.subject // "")"'
```

## Gating

```bash
plumbline scan --fail-on high --min-coverage 90 --threshold 80
```

| Code | Meaning |
|---|---|
| 0 | clean |
| 2 | findings at or above `--fail-on` |
| 3 | posture below `--threshold` |
| 4 | degraded: a collector failed, or coverage below `--min-coverage` |
| 10 | missing privileges, with `--strict-privileges` |
| 11 | timeout |
| 70 | internal error |
| 130 | interrupted |

`4` outranks `2` deliberately. "The scanner could not see your host" must be
louder than "your host is misconfigured".

## Budgets and interruption

```bash
plumbline scan --timeout 10m --collector-timeout 60s
```

A collector that blows its budget produces `UNKNOWN` with a timeout reason. It
never produces a truncated result reported as a `PASS`. Ctrl-C exits 130 and
writes no artifact at all, because a bundle from half a collection carries no
mark saying so.

## Environment

| Variable | Effect |
|---|---|
| `PLUMBLINE_CONFIG` | config path (below `--config`) |
| `NO_COLOR` | any value disables colour |
| `PLUMBLINE_NO_PROGRESS` | any value disables the progress indicator |
