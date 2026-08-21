# Usage

Every command, with examples that do something real. `docs/CLI-SPEC.md` is the
normative reference for flags, precedence and exit codes; this is the guided
tour.

## The shape of the tool

Auditing splits in two, and every command is one half or both:

```
collect   →   .plb bundle   →   eval   →   findings
(touches the host)            (pure, offline, repeatable)
```

`scan` is both fused together. That split is why a bundle collected on a
production host can be analysed somewhere safer, and why one collected last
quarter can be re-judged by today's catalog.

## scan — collect and evaluate in one pass

```bash
sudo plumbline scan                          # this host, human-readable
sudo plumbline scan --root /mnt/image        # a mounted image or container root
sudo plumbline scan --save-bundle host.plb   # keep the evidence it used
```

`--root` works because nothing asks the kernel about itself — the same reason
the tool is offline. A mounted image audits exactly like a live host.

## collect and eval — the split, used deliberately

```bash
sudo plumbline collect -o host.plb    # the expensive half, on the host
plumbline eval host.plb               # ~10 ms, anywhere, no privileges
```

Useful when the host is sensitive (collect there, analyse elsewhere), when the
host is slow (collect once, evaluate many times), or when you want to know what
today's checks say about last month's machine.

`collect` takes no selection flags beyond `--profile`. A bundle collected with
today's checks in mind cannot answer tomorrow's question.

> **`.plb` is an evidence bundle — the facts observed.** A findings document
> (`--json > out.json`) holds verdicts already drawn from those facts and cannot
> be re-evaluated or diffed. Hand one to `eval` or `diff` and it says so, and
> names the flag that writes the file it wanted.

## Output formats

```bash
plumbline scan                        # terminal report (default)
plumbline scan --json                 # findings/v1 — the public API
plumbline scan --format sarif -o x.sarif
plumbline scan --output report.txt    # never coloured, whatever the terminal
```

`findings/v1` is schema-validated in CI and is what you should parse. **The
terminal report is not** — its layout may change in a patch release. That is why
there are two renderers rather than one with a flag.

## Profiles — scope the question

```bash
plumbline profiles                    # what this binary carries
sudo plumbline scan --profile cis-l1
sudo plumbline scan --profile ./mine.json
```

Checks outside the profile are `SKIPPED` — never omitted — and **leave the
posture denominator**, so a thirty-check baseline reports coverage against
thirty checks rather than looking poorly covered.

A profile selects from the catalog and can never add to it: a finding that
exists only under one profile is one nobody else can reproduce.

## explain — the catalog, from your terminal

```bash
plumbline explain SSHD-0002
plumbline explain filesys-0010        # case-insensitive
```

What the check tests and why, which facts it reads, what each result state means
for it, and the remediation in full. Offline, unprivileged, no bundle.

## diff — what changed

```bash
plumbline diff march.plb today.plb
```

Four buckets, and unchanged findings are not printed:

| | |
|---|---|
| **RESOLVED** | was failing, now passes |
| **NEW FAILURE** | was fine, now fails |
| **NEWLY SUPPRESSED** | somebody accepted it |
| **REGRESSED** | a suppression lapsed — the one nobody remembers to look for |

Both arguments must be bundles. Diffing findings documents would compare two
sets of conclusions rather than two states of a host.

## Suppressions — accept a risk without hiding it

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

A suppressed finding becomes `SKIPPED`, keeps its severity, detail and evidence,
records what it *would* have said, and appears under `[=] Accepted risks` with
the justification. It stops counting against posture and stops tripping
`--fail-on`; it does not disappear.

`justification` is required and may not be blank. `expires_at` is optional and
is measured against **the scan's own start time**, not the wall clock — so an
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
| 4 | **degraded** — a collector failed, or coverage below `--min-coverage` |
| 10 | missing privileges, with `--strict-privileges` |
| 11 | timeout |
| 70 | internal error |
| 130 | interrupted |

`4` outranks `2` deliberately: *"the scanner could not see your host"* must be
louder than *"your host is misconfigured"*.

## Budgets and interruption

```bash
plumbline scan --timeout 10m --collector-timeout 60s
```

A collector that exceeds its budget produces `UNKNOWN` with a timeout reason,
never a truncated result reported as a `PASS`. Ctrl-C exits 130 and writes **no
artifact at all** — a bundle from half a collection carries no mark saying so.

## Environment

| Variable | Effect |
|---|---|
| `PLUMBLINE_CONFIG` | config path (below `--config`) |
| `NO_COLOR` | any value disables colour |
| `PLUMBLINE_NO_PROGRESS` | any value disables the progress indicator |
