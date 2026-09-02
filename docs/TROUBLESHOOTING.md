# Troubleshooting

## "Half the report is UNKNOWN"

You are almost certainly not root.

```bash
plumbline scan --json | jq -r '.scan.euid'
```

An unprivileged scan cannot read `/etc/shadow`, most of `/etc/ssh`, or several
`/proc/sys` entries. Those checks report `UNKNOWN` with a permission reason
instead of passing. That is the intended behaviour, not a bug. Run under `sudo`,
or accept the reduced coverage explicitly:

```bash
plumbline scan --strict-privileges     # exit 10 if privileges were missing
```

## "The scan takes forever"

It is the filesystem sweep, and it is disk-bound. Expect roughly 3 s warm and
30 s cold on a host with about 700k inodes. [`PERFORMANCE.md`](PERFORMANCE.md)
has the measured numbers and explains why `FILESYS-0010` cannot avoid visiting
every inode.

Options:

```bash
plumbline scan --profile cis-l1        # cis-l1 excludes FILESYS-0010, the walk
plumbline collect -o host.plb          # pay once, evaluate many times
plumbline scan --collector-timeout 60s # bound it; over-budget becomes UNKNOWN
```

Cost scales with inode count, not disk size. Nothing is hashed or read during
the walk. A 4 TB media server with 50,000 files scans faster than a 40 GB build
host with two million.

## "It exited 4 but everything passed"

Exit 4 is degraded: a collector failed, or coverage fell below
`--min-coverage`. The host may be fine. The scan was not complete.

```bash
plumbline scan --json | jq '.fact_errors, .summary.coverage'
```

This is deliberate. See [`CI-INTEGRATION.md`](CI-INTEGRATION.md). "The scanner
could not see your host" outranks "your host is misconfigured".

## "eval says my file is not a bundle"

```
plumbline: out.json is a findings/v1 document — the rendered verdicts of a scan, not an evidence bundle.
  A bundle holds the facts a scan observed, which is what lets them be re-evaluated;
  a findings document holds verdicts that have already been drawn from those facts.
  Write one with:  plumbline scan --save-bundle host.plb   (keeps the evidence a scan used)
```

You saved a findings document (`--json > out.json`), which holds conclusions.
`eval` and `diff` want the facts:

```bash
plumbline scan --save-bundle host.plb   # or: plumbline collect -o host.plb
```

## "No colour / no progress indicator"

Both are suppressed when the destination is not a terminal, which is why they
never appear in a pipe, a file or a CI log. Colour also honours `--no-color`,
`NO_COLOR` and `--output`. The indicator also honours `PLUMBLINE_NO_PROGRESS`,
`TERM=dumb`, an unset `TERM`, and any CI marker in the environment.

To confirm it is the environment and not the build:

```bash
plumbline scan 2>&1 | cat      # never coloured; a pipe is not a terminal
```

## "Escape sequences in my report file"

Do not redirect a coloured report into a file. Use `--output`, which is never
coloured:

```bash
plumbline scan --output report.txt      # not: plumbline scan > report.txt
```

## Container gotchas

- `/proc/sys` is the host's, namespaced. `KERNEL-*` failures inside a container
  describe the machine, not the image, and you cannot fix most of them from
  inside it.
- The mount table is the container's. `/tmp` and `/home` are not separate
  mounts, so `FILESYS-0007` and `FILESYS-0009` fail correctly and unavoidably.
- Scan an image, not a container, when you mean to audit the image:
  `plumbline scan --root /mnt/rootfs`.

## Distro quirks

- Fedora, RHEL and Rocky generate their PAM stacks with `authselect`, and
  `/etc/pam.d/system-auth` is a symlink into `/etc/authselect/`. Plumbline
  resolves it explicitly and bounded. If you hand-edited the stack, `authselect`
  may overwrite it.
- Ubuntu and Debian make `/etc/os-release` a symlink into `/usr/lib`. Resolved.
- Alpine has no PAM and no systemd. The `AUTH` module and most of `SERVICES`
  report `NOT_APPLICABLE`, which is a declined judgement rather than a gap.

## "Two runs of the same host differ"

They should not. Findings are deterministic for a given bundle and catalog
version. If they differ, something changed: the host, the catalog version
(`plumbline version --json`), or the profile.

To eliminate the host as a variable:

```bash
plumbline collect -o a.plb
plumbline eval a.plb --json | sha256sum
plumbline eval a.plb --json | sha256sum   # must match
```

If those two differ, report it as a bug, with the bundle attached.

## Getting help

Open an issue with `plumbline version --json` and a redacted bundle
(`plumbline collect --redact -o report.plb`). Read [`PRIVACY.md`](PRIVACY.md)
before you attach one.
