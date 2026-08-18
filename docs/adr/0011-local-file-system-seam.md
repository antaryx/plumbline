# ADR-0011 — Local file access lives in the seam, not in the System interface

**Status:** accepted · **Date:** 2026-08-18

## Context

WP-12 gave the CLI two jobs that touch the filesystem for reasons that have
nothing to do with auditing: `collect -o bundle.plb` writes a bundle, and
`eval bundle.plb` reads one back.

CLAUDE.md rule 1 says only `internal/system` touches the operating system, and
`make check-system-seam` enforces it over every other directory mechanically.
The first implementation of `--config` called `os.Stat` from `internal/cli` and
the gate failed the build, which is precisely what it is for.

That left a real question rather than a formality. The obvious move — put the
calls on the `System` interface, which is the seam — is wrong, and wrong in a
way that would have shipped silently:

**`System` is the observation seam.** Every path it opens is a fact about the
host being audited. Every path is interpreted beneath `--root`. Every method is
faked in tests so that checks are testable from fixtures. An output path is
none of those three things. It is an instruction rather than an observation, it
belongs to the operator's filesystem rather than to the scan target, and there
is nothing to fake — a test that writes a bundle wants a real file.

The concrete failure is `--root`. `plumbline collect --root /mnt/host -o out.plb`
means "audit the mounted image, write the bundle here". If output went through
`System`, `-o out.plb` would resolve to `/mnt/host/out.plb`: the bundle would be
written *inside the image being audited*, altering the evidence, possibly on a
read-only mount, and certainly not where the operator asked. Rooted access is a
security control for reads; applied to writes it becomes a bug.

Options considered:

- **`internal/system/localfile.go`, package-level functions** — same package, so
  the gate is satisfied honestly; deliberately not on the interface, so `--root`
  cannot apply and no collector receives them
- **Methods on `System`** — rejected above
- **A second package, `internal/localfile`** — the gate would fail it, and
  loosening the gate to exempt a second directory weakens the one control that
  keeps OS access findable
- **Exempt `cmd/` from the gate** — would let the CLI read `/etc` directly,
  which is exactly the habit the gate exists to prevent

## Decision

**Local file access is package-level functions in `internal/system`, not
methods on `System`.**

`CreateBundle`, `OpenLocal`, `CreateLocal` and `LocalExists`. Bundles are
created `0600`, and the mode is applied explicitly after opening rather than
through `O_CREATE`, because `O_CREATE`'s mode only applies to a file that did
not already exist — overwriting yesterday's world-readable bundle would
otherwise leave it world-readable.

The distinction is written into the file itself, next to the code, because the
next person to need a file handle will look there first:

> `System` is the observation seam — everything it opens is a fact about the
> host being audited, is interpreted beneath `--root`, and is faked in tests. An
> output path is none of those things.

## Consequences

- `--root` cannot leak into output paths, because the code that writes output
  has no access to the root
- All OS file access remains in one directory, so "what does this program touch"
  is answered by reading one package
- A collector *could* import these functions and bypass the interface. Nothing
  stops it mechanically: collectors receive a `System`, and reaching past it
  would be visible in review as an import that has no business being there. The
  gate cannot distinguish intent, only location
- The seam package now holds two unrelated concerns, which is a real cost. The
  alternative was a second exemption in the one control that makes OS access
  findable, and one crowded package is cheaper than a weaker gate
