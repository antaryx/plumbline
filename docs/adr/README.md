# Architecture Decision Records

One file per decision that would be expensive to reverse. Fifteen minutes each,
and they end every re-litigation six months later.

**Write an ADR before implementing** anything that changes architectural
direction, adds a dependency, alters the schema or scoring, or touches the
compliance data policy.

Format: context (what forced the decision), decision (what we chose),
consequences (what we now live with, including the bad parts). Status is
`accepted`, `superseded by NNNN`, or `deprecated`. **Never edit an accepted
ADR's decision** — supersede it with a new one, so the reasoning history stays
intact.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-collect-evaluate-split.md) | Split collection from evaluation | accepted |
| [0002](0002-no-go-plugin-package.md) | Go's `plugin` package is never used | accepted |
| [0003](0003-no-compliance-scoring.md) | No compliance percentages, ever | accepted |
| [0004](0004-vendor-feeds-over-nvd.md) | Vendor security data, not NVD version matching | accepted |
| [0005](0005-five-result-states.md) | Five result states, with UNKNOWN first-class | accepted |
| [0006](0006-no-auto-remediation.md) | Plumbline never applies a change | accepted |
| [0007](0007-json-schema-is-the-api.md) | The JSON schema is the public API, not a Go package | accepted |
| [0008](0008-zstd-bundle-compression.md) | zstd for bundle compression; the first and only dependency | accepted |
| [0009](0009-evidence-digest-tracking.md) | Facts carry the digest of every file they were parsed from | accepted |
| [0010](0010-nullable-posture-schema.md) | Posture and coverage are nullable in the schema; null is not zero | accepted |
| [0011](0011-local-file-system-seam.md) | Local file access is in the seam package, not on the System interface | accepted |
| [0012](0012-fileinfo-inode-seam.md) | `FileInfo` carries device and inode, flattened to integers | accepted |
| [0013](0013-fixture-inode-and-type-overrides.md) | Fixtures describe inode identity and file type in the manifest | accepted |
| [0014](0014-walk-scope-is-not-truncation.md) | Declared scope is not truncation, and a partial walk returns facts | accepted |
| [0015](0015-account-data-in-bundles.md) | Password hashes never enter a bundle; `--redact` does not anonymise account names | accepted |
| [0016](0016-fileinfo-ownership-seam.md) | `FileInfo` ownership is a verdict input; a check gates on state before reading it | accepted |
