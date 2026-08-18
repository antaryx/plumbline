## What and why

<!-- The diff says what changed. Say why. -->

## Type

- [ ] `feat` new capability
- [ ] `fix` bug fix
- [ ] `check` catalog change (new check, severity change, verdict correction)
- [ ] `docs` / `test` / `refactor` / `chore`

## Checklist

- [ ] `make verify` passes — output pasted below
- [ ] No new dependency, or it was agreed in advance
- [ ] No files outside the stated scope of this change

### If this touches a check or collector

- [ ] PASS and FAIL fixtures exist; NOT_APPLICABLE and UNKNOWN where reachable
- [ ] All five result states considered; unreachable ones explained in a comment
- [ ] Every UNKNOWN path carries a reason code
- [ ] Detail strings state observed values with file and line
- [ ] Evidence present on every FAIL and UNKNOWN
- [ ] `Caution` present if the remediation can lock an operator out
- [ ] `catalog.Version` bumped
- [ ] Verdict changes documented under `### Check corrections` in CHANGELOG.md

### If this touches internal/system, internal/finding, or schema/

- [ ] Threat-model review checklist completed (`docs/THREAT-MODEL.md` §5)
- [ ] Schema impact assessed against `docs/VERSIONING.md` §4
- [ ] No control text from any standard added (`docs/COMPLIANCE-DATA-POLICY.md`)

## `make verify` output

```
paste here
```
