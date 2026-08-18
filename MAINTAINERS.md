# Maintainers

| Area | Maintainer |
|---|---|
| Everything | @antaryx |

One maintainer is a fine answer. Ambiguity about who decides is not.

## What the maintainer owns

- Final call on scope, architecture, and what ships
- Check ID allocation and retirement
- Releases, signing keys, and the workflow identity used for keyless signing
- Security reports (`SECURITY.md`)

## Decisions that need a written record

Anything that would be expensive to reverse goes in `docs/adr/` before it is
implemented: architectural direction, dependency additions, schema changes,
scoring changes, and anything touching the compliance data policy.

## Bus factor

This project is maintained by one person. The mitigations that matter:

- Every irreversible decision is written down in `docs/adr/`
- Releases are reproducible from a tag by anyone, per `docs/SUPPLY-CHAIN.md`
- Signing is keyless: there is no private key to lose, and the identity is a
  public GitHub workflow
- No hosted infrastructure exists, so nothing goes dark if the maintainer does
