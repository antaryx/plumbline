# Glossary

Small document, disproportionate value. Without it these words drift within a
week, and inconsistent vocabulary in a codebase becomes inconsistent behaviour.

| Term | Definition |
|---|---|
| **Bundle** | The durable artifact of a collection: facts, evidence, fact errors, metadata. Zstd tar, `.plb`. Portable, re-evaluable, diffable. Read support is permanent. |
| **Catalog** | The immutable set of checks in a binary, with its own monotonic integer version. This build is catalog 34, carrying 112 checks. Scores are comparable only within one catalog version. |
| **Check** | A pure function from facts to one outcome. No IO, no clock, no network. Identified by a permanent `MODULE-NNNN` ID. |
| **Collector** | The only thing that touches the OS. Produces typed facts. Has dependencies, a cost class and a timeout budget. |
| **Coverage** | The percentage of applicable checks actually evaluated. `SKIPPED` and `UNKNOWN` reduce it. Never displayed without posture, and posture is never displayed without it. |
| **Detail** | The human-readable string stating what was observed, with real values, file and line. Not a description of what the check does. |
| **Evidence** | The material a verdict was derived from: source, line, excerpt, hash. A finding without evidence is a rumour. |
| **Fact** | One typed, serialisable observation. Data, never judgement. Carries its own version integer. |
| **Fact error** | A typed record of why a fact is absent. Propagates to `UNKNOWN`, never to `PASS`. |
| **FactSet** | The complete result of one collection: facts that succeeded, errors for those that did not. What a check receives. |
| **Finding** | One evaluated check: result, severity, detail, evidence, fingerprint. Serialises into the public schema. |
| **Fingerprint** | `sha256(check_id ‖ subject)`, truncated. Stable across runs and across verdict changes, so suppressions and SARIF baselines survive. |
| **Fixture** | A fake system: a partial filesystem tree plus a manifest. What every check is tested against. |
| **Golden bundle** | A recorded bundle plus its complete expected findings. Any catalog change shows its blast radius as a diff. |
| **Module** | A grouping of related checks, and the ID prefix. There are 11: `AUTH`, `CONTAINERS`, `CRON`, `FILESYS`, `KERNEL`, `LOGGING`, `MEMORY`, `NETWORK`, `SERVICES`, `SSHD`, `USERS`. |
| **Posture** | Weighted percentage of scoring checks that passed, over `PASS + FAIL` only. Pinned to a catalog version. There is exactly one score. There is no separate risk score. |
| **Profile** | A named selection from the catalog. This build carries `default`, the whole catalog, and `cis-l1`, an 87-check Level 1 server baseline. A profile can also be a path to a `profile/v1` file. |
| **Result** | One of exactly five: `PASS`, `FAIL`, `NOT_APPLICABLE`, `SKIPPED`, `UNKNOWN`. Closed set. A sixth is a breaking schema change. |
| **Scan root** | The `--root` prefix. Empty for a live host, `/mnt/host` when scanning a container's host mount or a mounted image. |
| **Subject** | The specific thing a finding concerns: a path, an account, a port. Feeds the fingerprint. Empty for host-wide checks. |
| **Suppression** | A user's recorded decision to accept a known finding, keyed by fingerprint, with a justification and an expiry. |
| **System** | The interface that is the single OS seam. Three implementations: `live`, rooted (`live` with a prefix), `fake`. |
| **UNKNOWN** | Not a failure and not a pass. Plumbline could not determine the answer. A first-class result with a machine-readable reason. |

## Words we do not use

| Avoid | Because |
|---|---|
| "Compliant", "certified", "assessed" | Plumbline produces evidence. People produce conclusions. See `COMPLIANCE-DATA-POLICY.md` §4. |
| "Compliance score", "X% compliant" | Meaningless for org-scope frameworks, and it invites reliance. |
| "Secure" as a verdict | A `PASS` means one condition was tested and met at one moment. |
| "Scan" for a remote host | Plumbline audits the host it is pointed at. It is not a network scanner. |
| "Agent" | There is no daemon and no installed state, in any planned version. |
| "Fix" as a verb Plumbline performs | It generates a script. It never runs one. |
