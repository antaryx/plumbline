# COMPLIANCE DATA POLICY — Plumbline

**Status:** binding. Applies to the repository, every released artifact, and
every contribution.
**Origin:** audit finding A-02. The design this project replaces shipped
`iso27001-2022.yaml`, `pci-dss-v4.yaml` and `cis-ubuntu-22.yaml` under
Apache-2.0, which is the kind of problem that gets a repository taken down
rather than politely emailed about.

This is not legal advice. It is a conservative operating rule that keeps the
project well clear of the line.

---

## 1. The rule

**Ship only what is in the public domain. Reference everything else by bare
identifier. Reproduce no control text, ever.**

| Framework | Status | May we ship a mapping file? | May we quote control text? |
|---|---|---|---|
| NIST SP 800-53 Rev 5 | US Government work | **Yes** | Yes |
| DISA STIG | US Government work | **Yes** | Yes |
| NIST SP 800-171 / CSF | US Government work | Yes | Yes |
| HIPAA Security Rule (45 CFR §164) | US regulation | Yes, CFR text is public | Yes, but see §4 on claims |
| **CIS Benchmarks** | © Center for Internet Security; own terms, derivatives restricted | **No** | **No** |
| **PCI-DSS v4.0** | © PCI Security Standards Council | **No** | **No** |
| **ISO/IEC 27001:2022** | © ISO/IEC; sold per copy | **No** | **No** |
| **SOC 2 / TSC** | © AICPA | **No** | **No** |
| **NIS2, DORA, GDPR** | EU legislation, official texts public | Article numbers yes | Recital/article text: cite and link, do not vendor |

When a framework is not in this table, the answer is **no** until someone has
checked and added a row.

---

## 2. What "bare identifier" means

Permitted in `finding.ControlRef`:

```go
Mappings: []finding.ControlRef{
    {Framework: "nist-800-53-r5", Control: "AC-6(2)"},
}
```

An identifier is a pointer, like a page number. It carries no expressive
content and is how every open-source security tool cross-references standards.

**Not permitted**, even for public-domain frameworks, because it bloats the
catalog and invites copy-paste from the restricted ones:

```go
// NO — control text belongs in the standard, not in our repository
{Framework: "...", Control: "AC-6(2)",
 Text: "The organization requires that users of information system accounts..."}
```

There is no `Text` field on `ControlRef` and there will not be one. The absence
is the enforcement.

---

## 3. How restricted frameworks are supported: user-supplied mapping packs

Users who hold a licensed copy of CIS, PCI-DSS or ISO 27001 supply their own
mapping, from v2:

```bash
plumbline mapping add ./our-cis-ubuntu-22-v2.yaml
plumbline eval bundle.plb --mapping cis-ubuntu-22 --format evidence
```

- The pack lives on the user's disk. It is never fetched, bundled, cached in a
  release artifact, or accepted into this repository.
- The format is documented; the content is the user's responsibility under
  their own licence.
- This also serves internal corporate frameworks, which is the more common real
  need anyway — most organisations audit against their own baseline, not a
  published one.

Contributors must not open a pull request adding such a pack, and reviewers
must reject one on sight regardless of how it is framed.

---

## 4. No compliance claims, ever

Separate from copyright, and equally binding (audit finding A-07).

**Forbidden output:**

> "This host is 87% PCI-DSS compliant."

That sentence is meaningless — most of PCI-DSS covers policy, personnel,
physical security and segmentation, none of which a process on one host can
assess — and someone will paste it into an audit response.

**Required framing:**

> Of PCI-DSS v4.0, Plumbline tests 34 requirements at host level: 29 pass,
> 5 fail, 0 unknown. This represents host-level technical coverage only and is
> not an assessment of compliance.

Rules:

1. Never emit a compliance percentage. Emit counts and an explicit coverage
   statement.
2. Never use "compliant", "certified", "assessed" or "audited" in output.
   Plumbline produces **evidence**; people produce conclusions.
3. Never imply endorsement by CIS, PCI SSC, ISO, AICPA, NIST or DISA. Mapping
   to a control is not affiliation.
4. `LEGAL-DISCLAIMER.md` ships with the tool and is printed by
   `plumbline eval --format evidence`.

---

## 5. Naming and marketing

| Do not | Do |
|---|---|
| "CIS Benchmark scanner" | "Checks that map to CIS Benchmark controls, using your licensed copy" |
| "PCI-DSS compliance tool" | "Collects host-level evidence relevant to PCI-DSS technical requirements" |
| "ISO 27001 certified configuration" | Nothing. Do not go near this. |
| Name a file `cis-ubuntu-22.yaml` in the repo | Name the user's file whatever they like, on their disk |

File names matter more than they should: a repository containing
`iso27001-2022.yaml` looks like redistribution before anyone opens it.

---

## 6. Contributor checklist

Reviewers reject a pull request that fails any of these:

- [ ] No control text from any framework, in code, docs, comments or tests
- [ ] Mappings use bare identifiers only
- [ ] Frameworks used appear in the §1 table with a "Yes"
- [ ] No file named after a restricted framework
- [ ] No output string containing "compliant", "compliance score", or a percentage against a framework
- [ ] Check descriptions are written from scratch — explaining *why* a setting matters, not paraphrasing a benchmark's rationale closely enough to be a derivative

That last one is the subtle one. Writing "Ensure permissions on /etc/passwd are
configured" because a benchmark says so is fine; reproducing its audit
procedure and rationale section in your own file is not.

---

## 7. If contacted by a standards body

1. Respond promptly and politely.
2. Remove the disputed content first, argue afterwards if at all. This project
   has no legal budget and no interest in a test case.
3. Record what happened in `postmortems/` and add the framework to §1 with
   the outcome, so the same mistake cannot be made twice.
