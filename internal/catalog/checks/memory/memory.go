// Package memory holds the MEMORY module's checks.
//
// The module asks one kind of question: was this binary built with the
// mitigations the toolchain has offered for a decade? The answers come from
// program headers, the dynamic section and the symbol tables, all of which the
// collector has already read, so every check here is a pure read of
// fact.ELFHardening and nothing else.
//
// All four checks have the same shape — walk the probed binaries, decide the
// property for each, and combine — so the walk lives here once and each check
// supplies only its predicate and its wording. That is not merely to save
// repetition. The combining rules are where a check of this shape goes wrong,
// and there are three of them:
//
//   - **FAIL outranks UNKNOWN.** An incomplete examination can invalidate a
//     negative result and can never invalidate a positive one (ADR-0014). A
//     binary that was read and violates the property still violates it
//     whatever the unreadable ones turn out to be.
//   - **A property that does not apply is not a property that passes.** A
//     statically linked binary has no lazy binding to close; counting it as a
//     pass would inflate the posture score with a control never tested.
//   - **A file that does not say is not a file that says no.** A stripped
//     image carries no symbols at all, and reading that as "no canary" reports
//     a hardened binary as unhardened on the strength of having found nothing
//     to look at.
//
// Getting any of the three wrong is silent, which is why they are written once
// and asserted by module-wide tests rather than restated in four places.
package memory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// verdict is one binary's answer for one property.
type verdict int

const (
	// holds: the binary satisfies the property.
	holds verdict = iota
	// violated: the binary was examined and does not satisfy it.
	violated
	// inapplicable: the property is not one this binary can have or lack — a
	// static binary and eager binding, a binary that calls nothing fortifiable.
	inapplicable
	// undetermined: the image does not answer. Distinct from violated, and the
	// distinction is the module's central correctness property.
	undetermined
)

// property is what one check asserts about one binary.
type property struct {
	// decide returns this binary's verdict.
	decide func(fact.ELFBinary) verdict
	// noun names the property in a detail string: "position-independent".
	// Used as "N binaries are not <noun>".
	violationClause string
	// passClause completes "All N probed binaries <passClause>".
	passClause string
	// inapplicableClause completes "No probed binary <inapplicableClause>".
	inapplicableClause string
	// undeterminedClause completes "... could not be determined for N
	// binaries because <undeterminedClause>".
	undeterminedClause string
	// excerpt renders the per-binary evidence for a violating or undetermined
	// entry.
	excerpt func(fact.ELFBinary) string
}

// evaluate walks the probed binaries and combines their verdicts.
//
// The branch order is the reasoning, not a style choice; see the package
// comment for why each of the three rules exists.
func evaluate(fs *fact.Set, p property) catalog.Outcome {
	// The runner guarantees the required fact is present and typed.
	h, _, _ := fact.Get[fact.ELFHardening](fs, fact.ELFHardeningID)

	var violating, unclear, applicable []fact.ELFBinary
	for _, b := range h.Binaries {
		if !b.Usable() {
			continue
		}
		switch p.decide(b) {
		case violated:
			violating = append(violating, b)
			applicable = append(applicable, b)
		case undetermined:
			unclear = append(unclear, b)
		case holds:
			applicable = append(applicable, b)
		case inapplicable:
			// Counted nowhere. It is neither a pass to celebrate nor a gap to
			// worry about: the question does not arise for this binary.
		}
	}
	gaps := h.Unreadable()

	if len(violating) > 0 {
		return failing(p, violating, len(gaps)+len(unclear), h.Truncated)
	}
	if len(gaps) > 0 || len(unclear) > 0 || h.Truncated {
		return unknown(p, gaps, unclear, h.Truncated)
	}
	if len(applicable) == 0 {
		return catalog.Outcome{
			Result: finding.NotApplicable,
			Detail: "No probed binary " + p.inapplicableClause + ".",
		}
	}
	return catalog.Outcome{
		Result: finding.Pass,
		Detail: fmt.Sprintf("All %d probed %s %s.",
			len(applicable), plural(len(applicable), "binary", "binaries"), p.passClause),
		Evidence: evidenceFor(applicable, p),
	}
}

// failing builds the FAIL outcome, naming every offender.
//
// The detail names the binaries rather than counting them: an operator reading
// "2 binaries are unhardened" has to go and find out which, and a report that
// makes somebody re-derive its own conclusion is one they stop reading.
func failing(p property, violating []fact.ELFBinary, unexamined int, truncated bool) catalog.Outcome {
	paths := make([]string, 0, len(violating))
	for _, b := range violating {
		paths = append(paths, describe(b))
	}
	sort.Strings(paths)

	detail := fmt.Sprintf("%d probed %s %s: %s.",
		len(violating),
		plural(len(violating), "binary is not", "binaries are not"),
		p.violationClause,
		strings.Join(paths, ", "))

	// The shortfall is stated even though it does not change the verdict. It is
	// the difference between "these are the offenders" and "these are the
	// offenders we could see", and an operator fixing the named ones deserves
	// to know the list may be short.
	if note := gapNote(unexamined, truncated); note != "" {
		detail += " " + note
	}

	return catalog.Outcome{
		Result:   finding.Fail,
		Subject:  violating[0].Path,
		Detail:   detail,
		Evidence: evidenceFor(violating, p),
	}
}

// unknown builds the UNKNOWN outcome for an examination with holes in it.
//
// gaps are binaries that could not be read at all; unclear are binaries that
// were read and whose image does not answer this particular question. They
// carry different reason codes because they send an operator to different
// places: re-running as root fixes the first and can do nothing about the
// second.
func unknown(p property, gaps, unclear []fact.ELFBinary, truncated bool) catalog.Outcome {
	reason := finding.ReasonAmbiguousState
	switch {
	case len(gaps) > 0 && len(unclear) == 0:
		reason = finding.ReasonPermission
		for _, b := range gaps {
			if b.State != fact.ELFDenied {
				reason = finding.ReasonAmbiguousState
				break
			}
		}
	case len(gaps) == 0 && len(unclear) == 0 && truncated:
		reason = finding.ReasonTruncated
	}

	var parts []string
	if len(gaps) > 0 {
		names := make([]string, 0, len(gaps))
		for _, b := range gaps {
			names = append(names, fmt.Sprintf("%s (%s)", b.Path, b.State))
		}
		sort.Strings(names)
		parts = append(parts, fmt.Sprintf("%d probed %s not be examined: %s",
			len(gaps), plural(len(gaps), "binary could", "binaries could"), strings.Join(names, ", ")))
	}
	if len(unclear) > 0 {
		names := make([]string, 0, len(unclear))
		for _, b := range unclear {
			names = append(names, describe(b))
		}
		sort.Strings(names)
		parts = append(parts, fmt.Sprintf("%s could not be determined for %d %s because %s: %s",
			p.violationClause, len(unclear), plural(len(unclear), "binary", "binaries"),
			p.undeterminedClause, strings.Join(names, ", ")))
	}
	if len(parts) == 0 {
		parts = append(parts, "the binary probe did not finish, so some targets were never examined")
	}

	detail := capitalise(strings.Join(parts, "; ")) + "."
	if truncated && (len(gaps) > 0 || len(unclear) > 0) {
		detail += " The probe also did not finish, so further targets were never looked at."
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Detail:        detail,
		Evidence:      evidenceFor(append(append([]fact.ELFBinary{}, gaps...), unclear...), p),
	}
}

// gapNote describes an incomplete examination for appending to a FAIL detail.
func gapNote(unexamined int, truncated bool) string {
	switch {
	case unexamined > 0 && truncated:
		return fmt.Sprintf("A further %d %s could not be examined and the probe did not finish, so this list may be incomplete.",
			unexamined, plural(unexamined, "binary", "binaries"))
	case unexamined > 0:
		return fmt.Sprintf("A further %d %s could not be examined, so this list may be incomplete.",
			unexamined, plural(unexamined, "binary", "binaries"))
	case truncated:
		return "The probe did not finish, so this list may be incomplete."
	}
	return ""
}

// describe names a binary, and names what it resolved to when that differs.
//
// An alternatives link is the common case — /usr/bin/sudo points into
// /etc/alternatives on every Debian-family host — and a report naming only one
// of the two paths either sends the operator to a symlink or never mentions the
// command they type.
func describe(b fact.ELFBinary) string {
	if b.Resolved != "" && b.Resolved != b.Path {
		return fmt.Sprintf("%s -> %s", b.Path, b.Resolved)
	}
	return b.Path
}

// evidenceFor cites each binary by path, with the property's own excerpt.
//
// The digest goes in the excerpt text rather than in Evidence.SHA256, and that
// is deliberate. Evidence.SHA256 means "this blob is in the bundle's evidence
// store", and a binary's bytes are not: they are read through the seam's opaque
// path precisely so that a portable artifact does not carry a few hundred
// kilobytes of machine code per target. Citing a digest with nothing behind it
// would send an auditor looking for a blob that was never stored — the same
// reasoning that leaves findings over /etc/shadow without a digest (ADR-0015).
//
// In the excerpt it is more useful than a stored blob would have been, because
// `sha256sum` on the host reproduces it. That verifies the claim against the
// running system rather than against a copy this scan made of it.
func evidenceFor(bins []fact.ELFBinary, p property) []finding.Evidence {
	out := make([]finding.Evidence, 0, len(bins))
	for _, b := range bins {
		var excerpt string
		switch {
		case !b.Usable() && b.Msg != "":
			excerpt = fmt.Sprintf("not examined (%s): %s", b.State, b.Msg)
		case !b.Usable():
			excerpt = fmt.Sprintf("not examined (%s)", b.State)
		default:
			excerpt = p.excerpt(b) + "; sha256 " + b.Digest
		}
		// NewEvidence neutralises the untrusted strings a host path carries
		// (THREAT-MODEL.md T-03). The empty digest is the honest value: there
		// is no stored blob to verify against.
		out = append(out, finding.NewEvidence(describe(b), 0, excerpt, ""))
	}
	return out
}

// symbolNote renders the symbol evidence behind a canary or FORTIFY verdict.
//
// The count is carried because "no such symbol among 190" and "no such symbol"
// are different degrees of evidence, and the first is what an operator needs in
// order to judge whether the verdict is worth acting on.
func symbolNote(b fact.ELFBinary) string {
	if b.Symbols != fact.ELFSymbolsRead {
		return "image is stripped: no symbol table to read"
	}
	return fmt.Sprintf("%d symbols read", b.SymbolCount)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
