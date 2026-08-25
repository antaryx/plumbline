package fact

import "sort"

// ELFHardeningID names the ELF memory-hardening fact.
//
// One fact for every probed binary rather than one fact per binary
// ("memory.elf.<path>"), for two reasons that are both structural rather than
// stylistic.
//
// A collector's Produces() is read before it runs, so that a timeout or a
// panic can be filed against the facts a check will look for. A per-path ID set
// is not known until the collector has already stat'ed the host, so such a
// collector could only ever be blamed by name — which is the failure mode
// Produces() exists to prevent. The fs.<interest> namespace is not a
// counter-example: interests are registered at init and are static by the time
// anything asks.
//
// And a fact ID becomes a bundle member name verbatim: bundle.factMembers
// writes "facts/" + id + ".json". An ID carrying an absolute path would put
// slashes in that name, turning the flat facts/ directory into a mirror of the
// audited host's filesystem layout.
//
// Per-binary ignorance is preserved by ELFBinary.State instead, which is where
// it belongs: one unreadable binary marks its own entry and leaves every other
// entry usable.
const ELFHardeningID ID = "memory.elf"

// ELFState is what the collector was able to observe about one target.
//
// The states are separate because a check must not treat them alike. "There is
// no /usr/bin/pkexec on this host" is NOT_APPLICABLE; "we were refused" is
// UNKNOWN(insufficient_privileges); "this is a shell script, not an ELF" is
// NOT_APPLICABLE for a different reason. A single "did we read it" boolean
// would have collapsed all of them into a guess.
type ELFState string

const (
	// ELFObserved means the file parsed as ELF. PIE, Stack and RELRO are
	// meaningful only in this state.
	ELFObserved ELFState = "observed"
	// ELFAbsent means the path does not exist. Common and unremarkable: no
	// distribution ships every target.
	ELFAbsent ELFState = "absent"
	// ELFDenied means the stat or the read was refused. Nothing may be
	// concluded about the binary's hardening.
	ELFDenied ELFState = "denied"
	// ELFNotRegular means something is at the path and it is not a regular
	// file — a directory, a device, a FIFO. Kept apart from ELFError because a
	// non-regular file where a setuid binary belongs is an observation about
	// the host, not a failure of this collector.
	ELFNotRegular ELFState = "not_regular"
	// ELFNotELF means the bytes were read and are not an ELF image: a shell
	// script, a wrapper, an interpreter shebang. NOT_APPLICABLE rather than a
	// finding — there is no ELF header to harden.
	ELFNotELF ELFState = "not_elf"
	// ELFTooLarge means the file exceeds the collector's read cap and was not
	// read at all. debug/elf resolves the section header table, which sits at
	// the end of the image, so there is no prefix of a large binary that can
	// be parsed instead.
	ELFTooLarge ELFState = "too_large"
	// ELFTruncated means the read hit the cap despite the size check passing,
	// which means the file grew between the two. The bytes on hand are a
	// prefix and a prefix does not parse; nothing may be concluded from it.
	ELFTruncated ELFState = "truncated"
	// ELFError means the read failed for a reason worth recording verbatim.
	ELFError ELFState = "error"
)

// ELFStack is what PT_GNU_STACK says about stack execute permission.
//
// It is three states rather than a bool because the ELF genuinely does not
// always answer the question. With no PT_GNU_STACK header the kernel applies
// its own default, which differs by architecture and by kernel version, and a
// collector that reported either answer would be inventing one. That is the
// case CONTRIBUTING.md rule 3 forbids, so the unspecified case is carried to
// the check and resolves to UNKNOWN there.
type ELFStack string

const (
	// ELFStackNoExec: PT_GNU_STACK is present and PF_X is clear. NX is on.
	ELFStackNoExec ELFStack = "noexec"
	// ELFStackExec: PT_GNU_STACK is present and PF_X is set. The binary asked
	// for an executable stack.
	ELFStackExec ELFStack = "exec"
	// ELFStackUnspecified: there is no PT_GNU_STACK header. The kernel decides
	// and this file does not record which way.
	ELFStackUnspecified ELFStack = "unspecified"
)

// ELFSymbols says whether symbol evidence was available for a binary.
//
// It exists because absence of a symbol and absence of a symbol *table* are
// different observations that a boolean would have merged. A fully stripped
// static binary has no `__stack_chk_fail` for the same reason it has no symbol
// of any kind, and reading that as "no stack canary" would report a hardened
// binary as unhardened on the strength of having found nothing to look at.
type ELFSymbols string

const (
	// ELFSymbolsRead means at least one symbol table was present and parsed.
	// HasCanary and HasFortify are meaningful only in this state.
	ELFSymbolsRead ELFSymbols = "read"
	// ELFSymbolsStripped means the image carries neither .dynsym nor .symtab.
	// Nothing may be concluded about which functions it calls.
	ELFSymbolsStripped ELFSymbols = "stripped"
)

// ELFBinary is one binary's memory-hardening properties.
//
// PIE, Stack and RELRO mean nothing unless State is ELFObserved. False is a
// legitimate value for both booleans, so neither can double as "not recorded",
// and a check must gate on State before reading them — the same rule
// docs/adr/0016-fileinfo-ownership-seam.md sets for uid 0.
type ELFBinary struct {
	Path  string   `json:"path"`
	State ELFState `json:"state"`

	// Resolved is the path actually read, when the target was a symbolic link
	// and differs from Path. Empty when Path was read directly.
	//
	// It is recorded rather than silently substituted because the two are
	// different claims. Debian's alternatives system puts a link at
	// /usr/bin/sudo pointing into /etc/alternatives, so a finding that named
	// only /usr/bin/sudo would send an operator to a symlink and a finding
	// that named only the destination would not mention the binary they
	// invoke. Both paths belong in the report.
	Resolved string `json:"resolved,omitempty"`

	// PIE reports whether the ELF type is ET_DYN.
	//
	// For an executable that is position-independent code, which is what the
	// property is asked about. ET_DYN is also the type of every shared object,
	// so this field distinguishes a PIE executable from a non-PIE one and does
	// not distinguish either from a library. Every target this collector
	// probes is an executable; Type is recorded so a later check that needs
	// the distinction has it without a second collection.
	PIE bool `json:"pie"`

	// Stack is what PT_GNU_STACK says. See ELFStack: the unspecified case is
	// not an absent NX, it is an unanswered question.
	Stack ELFStack `json:"stack"`

	// RELRO reports whether a PT_GNU_RELRO segment is present.
	//
	// **This is partial RELRO and nothing more.** Full RELRO is partial RELRO
	// plus BIND_NOW, which lives in the dynamic section rather than in the
	// program headers, and a check that read this field as "RELRO is on" would
	// report a writable GOT as hardened. Distinguishing the two is deliberately
	// left to the work package that adds the checks, so that the field cannot
	// be quietly widened to mean something it was not collected for.
	RELRO bool `json:"relro"`

	// Dynamic reports whether the image has a dynamic section, which is to say
	// whether it is dynamically linked.
	//
	// BindNow is meaningful only when this is true. A statically linked binary
	// resolves nothing at run time, so it has no relocation table to bind
	// eagerly and no lazy-binding weakness to close: "full RELRO" is not a
	// property it can have or lack, and reporting it as absent would be a
	// finding about a mechanism the file does not use.
	Dynamic bool `json:"dynamic"`

	// BindNow reports whether the dynamic linker is told to resolve every
	// relocation before handing control to the program.
	//
	// Partial RELRO (the RELRO field) maps the relocation segment read-only
	// after startup. It leaves the PLT's GOT writable, because lazy binding
	// writes into it on every first call. BindNow is what closes that: with
	// eager binding the GOT is finished before main runs and RELRO can cover
	// it. **RELRO && BindNow is full RELRO; RELRO alone is not.**
	//
	// Three encodings mean the same thing and all three are accepted. The
	// modern one is DT_FLAGS_1/DF_1_NOW, which is what current toolchains
	// actually emit — on a sample of stock Debian binaries none carried the
	// older DT_BIND_NOW at all, so a reader that looked only for that tag
	// would report every correctly hardened binary as lazily bound.
	BindNow bool `json:"bind_now"`

	// Symbols says whether symbol evidence was available. HasCanary and
	// HasFortify mean nothing unless this is ELFSymbolsRead.
	Symbols ELFSymbols `json:"symbols"`

	// SymbolCount is how many symbols were examined, across both tables. It is
	// carried so a finding can say "no such symbol among 190" rather than
	// "no such symbol", which are different degrees of evidence.
	SymbolCount int `json:"symbol_count,omitempty"`

	// HasCanary reports whether the image references __stack_chk_fail, the
	// function a stack-protector prologue calls when a canary is overwritten.
	//
	// **Its presence proves instrumentation; its absence does not disprove the
	// compiler flag.** -fstack-protector-strong, the distribution default,
	// instruments only functions with local arrays or address-taken locals, so
	// a small utility compiled with it correctly may contain no call at all.
	// A binary from a memory-safe language will not have one either. Both are
	// stated on MEMORY-0003 rather than guessed at here: this field records
	// what the symbol table says, and the check is where that becomes a
	// verdict.
	HasCanary bool `json:"has_canary"`

	// HasFortify reports whether the image references any _chk symbol —
	// __printf_chk, __memcpy_chk and the rest of the fortified libc variants
	// that _FORTIFY_SOURCE substitutes for the ordinary ones.
	HasFortify bool `json:"has_fortify"`

	// FortifyCandidates counts referenced libc functions that have a fortified
	// variant and were linked in their unfortified form.
	//
	// It is what separates "compiled without _FORTIFY_SOURCE" from "compiled
	// with it and calling nothing it could fortify". Without the distinction a
	// binary that never calls a string or stdio function would be reported as
	// unfortified, which is a finding about a header macro drawn from a
	// program that would look identical either way.
	FortifyCandidates int `json:"fortify_candidates,omitempty"`

	// Type is the ELF type as debug/elf names it ("ET_DYN", "ET_EXEC").
	// Recorded verbatim so a finding can state what was actually read.
	Type string `json:"type,omitempty"`

	// Digest is the sha256 of the bytes read, so a finding can cite the exact
	// image it drew a conclusion from. Set whenever the file was read, parsed
	// or not.
	Digest string `json:"digest,omitempty"`

	// Msg carries the reason for any state other than ELFObserved.
	Msg string `json:"msg,omitempty"`
}

// NX reports whether the stack is non-executable, and whether the ELF said.
//
// The second return is not a courtesy. A check that ignored it would read
// ELFStackUnspecified as an executable stack and report a finding the file does
// not support.
func (b ELFBinary) NX() (nx, known bool) {
	switch b.Stack {
	case ELFStackNoExec:
		return true, true
	case ELFStackExec:
		return false, true
	default:
		return false, false
	}
}

// Usable reports whether this entry's hardening properties may be read.
func (b ELFBinary) Usable() bool { return b.State == ELFObserved }

// FullRELRO reports whether the relocation table is both mapped read-only and
// fully resolved before the program starts, and whether the file said.
//
// The second return is false for a statically linked binary, which has no
// dynamic relocations and therefore neither has nor lacks the property.
func (b ELFBinary) FullRELRO() (full, known bool) {
	if !b.Usable() || !b.Dynamic {
		return false, false
	}
	return b.RELRO && b.BindNow, true
}

// SymbolsRead reports whether HasCanary and HasFortify carry meaning. A
// stripped image answers neither question, and a check must gate on this
// before reading either.
func (b ELFBinary) SymbolsRead() bool {
	return b.Usable() && b.Symbols == ELFSymbolsRead
}

// ELFHardening is the memory-hardening properties of the probed binaries.
//
// It carries no binary contents. The parsed properties and a digest are what a
// check needs, and a bundle is written to travel: copying whole executables
// into one would make an audit artifact the size of the binaries it audited,
// for checks that never look at the bytes. Same reasoning as the CRON module's
// refusal to collect crontab contents.
type ELFHardening struct {
	// Binaries are in the collector's declared target order, which is fixed,
	// so the fact is deterministic without anything downstream having to sort.
	//
	// A target absent from this slice was never probed, which no check may
	// read as a statement about the host. Truncated says whether that can have
	// happened.
	Binaries []ELFBinary `json:"binaries"`

	// Truncated means the collector stopped before probing every target,
	// because its context was cancelled. The entries present are true
	// observations; the absent ones were never looked at, and a check
	// concluding "none of the probed binaries is unhardened" over a truncated
	// probe is asserting something about files nobody opened.
	Truncated bool `json:"truncated,omitempty"`
}

func (ELFHardening) FactID() ID       { return ELFHardeningID }
func (ELFHardening) FactVersion() int { return 1 }

// Get returns one target's record.
func (h ELFHardening) Get(path string) (ELFBinary, bool) {
	for _, b := range h.Binaries {
		if b.Path == path {
			return b, true
		}
	}
	return ELFBinary{}, false
}

// Observed returns the entries whose properties may be read, in probe order.
func (h ELFHardening) Observed() []ELFBinary {
	var out []ELFBinary
	for _, b := range h.Binaries {
		if b.Usable() {
			out = append(out, b)
		}
	}
	return out
}

// Unreadable returns the entries that exist and could not be examined, sorted
// by path.
//
// A check calls this before drawing a negative conclusion. A binary whose bytes
// were refused could be the unhardened one, and reporting PASS over the ones
// that happened to be readable is the false assurance rule 3 forbids.
//
// ELFNotRegular counts as a gap. A FIFO or a directory where a setuid binary
// belongs is not an answer to "is this binary hardened": something occupies the
// path, this scan could not examine it, and both of the confident readings —
// "not installed" and "fine" — are wrong.
//
// Absent and not-ELF targets are excluded deliberately: neither is a gap in
// what was examined. No distribution ships every target, and a shell wrapper
// has no ELF header to harden. Folding either in would push every host with a
// missing optional binary to UNKNOWN.
func (h ELFHardening) Unreadable() []ELFBinary {
	var out []ELFBinary
	for _, b := range h.Binaries {
		switch b.State {
		case ELFDenied, ELFError, ELFTooLarge, ELFTruncated, ELFNotRegular:
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
