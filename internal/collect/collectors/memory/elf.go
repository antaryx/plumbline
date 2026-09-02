// Package memory collects ELF memory-hardening properties from the binaries
// most worth hardening on a Linux host.
//
// It reads headers and symbol names, never code paths, and it never executes
// anything. Everything comes out of the ELF image with debug/elf, from three
// places in it:
//
//	program headers    PIE, from the ELF type being ET_DYN
//	                   NX, from the PF_X bit on PT_GNU_STACK
//	                   partial RELRO, from PT_GNU_RELRO being present
//	dynamic section    BindNow, from DT_BIND_NOW, DF_BIND_NOW or DF_1_NOW
//	symbol tables      stack canaries, from __stack_chk_fail
//	                   FORTIFY_SOURCE, from the _chk entry points
//
// All of it is static, so this collector is a pure read of bytes the kernel
// would read anyway, and its answers are identical whether the binary has ever
// been run.
//
// The two halves differ in what a silence means, and that is the whole
// difficulty of the module. A program header is present or it is not, and
// either way the file has answered. A symbol's absence is only evidence if
// there was a symbol table to be absent from — every binary a distribution
// ships is stripped of .symtab — and even then it is weaker evidence than it
// looks, because a compiler emits __stack_chk_fail only for functions that
// needed a canary. fact.ELFSymbols carries the first distinction; the checks
// carry the second.
//
// The target list is explicit rather than discovered, for the reason the KERNEL
// module states about /proc/sys: walking /usr/bin would produce several
// thousand facts, put every executable path on the host into a bundle designed
// to travel, and take an unbounded amount of time to do it. A collector reads
// what the checks need and no more.
package memory

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier. The collector is "memory"; the fact it
// writes is "memory.elf".
const ID = "memory"

// MaxBinaryRead bounds one binary. A file larger than this is recorded as
// fact.ELFTooLarge and is never read.
//
// The cap is a bound, not an expectation. Every binary on this list is tens to
// a few hundred kilobytes — sshd is the largest at about 400 KiB on a current
// Debian — so the cap is never approached by an honest host. It exists because
// this process may be root and a path under /usr/bin is not a promise about
// what is at it.
//
// It is a whole-file cap rather than a prefix read because debug/elf resolves
// the section header table during NewFile, and e_shoff points at the end of the
// image. Every prefix of a real binary therefore fails to parse with EOF, so
// there is no smaller read that answers the question; a partial read can only
// be recorded as a gap, which is what fact.ELFTruncated is.
const MaxBinaryRead int64 = 16 << 20

// maxSymlinkHops bounds symlink resolution for one target.
//
// The seam never follows a terminal symlink, deliberately: resolution is the
// caller's job and has to go back through the interface so that --root still
// governs what is looked at. That makes following the link this collector's
// work, and a bound is what stops a cycle from spinning a root process. Real
// chains are short — Debian's alternatives system is two hops, /usr/bin/sudo to
// /etc/alternatives/sudo to the binary — so eight is far past anything honest.
const maxSymlinkHops = 8

// errSymlinkLoop is returned when resolution exceeds maxSymlinkHops. It is a
// distinct condition from a broken link and is recorded as one.
var errSymlinkLoop = errors.New("symlink chain exceeds the hop limit")

// Targets are the binaries this module probes, in record order.
//
// Two groups, and both are on the list for the same reason: they are the
// programs on a Linux host where a missing mitigation is worth an operator's
// attention, because they either already run with privilege or are the first
// thing an unprivileged process reaches for.
//
//   - setuid-root utilities, where a memory-corruption bug is a local root
//     escalation rather than a crash
//   - the privileged daemons and helpers that authenticate, schedule, or
//     accept a connection
//
// The merged-usr duplicates (/bin, /sbin) are deliberately absent. On a merged
// host they are symlinks to the /usr paths already listed and would record the
// same inode twice; on an unmerged host the /usr path is the one the
// distribution installs. A target that is not present is recorded as
// fact.ELFAbsent, which is an ordinary observation rather than a gap.
//
// The order is fixed rather than sorted at use, so the fact is byte-identical
// across two collections of an unchanged host.
var Targets = []string{
	"/usr/bin/at",
	"/usr/bin/chfn",
	"/usr/bin/chsh",
	"/usr/bin/crontab",
	"/usr/bin/gpasswd",
	"/usr/bin/mount",
	"/usr/bin/newgrp",
	"/usr/bin/passwd",
	"/usr/bin/pkexec",
	"/usr/bin/su",
	"/usr/bin/sudo",
	"/usr/bin/umount",
	"/usr/sbin/sshd",
	"/usr/sbin/unix_chkpwd",
}

// Collector implements collect.Collector for ELF memory hardening.
type Collector struct{}

// New returns the memory collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

// Produces names the fact this collector is responsible for, so a failure it
// never got to report is filed against memory.elf, which is what MEMORY checks
// will require and look up.
func (Collector) Produces() []fact.ID { return []fact.ID{fact.ELFHardeningID} }

// DependsOn is nil. Reading an ELF header needs nothing else observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone.
//
// Every target here is world-readable on a stock installation — a setuid binary
// has to be executable by the users it exists for. Declaring CapRoot would make
// an unprivileged scan skip the collector wholesale and report only that it was
// skipped; running it means each target records whether it was readable, and a
// check resolves to UNKNOWN for exactly the ones that were not.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap.
//
// The target list is fixed and short, and the files on it are small: a whole
// pass is a couple of megabytes of sequential reads by name. There is no walk,
// no exec and no network. MaxBinaryRead bounds the pathological case rather
// than describing the normal one.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is thirty seconds.
//
// Fourteen bounded reads of small files should finish in milliseconds. The
// budget is not sized for that case: /usr may be on a network filesystem, and a
// server that has stopped answering turns a read by name into an indefinite
// block. Thirty seconds is long enough that no healthy host approaches it and
// short enough that an audit records why it stopped instead of hanging.
func (Collector) Timeout() time.Duration { return 30 * time.Second }

// Collect probes each target and records what it found.
//
// It returns nil in every circumstance. A binary that could not be read is
// recorded as that binary's state, not as a failure of the whole fact: the
// difference between "one target was refused" and "we know nothing about this
// host's binaries" is the difference between one UNKNOWN finding and all of
// them.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	h := fact.ELFHardening{Binaries: make([]fact.ELFBinary, 0, len(Targets))}

	for _, target := range Targets {
		// An abandoned scan stops reading. The runner has already stopped
		// waiting, so every further read is work done on the audited host for
		// a result nobody will look at. What was read so far is still true, so
		// it is kept and the shortfall is declared rather than hidden.
		if ctx.Err() != nil {
			h.Truncated = true
			break
		}
		h.Binaries = append(h.Binaries, inspect(s, target))
	}

	fs.Put(h)
	return nil
}

// inspect reads one binary and returns its record.
//
// Stat comes before ReadFile so that an oversized file is refused by size
// rather than read and then discarded, and so that a non-regular file at a
// binary's path is recorded as what it is instead of as a read error.
func inspect(s system.System, target string) fact.ELFBinary {
	b := fact.ELFBinary{Path: target, Stack: fact.ELFStackUnspecified}

	// Symlinks are followed here rather than at the seam. This is not an edge
	// case: on every Debian-family host /usr/bin/sudo is an alternatives link,
	// and a collector that reported it as a non-regular file would examine
	// nothing on the one binary most worth examining.
	readPath, fi, err := resolveTarget(s, target)
	switch {
	case errors.Is(err, system.ErrNotExist):
		b.State = fact.ELFAbsent
		if readPath != target {
			b.Resolved = readPath
			b.Msg = "the symlink target does not exist"
		}
		return b
	case errors.Is(err, system.ErrPermission):
		b.State = fact.ELFDenied
		b.Msg = "cannot stat the path"
		return b
	case err != nil:
		b.State = fact.ELFError
		b.Msg = err.Error()
		return b
	}
	if readPath != target {
		b.Resolved = readPath
	}

	if !fi.IsRegular {
		b.State = fact.ELFNotRegular
		b.Msg = "the path is not a regular file"
		return b
	}
	if fi.Size > MaxBinaryRead {
		b.State = fact.ELFTooLarge
		b.Msg = "the file exceeds the collector's read cap and was not read"
		return b
	}

	// ReadOpaque, not ReadFile: the bytes of an executable are not evidence
	// anybody reads, and a bundle that carried them would be the size of the
	// binaries it audited. The digest below is what survives, and it is the
	// part an auditor can actually verify against the running host. The
	// exclusion itself lives at the seam — see collect.recordingSystem.
	res, err := s.ReadOpaque(readPath, MaxBinaryRead)
	switch {
	case errors.Is(err, system.ErrNotExist):
		// It was there a moment ago. Absent is still the honest record of what
		// the read found.
		b.State = fact.ELFAbsent
		return b
	case errors.Is(err, system.ErrPermission):
		b.State = fact.ELFDenied
		b.Msg = "cannot read the file"
		return b
	case errors.Is(err, system.ErrNotRegular):
		b.State = fact.ELFNotRegular
		b.Msg = "the path is not a regular file"
		return b
	case err != nil:
		b.State = fact.ELFError
		b.Msg = err.Error()
		return b
	}

	if res.Truncated {
		// The size check passed and the read still hit the cap, so the file
		// grew between the two. A prefix of an ELF does not parse, and
		// reporting on one would be reporting on a file that no longer exists
		// in the form it was measured.
		b.State = fact.ELFTruncated
		b.Msg = "the file grew past the read cap between stat and read"
		return b
	}

	// The digest is over the bytes actually read, computed at the seam. It is
	// recorded before the parse so that a file that turned out not to be an
	// ELF still cites the image the conclusion was drawn from.
	b.Digest = res.SHA256

	// debug/elf over the bytes in hand rather than elf.Open, which would open
	// the path itself: that bypasses --root, the read cap and the fixture
	// backend all at once, and CONTRIBUTING.md rule 1 exists to stop exactly
	// that. bytes.Reader is the io.ReaderAt NewFile wants.
	f, err := elf.NewFile(bytes.NewReader(res.Data))
	if err != nil {
		// Not an ELF at all — a shell wrapper, an interpreter shebang, or a
		// file whose headers are inconsistent. Either way there is no ELF to
		// report hardening for, and guessing from a broken header is worse
		// than saying so.
		b.State = fact.ELFNotELF
		b.Msg = err.Error()
		return b
	}

	b.State = fact.ELFObserved
	b.Type = f.Type.String()
	// ET_DYN is position-independent code. It is also every shared object's
	// type; see fact.ELFBinary.PIE for why that is not a problem for the
	// targets on this list and why Type is recorded anyway.
	b.PIE = f.Type == elf.ET_DYN

	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			// The header's presence is the answer, whichever way the bit
			// points. Its absence is not an answer at all, which is why Stack
			// was initialised to unspecified rather than to noexec.
			if p.Flags&elf.PF_X != 0 {
				b.Stack = fact.ELFStackExec
			} else {
				b.Stack = fact.ELFStackNoExec
			}
		case elf.PT_GNU_RELRO:
			// Partial RELRO. Full RELRO is this plus BindNow, read below.
			b.RELRO = true
		}
	}

	b.Dynamic, b.BindNow = readBinding(f)
	readSymbols(f, &b)
	return b
}

// readBinding reports whether the image is dynamically linked and, if so,
// whether it asks the dynamic linker to resolve every relocation up front.
//
// Three encodings mean the same thing, and all three are checked because
// toolchains disagree about which to emit. DT_BIND_NOW is the original and is
// now essentially extinct — on a sample of stock Debian binaries not one
// carried it, while every one carried DF_1_NOW. A reader that trusted the tag
// named in the specification would report every hardened binary on a current
// distribution as lazily bound.
func readBinding(f *elf.File) (dynamic, bindNow bool) {
	if f.SectionByType(elf.SHT_DYNAMIC) == nil {
		// Statically linked: no dynamic relocations, so eager binding is not a
		// property this file can have. The caller must not read BindNow.
		return false, false
	}

	// DynValue returns ErrNoSymbols or a missing-tag error for a tag the
	// section does not carry, which is the ordinary case for two of these
	// three. An error here means "not set", never "could not tell".
	if v, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(v) > 0 {
		return true, true
	}
	if v, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, raw := range v {
			if raw&uint64(elf.DF_BIND_NOW) != 0 {
				return true, true
			}
		}
	}
	if v, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, raw := range v {
			if raw&uint64(elf.DF_1_NOW) != 0 {
				return true, true
			}
		}
	}
	return true, false
}

// stackCanarySymbol is the function a stack-protector prologue calls when the
// canary has been overwritten. Its presence is what proves instrumentation.
const stackCanarySymbol = "__stack_chk_fail"

// fortifySuffix is what _FORTIFY_SOURCE's substituted libc entry points end
// with: __printf_chk, __memcpy_chk, __strcpy_chk and the rest.
const fortifySuffix = "_chk"

// fortifiable are libc functions that have a fortified variant.
//
// The list exists to tell two silences apart. A binary with no _chk symbol may
// have been compiled without _FORTIFY_SOURCE, or may have been compiled with
// it and call nothing the macro could substitute — and those are a finding and
// a non-finding respectively. Counting the unfortified originals is what
// distinguishes them: a binary that calls memcpy and sprintf and has no
// __memcpy_chk was not fortified, while one that calls neither would look
// identical either way.
//
// It is deliberately not exhaustive. glibc fortifies well over a hundred
// entry points; these are the ones a program has to work at to avoid, so a
// binary that references none of them genuinely has very little to fortify.
// Adding to the list can only sharpen the distinction, never change a verdict
// from FAIL to PASS.
var fortifiable = map[string]bool{
	"printf": true, "fprintf": true, "sprintf": true, "snprintf": true,
	"vprintf": true, "vfprintf": true, "vsprintf": true, "vsnprintf": true,
	"memcpy": true, "memmove": true, "memset": true, "mempcpy": true,
	"strcpy": true, "stpcpy": true, "strncpy": true, "strcat": true,
	"strncat": true, "gets": true, "read": true, "pread": true,
	"realpath": true, "getcwd": true, "poll": true, "recv": true,
}

// readSymbols fills in the symbol-derived properties.
//
// Both tables are consulted and the results unioned. Which one holds the
// evidence depends on how the binary was built and shipped: a stripped image —
// which is every binary a distribution installs — keeps .dynsym and discards
// .symtab, while a statically linked unstripped one has the reverse. Reading
// only the table the common case uses would report a locally built static
// binary as having no symbols at all.
//
// debug/elf reports an absent table as elf.ErrNoSymbols rather than as a parse
// failure, and that distinction is the whole of this function's care: no table
// is a fact about the file (it was stripped), and it is recorded as
// ELFSymbolsStripped so a check resolves to UNKNOWN instead of reading an empty
// list as an absence of instrumentation.
func readSymbols(f *elf.File, b *fact.ELFBinary) {
	var names []string
	found := false

	if syms, err := f.DynamicSymbols(); err == nil {
		found = true
		for _, s := range syms {
			names = append(names, s.Name)
		}
	}
	if syms, err := f.Symbols(); err == nil {
		found = true
		for _, s := range syms {
			names = append(names, s.Name)
		}
	}

	if !found {
		b.Symbols = fact.ELFSymbolsStripped
		return
	}

	b.Symbols = fact.ELFSymbolsRead
	b.SymbolCount = len(names)
	for _, n := range names {
		switch {
		case n == stackCanarySymbol:
			b.HasCanary = true
		case strings.HasSuffix(n, fortifySuffix):
			// Every fortified entry point ends this way and nothing else in a
			// libc-linked binary does. A local symbol coincidentally named so
			// would be a false positive in the safe direction: it can only
			// turn a FAIL into a PASS for a binary that named a function
			// after the convention, which is not a mistake worth widening the
			// test to catch.
			b.HasFortify = true
		case fortifiable[n]:
			b.FortifyCandidates++
		}
	}
}

// resolveTarget follows symbolic links at start and returns the path that is
// not a link, together with its metadata.
//
// Every hop goes back through the seam — Readlink, then Stat on the resolved
// path — so a scan with --root stays inside the tree it was pointed at. A seam
// that resolved links itself would have dereferenced them against the real
// host, which is what --root exists to prevent (ADR-0017).
//
// The returned path is the last one examined even on failure, so the caller can
// report which link in the chain broke rather than only that one did.
func resolveTarget(s system.System, start string) (string, system.FileInfo, error) {
	p := start
	for hop := 0; hop < maxSymlinkHops; hop++ {
		fi, err := s.Stat(p)
		if err != nil {
			return p, system.FileInfo{}, err
		}
		if !fi.IsSymlink {
			return p, fi, nil
		}
		dest, err := s.Readlink(p)
		if err != nil {
			return p, system.FileInfo{}, err
		}
		p = resolveAgainst(p, dest)
	}
	return p, system.FileInfo{}, errSymlinkLoop
}

// resolveAgainst makes a link target absolute against the link's own directory.
//
// A relative target read as absolute names a completely different file, and
// relative targets are ordinary: `ln -s sudo.real sudo` writes one. The result
// is handed straight back through the seam, so --root still governs it.
func resolveAgainst(link, dest string) string {
	if path.IsAbs(dest) {
		return path.Clean(dest)
	}
	return path.Clean(path.Join(path.Dir(link), dest))
}
