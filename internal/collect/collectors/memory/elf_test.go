package memory_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/memory"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// The fixtures here are built rather than committed, because a real binary in
// testdata would be one architecture's answer to a question this collector
// asks of every architecture, and 400 KiB of it per case.
//
// buildELF emits the smallest image debug/elf will accept that still carries
// the three places the properties live: a program header table, an optional
// dynamic section, and optional symbol tables. It writes 64-bit little-endian
// regardless of host, so the test asserts the same bytes everywhere.
//
// The section-header machinery below is the price of testing the symbol
// properties at all. debug/elf reaches .dynamic, .dynsym and .symtab through
// the section header table, not through the program headers, so an image
// without sections can express PIE, NX and partial RELRO and nothing else.
type elfSpec struct {
	typ   elf.Type
	progs []elf.ProgHeader
	// dynamic, when non-nil, produces a .dynamic section. An empty non-nil
	// slice is a dynamically linked binary with no flags set, which is a
	// different file from a statically linked one.
	dynamic []dynEntry
	// dynsyms and symtabs produce .dynsym and .symtab. Both nil is a stripped
	// image, which is what every distribution ships.
	dynsyms []string
	symtabs []string
}

type dynEntry struct {
	tag elf.DynTag
	val uint64
}

// section is one emitted section header plus its bytes.
type section struct {
	name    string
	typ     elf.SectionType
	link    uint32
	entsize uint64
	data    []byte
}

const (
	elfEhsize    = 64
	elfPhentsize = 56
	elfShentsize = 64
	elfSymsize   = 24
)

func buildELF(t *testing.T, spec elfSpec) []byte {
	t.Helper()

	le := binary.LittleEndian
	secs := []section{{name: ""}} // index 0 is always SHN_UNDEF

	// strtab packs names into a NUL-separated table and returns their offsets.
	strtab := func(names []string) ([]byte, []uint32) {
		buf := []byte{0}
		offs := make([]uint32, len(names))
		for i, n := range names {
			offs[i] = uint32(len(buf))
			buf = append(buf, n...)
			buf = append(buf, 0)
		}
		return buf, offs
	}
	// symbols emits Elf64_Sym entries, all undefined globals: the collector
	// reads names and nothing else, and an imported libc function is exactly
	// what these stand for.
	symbols := func(offs []uint32) []byte {
		var b bytes.Buffer
		b.Write(make([]byte, elfSymsize)) // index 0 is the null symbol
		for _, o := range offs {
			var e [elfSymsize]byte
			le.PutUint32(e[0:], o)
			e[4] = byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC))
			le.PutUint16(e[6:], uint16(elf.SHN_UNDEF))
			b.Write(e[:])
		}
		return b.Bytes()
	}

	if spec.dynamic != nil {
		var b bytes.Buffer
		for _, d := range spec.dynamic {
			mustWrite(t, &b, uint64(d.tag))
			mustWrite(t, &b, d.val)
		}
		mustWrite(t, &b, uint64(elf.DT_NULL))
		mustWrite(t, &b, uint64(0))
		secs = append(secs, section{name: ".dynamic", typ: elf.SHT_DYNAMIC, entsize: 16, data: b.Bytes()})
	}
	if spec.dynsyms != nil {
		sb, offs := strtab(spec.dynsyms)
		secs = append(secs,
			section{name: ".dynsym", typ: elf.SHT_DYNSYM, link: uint32(len(secs) + 1), entsize: elfSymsize, data: symbols(offs)},
			section{name: ".dynstr", typ: elf.SHT_STRTAB, data: sb})
	}
	if spec.symtabs != nil {
		sb, offs := strtab(spec.symtabs)
		secs = append(secs,
			section{name: ".symtab", typ: elf.SHT_SYMTAB, link: uint32(len(secs) + 1), entsize: elfSymsize, data: symbols(offs)},
			section{name: ".strtab", typ: elf.SHT_STRTAB, data: sb})
	}

	// .shstrtab holds every section name including its own, and e_shstrndx
	// points at it. Without a valid one debug/elf cannot name any section and
	// f.Section(".dynsym") finds nothing.
	shstr := []byte{0}
	nameOff := make([]uint32, len(secs)+1)
	for i, sec := range secs {
		if sec.name == "" {
			continue
		}
		nameOff[i] = uint32(len(shstr))
		shstr = append(shstr, sec.name...)
		shstr = append(shstr, 0)
	}
	nameOff[len(secs)] = uint32(len(shstr))
	shstr = append(shstr, ".shstrtab"...)
	shstr = append(shstr, 0)
	secs = append(secs, section{name: ".shstrtab", typ: elf.SHT_STRTAB, data: shstr})

	// Layout: header, program headers, section data, section headers.
	off := uint64(elfEhsize + elfPhentsize*len(spec.progs))
	dataOff := make([]uint64, len(secs))
	for i := 1; i < len(secs); i++ {
		dataOff[i] = off
		off += uint64(len(secs[i].data))
	}
	shoff := off

	var out bytes.Buffer
	w := func(v any) { mustWrite(t, &out, v) }

	out.Write([]byte{0x7f, 'E', 'L', 'F'})
	out.WriteByte(byte(elf.ELFCLASS64))
	out.WriteByte(byte(elf.ELFDATA2LSB))
	out.WriteByte(byte(elf.EV_CURRENT))
	out.WriteByte(byte(elf.ELFOSABI_LINUX))
	out.WriteByte(0)           // EI_ABIVERSION
	out.Write(make([]byte, 7)) // EI_PAD
	w(uint16(spec.typ))        // e_type
	w(uint16(elf.EM_X86_64))   // e_machine
	w(uint32(elf.EV_CURRENT))  // e_version
	w(uint64(0x1000))          // e_entry
	w(uint64(elfEhsize))       // e_phoff
	w(shoff)                   // e_shoff
	w(uint32(0))               // e_flags
	w(uint16(elfEhsize))       // e_ehsize
	w(uint16(elfPhentsize))    // e_phentsize
	w(uint16(len(spec.progs))) // e_phnum
	w(uint16(elfShentsize))    // e_shentsize
	w(uint16(len(secs)))       // e_shnum
	w(uint16(len(secs) - 1))   // e_shstrndx: .shstrtab is last

	for _, p := range spec.progs {
		w(uint32(p.Type))
		w(uint32(p.Flags))
		w(p.Off)
		w(p.Vaddr)
		w(p.Paddr)
		w(p.Filesz)
		w(p.Memsz)
		w(uint64(16))
	}
	for i := 1; i < len(secs); i++ {
		out.Write(secs[i].data)
	}
	for i, sec := range secs {
		w(nameOff[i])
		w(uint32(sec.typ))
		w(uint64(0)) // sh_flags
		w(uint64(0)) // sh_addr
		w(dataOff[i])
		w(uint64(len(sec.data)))
		w(sec.link)
		w(uint32(0)) // sh_info
		w(uint64(1)) // sh_addralign
		w(sec.entsize)
	}
	return out.Bytes()
}

func mustWrite(t *testing.T, b *bytes.Buffer, v any) {
	t.Helper()
	if err := binary.Write(b, binary.LittleEndian, v); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
}

// hardened is the fully hardened image every negative case is a variation on.
func hardened(t *testing.T) []byte {
	t.Helper()
	return buildELF(t, elfSpec{
		typ:     elf.ET_DYN,
		progs:   []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W), gnuRelro()},
		dynamic: []dynEntry{{elf.DT_FLAGS_1, uint64(elf.DF_1_NOW)}},
		dynsyms: []string{"__stack_chk_fail", "__printf_chk", "__memcpy_chk", "printf", "memcpy"},
	})
}

func gnuStack(flags elf.ProgFlag) elf.ProgHeader {
	return elf.ProgHeader{Type: elf.PT_GNU_STACK, Flags: flags, Align: 16}
}

func gnuRelro() elf.ProgHeader {
	return elf.ProgHeader{Type: elf.PT_GNU_RELRO, Flags: elf.PF_R, Align: 1}
}

// fixture writes a fake-backed system whose tree holds the given files, keyed
// by the absolute path the collector will ask for.
func fixture(t *testing.T, files map[string][]byte, manifest *fake.Manifest) *fake.System {
	t.Helper()

	root := t.TempDir()
	for p, data := range files {
		real := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
			t.Fatalf("fixture mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(real, data, 0o755); err != nil {
			t.Fatalf("fixture write %s: %v", p, err)
		}
	}
	if manifest != nil {
		dir := filepath.Join(root, filepath.FromSlash(filepath.Dir(fake.ManifestPath)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("fixture manifest dir: %v", err)
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("fixture manifest encode: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(fake.ManifestPath)), data, 0o644); err != nil {
			t.Fatalf("fixture manifest write: %v", err)
		}
	}

	sys, err := fake.New(root)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return sys
}

func collectFrom(t *testing.T, sys *fake.System) fact.ELFHardening {
	t.Helper()

	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect: %v", err)
	}
	h, ferr, ok := fact.Get[fact.ELFHardening](facts, fact.ELFHardeningID)
	if !ok {
		t.Fatalf("memory.elf missing after collection: %v", ferr)
	}
	return h
}

// TestCollectorContract asserts the declarations the runner schedules on.
func TestCollectorContract(t *testing.T) {
	c := collector.New()

	if got, want := c.ID(), "memory"; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if got := c.Produces(); len(got) != 1 || got[0] != fact.ELFHardeningID {
		t.Errorf("Produces = %v, want [%s]", got, fact.ELFHardeningID)
	}
	if got := c.DependsOn(); len(got) != 0 {
		t.Errorf("DependsOn = %v, want nothing", got)
	}
	if got, want := c.Cost(), collect.Cheap; got != want {
		t.Errorf("Cost = %v, want %v", got, want)
	}
	// CapNone deliberately: an unprivileged run must record which binaries it
	// could not read, not be skipped wholesale and report nothing.
	if got, want := c.Requires(), collect.CapNone; got != want {
		t.Errorf("Requires = %v, want %v", got, want)
	}
	if c.Timeout() <= 0 || c.Timeout() > time.Minute {
		t.Errorf("Timeout = %v; the collector must declare a budget it can justify", c.Timeout())
	}
	if _, ok := collect.Default().Get("memory"); !ok {
		t.Errorf("the memory collector did not register itself; the registry holds %v", collect.Default().IDs())
	}
}

// TestReadsTheThreeProperties is the collector's reason to exist. Each case
// pins one combination of the header bits the module reads.
func TestReadsTheThreeProperties(t *testing.T) {
	const target = "/usr/bin/sudo"

	cases := []struct {
		name  string
		typ   elf.Type
		progs []elf.ProgHeader

		wantPIE   bool
		wantStack fact.ELFStack
		wantRELRO bool
		wantType  string
	}{
		{
			name:      "hardened: PIE, NX, RELRO",
			typ:       elf.ET_DYN,
			progs:     []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W), gnuRelro()},
			wantPIE:   true,
			wantStack: fact.ELFStackNoExec,
			wantRELRO: true,
			wantType:  "ET_DYN",
		},
		{
			name:      "unhardened: fixed load address, executable stack, no RELRO",
			typ:       elf.ET_EXEC,
			progs:     []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W | elf.PF_X)},
			wantPIE:   false,
			wantStack: fact.ELFStackExec,
			wantRELRO: false,
			wantType:  "ET_EXEC",
		},
		{
			// The case a boolean would have got wrong. No PT_GNU_STACK means
			// the kernel picks, by a rule that varies with architecture and
			// version, so the file does not answer the question.
			name:      "no PT_GNU_STACK header: NX is unspecified, not absent",
			typ:       elf.ET_DYN,
			progs:     []elf.ProgHeader{gnuRelro()},
			wantPIE:   true,
			wantStack: fact.ELFStackUnspecified,
			wantRELRO: true,
			wantType:  "ET_DYN",
		},
		{
			name:      "RELRO without NX",
			typ:       elf.ET_EXEC,
			progs:     []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W | elf.PF_X), gnuRelro()},
			wantPIE:   false,
			wantStack: fact.ELFStackExec,
			wantRELRO: true,
			wantType:  "ET_EXEC",
		},
		{
			name:      "no program headers at all",
			typ:       elf.ET_EXEC,
			progs:     nil,
			wantPIE:   false,
			wantStack: fact.ELFStackUnspecified,
			wantRELRO: false,
			wantType:  "ET_EXEC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := fixture(t, map[string][]byte{
				target: buildELF(t, elfSpec{typ: tc.typ, progs: tc.progs}),
			}, nil)

			b, ok := collectFrom(t, sys).Get(target)
			if !ok {
				t.Fatalf("%s was not probed", target)
			}
			if b.State != fact.ELFObserved {
				t.Fatalf("state = %s (%s), want %s", b.State, b.Msg, fact.ELFObserved)
			}
			if b.PIE != tc.wantPIE {
				t.Errorf("PIE = %v, want %v", b.PIE, tc.wantPIE)
			}
			if b.Stack != tc.wantStack {
				t.Errorf("Stack = %s, want %s", b.Stack, tc.wantStack)
			}
			if b.RELRO != tc.wantRELRO {
				t.Errorf("RELRO = %v, want %v", b.RELRO, tc.wantRELRO)
			}
			if b.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", b.Type, tc.wantType)
			}
			if b.Digest == "" {
				t.Error("Digest is empty; a finding could not cite the image it read")
			}
		})
	}
}

// TestNXReportsWhetherTheFileAnswered is the accessor half of the case above.
// A check that ignored the second return would read an unspecified stack as an
// executable one and report a finding the file does not support.
func TestNXReportsWhetherTheFileAnswered(t *testing.T) {
	cases := []struct {
		stack     fact.ELFStack
		wantNX    bool
		wantKnown bool
	}{
		{fact.ELFStackNoExec, true, true},
		{fact.ELFStackExec, false, true},
		{fact.ELFStackUnspecified, false, false},
		{fact.ELFStack(""), false, false},
	}
	for _, tc := range cases {
		nx, known := fact.ELFBinary{Stack: tc.stack}.NX()
		if nx != tc.wantNX || known != tc.wantKnown {
			t.Errorf("%q: NX() = (%v, %v), want (%v, %v)", tc.stack, nx, known, tc.wantNX, tc.wantKnown)
		}
	}
}

// TestUnobservableStatesAreDistinguished is the module's central collector
// invariant, and the reason ELFState is not a boolean. Each of these leads a
// check somewhere different, and a collector that reported them alike would
// turn an unprivileged scan into a clean bill of health.
func TestUnobservableStatesAreDistinguished(t *testing.T) {
	const (
		present = "/usr/bin/sudo"
		script  = "/usr/bin/su"
		denied  = "/usr/bin/passwd"
		absent  = "/usr/bin/mount"
	)

	sys := fixture(t, map[string][]byte{
		present: buildELF(t, elfSpec{typ: elf.ET_DYN, progs: []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W)}}),
		// A wrapper script where a binary is expected. Read fine, parsed as
		// nothing: there is no ELF header to report hardening for.
		script: []byte("#!/bin/sh\nexec /usr/bin/su.real \"$@\"\n"),
		denied: buildELF(t, elfSpec{typ: elf.ET_DYN}),
	}, &fake.Manifest{
		Description: "one readable ELF, one script, one refused, one directory",
		Unreadable:  []string{denied},
	})

	h := collectFrom(t, sys)

	want := map[string]fact.ELFState{
		present: fact.ELFObserved,
		script:  fact.ELFNotELF,
		denied:  fact.ELFDenied,
		// Never created in the fixture tree, and every remaining target with
		// it: absence is an ordinary observation, not a gap.
		absent:           fact.ELFAbsent,
		"/usr/bin/at":    fact.ELFAbsent,
		"/usr/sbin/sshd": fact.ELFAbsent,
	}
	for path, state := range want {
		b, ok := h.Get(path)
		if !ok {
			t.Errorf("%s was not probed at all", path)
			continue
		}
		if b.State != state {
			t.Errorf("%s: state = %s (%s), want %s", path, b.State, b.Msg, state)
		}
	}

	// Only the refused one is a gap. A missing optional binary and a wrapper
	// script are answers, and folding them in here would push every host that
	// has either to UNKNOWN.
	unreadable := h.Unreadable()
	if len(unreadable) != 1 || unreadable[0].Path != denied {
		t.Errorf("Unreadable() = %v, want exactly [%s]", unreadable, denied)
	}

	// A state other than observed must never carry properties a check could
	// read as a verdict.
	for _, b := range h.Binaries {
		if b.Usable() {
			continue
		}
		if b.PIE || b.RELRO {
			t.Errorf("%s: state %s carries PIE=%v RELRO=%v; a check gating on state would still see values", b.Path, b.State, b.PIE, b.RELRO)
		}
	}
}

// TestNonRegularPathIsNotAReadError: a FIFO where a setuid binary belongs is an
// observation about the host, and the collector must not block on it either.
// The seam refuses non-regular files, which is what keeps a root process off
// the end of an unprivileged user's pipe.
func TestNonRegularPathIsNotAReadError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin", "sudo"), 0o755); err != nil {
		t.Fatal(err)
	}
	sys, err := fake.New(root)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}

	b, ok := collectFrom(t, sys).Get("/usr/bin/sudo")
	if !ok {
		t.Fatal("/usr/bin/sudo was not probed")
	}
	if b.State != fact.ELFNotRegular {
		t.Errorf("state = %s (%s), want %s", b.State, b.Msg, fact.ELFNotRegular)
	}
}

// TestEveryTargetIsProbed: absence from Binaries means "never looked at", so a
// complete run has to account for every declared target. Without this a check
// reading Get(path) would get !ok and have no way to tell a target the
// collector skipped from one it never declared.
func TestEveryTargetIsProbed(t *testing.T) {
	h := collectFrom(t, fixture(t, nil, nil))

	if h.Truncated {
		t.Error("a completed run declared itself truncated")
	}
	if got, want := len(h.Binaries), len(collector.Targets); got != want {
		t.Fatalf("probed %d targets, want %d", got, want)
	}
	for i, path := range collector.Targets {
		if h.Binaries[i].Path != path {
			t.Errorf("entry %d is %s, want %s (probe order is part of the fact)", i, h.Binaries[i].Path, path)
		}
	}
}

// TestCancelledContextTruncatesRatherThanLies: the runner abandons a collector
// that outruns its budget. What was read is still true; what was not read must
// not read as absent, which is what Truncated declares.
func TestCancelledContextTruncatesRatherThanLies(t *testing.T) {
	sys := fixture(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	facts := fact.NewSet()
	if err := collector.New().Collect(ctx, sys, facts); err != nil {
		t.Fatalf("collect: %v", err)
	}
	h, _, ok := fact.Get[fact.ELFHardening](facts, fact.ELFHardeningID)
	if !ok {
		t.Fatal("memory.elf missing; an abandoned collector must still record what it saw")
	}
	if !h.Truncated {
		t.Error("Truncated = false after cancellation; the unprobed targets would read as absent")
	}
	if len(h.Binaries) != 0 {
		t.Errorf("probed %d targets under a cancelled context, want 0", len(h.Binaries))
	}
}

// TestDoesNotPanicOnHostileBytes. The collector hands attacker-influenceable
// bytes to debug/elf inside a process that may be root. The runner recovers a
// panicking collector, but a panic still costs the whole fact, so the shapes
// most likely to provoke one are pinned here.
func TestDoesNotPanicOnHostileBytes(t *testing.T) {
	good := hardened(t)

	// e_phnum claims 65535 program headers in a 176-byte file.
	lyingPhnum := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(lyingPhnum[56:58], 0xffff)

	// e_shoff points past the end of the image.
	lyingShoff := append([]byte(nil), good...)
	binary.LittleEndian.PutUint64(lyingShoff[40:48], 1<<40)

	cases := map[string][]byte{
		"empty":              {},
		"magic only":         {0x7f, 'E', 'L', 'F'},
		"header cut in half": good[:len(good)/2],
		"lying e_phnum":      lyingPhnum,
		"lying e_shoff":      lyingShoff,
		"random text":        []byte("this is not an ELF and never was\n"),
		"all zeroes":         make([]byte, 4096),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			const target = "/usr/bin/sudo"
			sys := fixture(t, map[string][]byte{target: data}, nil)

			// The assertion is that this returns at all. A panic here fails
			// the test by unwinding it.
			b, ok := collectFrom(t, sys).Get(target)
			if !ok {
				t.Fatalf("%s was not probed", target)
			}
			if b.Usable() {
				t.Errorf("state = %s: malformed bytes were reported as a readable ELF", b.State)
			}
		})
	}
}

// TestFollowsSymlinks. On every Debian-family host /usr/bin/sudo is an
// alternatives link, so a collector that did not follow links would examine
// nothing on the one binary most worth examining and would report the miss as
// "not a regular file". Both paths are recorded: a finding naming only the link
// sends an operator to a symlink, and one naming only the destination does not
// mention the command they type.
func TestFollowsSymlinks(t *testing.T) {
	const (
		link  = "/usr/bin/sudo"
		mid   = "/etc/alternatives/sudo"
		final = "/usr/bin/sudo.real"
	)

	sys := fixture(t, map[string][]byte{
		final: hardened(t),
		// Placeholders: fake.Stat consults the tree before the manifest, so a
		// declared link still needs a file at its path.
		link: {},
		mid:  {},
	}, &fake.Manifest{
		Description: "alternatives-style two-hop link, as Debian ships it",
		Symlinks:    map[string]string{link: mid, mid: final},
	})

	b, ok := collectFrom(t, sys).Get(link)
	if !ok {
		t.Fatalf("%s was not probed", link)
	}
	if b.State != fact.ELFObserved {
		t.Fatalf("state = %s (%s), want %s", b.State, b.Msg, fact.ELFObserved)
	}
	if b.Path != link {
		t.Errorf("Path = %q, want the target as declared, %q", b.Path, link)
	}
	if b.Resolved != final {
		t.Errorf("Resolved = %q, want %q", b.Resolved, final)
	}
	if !b.PIE || b.Stack != fact.ELFStackNoExec || !b.RELRO {
		t.Errorf("properties came from the wrong file: pie=%v stack=%s relro=%v", b.PIE, b.Stack, b.RELRO)
	}
}

// TestSymlinkFailuresAreNotAnObservation: a link pointing nowhere and a link
// that loops are different from a hardened binary and from each other, and
// neither may resolve to a reading of some other file.
func TestSymlinkFailuresAreNotAnObservation(t *testing.T) {
	cases := []struct {
		name      string
		symlinks  map[string]string
		wantState fact.ELFState
	}{
		{
			name:      "dangling",
			symlinks:  map[string]string{"/usr/bin/sudo": "/usr/bin/sudo.uninstalled"},
			wantState: fact.ELFAbsent,
		},
		{
			name: "loop",
			symlinks: map[string]string{
				"/usr/bin/sudo":   "/usr/bin/sudo.a",
				"/usr/bin/sudo.a": "/usr/bin/sudo",
			},
			wantState: fact.ELFError,
		},
		{
			// A relative target read as absolute names a completely different
			// file. ln -s writes these routinely.
			name:      "relative target",
			symlinks:  map[string]string{"/usr/bin/sudo": "sudo.real"},
			wantState: fact.ELFObserved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{
				"/usr/bin/sudo":      {},
				"/usr/bin/sudo.a":    {},
				"/usr/bin/sudo.real": hardened(t),
			}
			sys := fixture(t, files, &fake.Manifest{Symlinks: tc.symlinks})

			b, ok := collectFrom(t, sys).Get("/usr/bin/sudo")
			if !ok {
				t.Fatal("/usr/bin/sudo was not probed")
			}
			if b.State != tc.wantState {
				t.Fatalf("state = %s (%s), want %s", b.State, b.Msg, tc.wantState)
			}
			if b.State != fact.ELFObserved && (b.PIE || b.RELRO) {
				t.Errorf("a %s entry carries pie=%v relro=%v", b.State, b.PIE, b.RELRO)
			}
		})
	}
}

// TestReadsBindNowInAllThreeEncodings. Three dynamic-section encodings mean the
// same thing and toolchains disagree about which to emit. DT_BIND_NOW is the
// one the specification names and the one nothing produces any more: on a
// sample of stock Debian binaries not a single image carried it and every one
// carried DF_1_NOW. A reader that trusted the documented tag would report every
// correctly hardened binary on a current distribution as lazily bound.
func TestReadsBindNowInAllThreeEncodings(t *testing.T) {
	const target = "/usr/bin/sudo"

	cases := []struct {
		name    string
		dynamic []dynEntry
		want    bool
	}{
		{"DT_BIND_NOW, the original", []dynEntry{{elf.DT_BIND_NOW, 0}}, true},
		{"DT_FLAGS with DF_BIND_NOW", []dynEntry{{elf.DT_FLAGS, uint64(elf.DF_BIND_NOW)}}, true},
		{"DT_FLAGS_1 with DF_1_NOW, what linkers emit", []dynEntry{{elf.DT_FLAGS_1, uint64(elf.DF_1_NOW)}}, true},
		{"DT_FLAGS carrying other flags only", []dynEntry{{elf.DT_FLAGS, uint64(elf.DF_ORIGIN)}}, false},
		{"a dynamic section with no flags at all", []dynEntry{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := fixture(t, map[string][]byte{
				target: buildELF(t, elfSpec{
					typ:     elf.ET_DYN,
					progs:   []elf.ProgHeader{gnuRelro()},
					dynamic: tc.dynamic,
				}),
			}, nil)

			b, ok := collectFrom(t, sys).Get(target)
			if !ok {
				t.Fatalf("%s was not probed", target)
			}
			if !b.Dynamic {
				t.Fatal("a binary with a .dynamic section was recorded as statically linked")
			}
			if b.BindNow != tc.want {
				t.Errorf("BindNow = %v, want %v", b.BindNow, tc.want)
			}
			// Full RELRO is partial RELRO and eager binding together. Partial
			// alone leaves the PLT's GOT writable, which is the whole reason
			// the two are separate fields.
			full, known := b.FullRELRO()
			if !known {
				t.Fatal("FullRELRO reported unknown for a dynamically linked binary")
			}
			if full != tc.want {
				t.Errorf("FullRELRO = %v, want %v (RELRO=%v BindNow=%v)", full, tc.want, b.RELRO, b.BindNow)
			}
		})
	}
}

// TestStaticBinaryHasNoBindingToReport. A statically linked image resolves
// nothing at run time, so it neither has nor lacks eager binding. Reporting it
// as lazily bound would be a finding about a mechanism the file does not use.
func TestStaticBinaryHasNoBindingToReport(t *testing.T) {
	const target = "/usr/bin/sudo"
	sys := fixture(t, map[string][]byte{
		target: buildELF(t, elfSpec{
			typ:     elf.ET_EXEC,
			progs:   []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W), gnuRelro()},
			symtabs: []string{"__stack_chk_fail", "main"},
		}),
	}, nil)

	b, ok := collectFrom(t, sys).Get(target)
	if !ok {
		t.Fatalf("%s was not probed", target)
	}
	if b.Dynamic {
		t.Error("an image with no .dynamic section was recorded as dynamically linked")
	}
	if b.BindNow {
		t.Error("BindNow is true on a static binary, which has no relocations to bind")
	}
	if _, known := b.FullRELRO(); known {
		t.Error("FullRELRO claims to know an answer for a statically linked binary")
	}
	// The symbol properties still work: .symtab is where an unstripped static
	// binary keeps them, and reading only .dynsym would have missed it.
	if !b.SymbolsRead() {
		t.Fatalf("symbols = %s, want them read from .symtab", b.Symbols)
	}
	if !b.HasCanary {
		t.Error("__stack_chk_fail in .symtab was not seen; only .dynsym is being read")
	}
}

// TestReadsSymbolProperties covers the canary and FORTIFY evidence, including
// the two silences that are not the same as an absence.
func TestReadsSymbolProperties(t *testing.T) {
	const target = "/usr/bin/sudo"

	cases := []struct {
		name    string
		dynsyms []string
		symtabs []string

		wantState      fact.ELFSymbols
		wantCanary     bool
		wantFortify    bool
		wantCandidates int
	}{
		{
			name:           "hardened: canary and fortified calls",
			dynsyms:        []string{"__stack_chk_fail", "__printf_chk", "__memcpy_chk", "printf"},
			wantState:      fact.ELFSymbolsRead,
			wantCanary:     true,
			wantFortify:    true,
			wantCandidates: 1, // printf, unfortified, alongside its _chk form
		},
		{
			name:           "unhardened: unfortified calls, no canary",
			dynsyms:        []string{"printf", "memcpy", "strcpy", "malloc"},
			wantState:      fact.ELFSymbolsRead,
			wantCanary:     false,
			wantFortify:    false,
			wantCandidates: 3, // malloc has no fortified variant
		},
		{
			// The case that separates "not fortified" from "nothing to
			// fortify". No _chk symbols and nothing that could have had one.
			name:           "nothing fortifiable is called at all",
			dynsyms:        []string{"malloc", "free", "exit"},
			wantState:      fact.ELFSymbolsRead,
			wantCanary:     false,
			wantFortify:    false,
			wantCandidates: 0,
		},
		{
			// A canary without fortified calls is an ordinary combination:
			// the two come from different compiler flags.
			name:           "canary but no FORTIFY",
			dynsyms:        []string{"__stack_chk_fail", "memcpy"},
			wantState:      fact.ELFSymbolsRead,
			wantCanary:     true,
			wantFortify:    false,
			wantCandidates: 1,
		},
		{
			// Both tables are unioned. A binary can carry either or both.
			name:           "evidence split across both tables",
			dynsyms:        []string{"printf"},
			symtabs:        []string{"__stack_chk_fail"},
			wantState:      fact.ELFSymbolsRead,
			wantCanary:     true,
			wantFortify:    false,
			wantCandidates: 1,
		},
		{
			// The silence that is not an absence. No table means no evidence
			// either way, and a boolean would have read this as "unhardened".
			name:        "stripped: no table to be absent from",
			wantState:   fact.ELFSymbolsStripped,
			wantCanary:  false,
			wantFortify: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := fixture(t, map[string][]byte{
				target: buildELF(t, elfSpec{
					typ:     elf.ET_DYN,
					progs:   []elf.ProgHeader{gnuStack(elf.PF_R | elf.PF_W), gnuRelro()},
					dynamic: []dynEntry{{elf.DT_FLAGS_1, uint64(elf.DF_1_NOW)}},
					dynsyms: tc.dynsyms,
					symtabs: tc.symtabs,
				}),
			}, nil)

			b, ok := collectFrom(t, sys).Get(target)
			if !ok {
				t.Fatalf("%s was not probed", target)
			}
			if b.State != fact.ELFObserved {
				t.Fatalf("state = %s (%s)", b.State, b.Msg)
			}
			if b.Symbols != tc.wantState {
				t.Errorf("Symbols = %s, want %s", b.Symbols, tc.wantState)
			}
			if b.HasCanary != tc.wantCanary {
				t.Errorf("HasCanary = %v, want %v", b.HasCanary, tc.wantCanary)
			}
			if b.HasFortify != tc.wantFortify {
				t.Errorf("HasFortify = %v, want %v", b.HasFortify, tc.wantFortify)
			}
			if b.FortifyCandidates != tc.wantCandidates {
				t.Errorf("FortifyCandidates = %d, want %d", b.FortifyCandidates, tc.wantCandidates)
			}
			if got := b.SymbolsRead(); got != (tc.wantState == fact.ELFSymbolsRead) {
				t.Errorf("SymbolsRead() = %v for state %s", got, b.Symbols)
			}
		})
	}
}

// TestStrippedImageIsNotAnUnhardenedOne is the symbol half of the module's
// central property, and the reason ELFSymbols is not a boolean. A stripped
// binary and one with an empty symbol table are indistinguishable to anything
// that only counts symbols, and reading either as "no canary" reports a
// hardened binary as unhardened on the strength of having found nothing to
// look at.
func TestStrippedImageIsNotAnUnhardenedOne(t *testing.T) {
	const target = "/usr/bin/sudo"

	stripped := fixture(t, map[string][]byte{
		target: buildELF(t, elfSpec{typ: elf.ET_DYN, progs: []elf.ProgHeader{gnuRelro()}}),
	}, nil)
	unhardened := fixture(t, map[string][]byte{
		target: buildELF(t, elfSpec{
			typ:     elf.ET_DYN,
			progs:   []elf.ProgHeader{gnuRelro()},
			dynsyms: []string{"printf", "memcpy"},
		}),
	}, nil)

	s, _ := collectFrom(t, stripped).Get(target)
	u, _ := collectFrom(t, unhardened).Get(target)

	if s.HasCanary || u.HasCanary {
		t.Fatal("neither image has a canary symbol; the comparison below proves nothing")
	}
	if s.SymbolsRead() {
		t.Error("a stripped image reported its symbols as read")
	}
	if !u.SymbolsRead() {
		t.Error("an image with a .dynsym reported its symbols as unread")
	}
	// Same booleans, different meanings. Only the state tells them apart.
	if s.Symbols == u.Symbols {
		t.Errorf("both images report Symbols = %s; a check cannot tell 'no canary' from 'no evidence'", s.Symbols)
	}
}
