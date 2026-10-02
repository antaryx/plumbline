// Package elfgen builds the smallest ELF images debug/elf will accept that
// still carry the properties the MEMORY collector reads.
//
// It exists so that no test needs a committed binary. A real /usr/bin/sudo in
// testdata is one architecture's answer to a question the collector asks of
// every architecture, it is several hundred KiB per case, and — being a copy of
// a distribution's build — it travels without the source or the licence that
// would make redistributing it legitimate. A generated image has none of those
// problems and is a more honest test besides: the bytes under test are the ones
// the case is about and nothing else.
//
// The three places the properties live are the program header table, an
// optional dynamic section, and optional symbol tables:
//
//	e_type                        PIE
//	PT_GNU_STACK PF_X             NX
//	PT_GNU_RELRO                  partial RELRO
//	DT_BIND_NOW/DF_BIND_NOW/DF_1_NOW   full RELRO
//	.dynsym / .symtab             stack canary, FORTIFY_SOURCE
//
// Output is 64-bit little-endian regardless of host, so a test asserts the same
// bytes everywhere.
//
// This is the importable twin of the builder in the memory collector's own
// elf_test.go. That copy predates this package and should be migrated onto it;
// the two must not be allowed to disagree about ELF layout.
package elfgen

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// Spec describes an image to build. The zero value is a headerless ET_NONE
// file, which is not useful; every field is meant to be set deliberately.
type Spec struct {
	// Type is e_type: ET_DYN for a position-independent image, ET_EXEC for one
	// loaded at a fixed address.
	Type elf.Type
	// Progs is the program header table. GNUStack and GNURelro build the two
	// entries that carry a hardening property.
	Progs []elf.ProgHeader
	// Dynamic, when non-nil, produces a .dynamic section. An empty non-nil
	// slice is a dynamically linked binary with no flags set, which is a
	// different file from a statically linked one — that distinction is the
	// whole of the full-versus-partial RELRO question, so the nil-ness matters.
	Dynamic []Dyn
	// Dynsyms and Symtabs produce .dynsym and .symtab. Both nil is a stripped
	// image, which is what every distribution ships.
	Dynsyms []string
	Symtabs []string
}

// Dyn is one entry in the dynamic section.
type Dyn struct {
	Tag elf.DynTag
	Val uint64
}

// Canary is the symbol a compiler emits a reference to when the stack
// protector is in effect.
const Canary = "__stack_chk_fail"

// GNUStack builds a PT_GNU_STACK header. Pass PF_R|PF_W for a non-executable
// stack; adding PF_X is what NX detection must catch.
func GNUStack(flags elf.ProgFlag) elf.ProgHeader {
	return elf.ProgHeader{Type: elf.PT_GNU_STACK, Flags: flags, Align: 16}
}

// GNURelro builds a PT_GNU_RELRO header, which on its own is partial RELRO.
func GNURelro() elf.ProgHeader {
	return elf.ProgHeader{Type: elf.PT_GNU_RELRO, Flags: elf.PF_R, Align: 1}
}

// Hardened is the fully hardened image every negative case is a variation on:
// ET_DYN, non-executable stack, PT_GNU_RELRO, DF_1_NOW, a canary reference and
// fortified _chk entry points alongside the unfortified names they replace.
func Hardened() Spec {
	return Spec{
		Type:    elf.ET_DYN,
		Progs:   []elf.ProgHeader{GNUStack(elf.PF_R | elf.PF_W), GNURelro()},
		Dynamic: []Dyn{{elf.DT_FLAGS_1, uint64(elf.DF_1_NOW)}},
		Dynsyms: []string{Canary, "__printf_chk", "__memcpy_chk", "printf", "memcpy"},
	}
}

const (
	ehsize    = 64
	phentsize = 56
	shentsize = 64
	symsize   = 24
)

// section is one emitted section header plus its bytes.
type section struct {
	name    string
	typ     elf.SectionType
	link    uint32
	entsize uint64
	data    []byte
}

// Build emits the image. The only error it can return comes from encoding, so a
// caller building a literal Spec may treat a failure as a programming fault.
func Build(spec Spec) ([]byte, error) {
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
		b.Write(make([]byte, symsize)) // index 0 is the null symbol
		for _, o := range offs {
			var e [symsize]byte
			le.PutUint32(e[0:], o)
			e[4] = elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)
			le.PutUint16(e[6:], uint16(elf.SHN_UNDEF))
			b.Write(e[:])
		}
		return b.Bytes()
	}

	var err error
	put := func(b *bytes.Buffer, v any) {
		if err == nil {
			err = binary.Write(b, binary.LittleEndian, v)
		}
	}

	if spec.Dynamic != nil {
		var b bytes.Buffer
		for _, d := range spec.Dynamic {
			put(&b, uint64(d.Tag))
			put(&b, d.Val)
		}
		put(&b, uint64(elf.DT_NULL))
		put(&b, uint64(0))
		secs = append(secs, section{name: ".dynamic", typ: elf.SHT_DYNAMIC, entsize: 16, data: b.Bytes()})
	}
	if spec.Dynsyms != nil {
		sb, offs := strtab(spec.Dynsyms)
		secs = append(secs,
			section{name: ".dynsym", typ: elf.SHT_DYNSYM, link: uint32(len(secs) + 1), entsize: symsize, data: symbols(offs)},
			section{name: ".dynstr", typ: elf.SHT_STRTAB, data: sb})
	}
	if spec.Symtabs != nil {
		sb, offs := strtab(spec.Symtabs)
		secs = append(secs,
			section{name: ".symtab", typ: elf.SHT_SYMTAB, link: uint32(len(secs) + 1), entsize: symsize, data: symbols(offs)},
			section{name: ".strtab", typ: elf.SHT_STRTAB, data: sb})
	}

	// .shstrtab holds every section name including its own, and e_shstrndx
	// points at it. Without a valid one debug/elf cannot name any section and
	// Section(".dynsym") finds nothing.
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
	off := uint64(ehsize + phentsize*len(spec.Progs))
	dataOff := make([]uint64, len(secs))
	for i := 1; i < len(secs); i++ {
		dataOff[i] = off
		off += uint64(len(secs[i].data))
	}
	shoff := off

	var out bytes.Buffer
	w := func(v any) { put(&out, v) }

	out.Write([]byte{0x7f, 'E', 'L', 'F'})
	out.WriteByte(byte(elf.ELFCLASS64))
	out.WriteByte(byte(elf.ELFDATA2LSB))
	out.WriteByte(byte(elf.EV_CURRENT))
	out.WriteByte(byte(elf.ELFOSABI_LINUX))
	out.WriteByte(0)           // EI_ABIVERSION
	out.Write(make([]byte, 7)) // EI_PAD
	w(uint16(spec.Type))       // e_type
	w(uint16(elf.EM_X86_64))   // e_machine
	w(uint32(elf.EV_CURRENT))  // e_version
	w(uint64(0x1000))          // e_entry
	w(uint64(ehsize))          // e_phoff
	w(shoff)                   // e_shoff
	w(uint32(0))               // e_flags
	w(uint16(ehsize))          // e_ehsize
	w(uint16(phentsize))       // e_phentsize
	w(uint16(len(spec.Progs))) // e_phnum
	w(uint16(shentsize))       // e_shentsize
	w(uint16(len(secs)))       // e_shnum
	w(uint16(len(secs) - 1))   // e_shstrndx: .shstrtab is last

	for _, p := range spec.Progs {
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
	if err != nil {
		return nil, fmt.Errorf("building ELF image: %w", err)
	}
	return out.Bytes(), nil
}

// MustBuild is Build for a literal Spec, where a failure is a programming
// fault rather than a condition to handle.
func MustBuild(spec Spec) []byte {
	b, err := Build(spec)
	if err != nil {
		panic(err)
	}
	return b
}
