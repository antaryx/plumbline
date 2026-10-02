package memory_test

import (
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/antaryx/plumbline/internal/system/fake"
	"github.com/antaryx/plumbline/internal/system/fake/elfgen"
)

// The MEMORY fixtures are built here rather than committed under
// testdata/fixtures, for the reason stated in package elfgen: a committed
// /usr/bin/sudo is a copy of some distribution's build, travelling without the
// source or the licence that would let it be redistributed, and answering for
// one architecture a question the collector asks of every architecture.
//
// What the fixture directories held was four ELF files per case and a manifest.
// What a case actually *is* is a sentence about one ELF property, and that is
// what a blueprint states. The descriptions that were in each fixture.json are
// kept here, because they are the specification the specs below implement.

const (
	sshd   = "/usr/sbin/sshd"
	su     = "/usr/bin/su"
	sudo   = "/usr/bin/sudo"
	passwd = "/usr/bin/passwd"
)

// probed is every binary the collector looks for in these cases.
var probed = []string{sshd, su, sudo, passwd}

// blueprint is one fixture: the ELF spec for each installed binary, any file
// whose content is not an ELF at all, and the manifest fields the case needs.
type blueprint struct {
	description string
	elves       map[string]elfgen.Spec
	raw         map[string]string
	manifest    fake.Manifest
}

// allHardened installs the fully hardened image at every probed path. Every
// negative case starts from this and changes exactly one thing.
func allHardened() map[string]elfgen.Spec {
	m := make(map[string]elfgen.Spec, len(probed))
	for _, p := range probed {
		m[p] = elfgen.Hardened()
	}
	return m
}

// with returns allHardened with path replaced by spec, so a case reads as the
// single difference it is about.
func with(path string, spec elfgen.Spec) map[string]elfgen.Spec {
	m := allHardened()
	m[path] = spec
	return m
}

// unprivileged is the manifest of a scan running as a normal user that cannot
// read the named paths — the shape of an unprivileged run, without needing real
// permissions in git.
func unprivileged(unreadable ...string) fake.Manifest {
	n := 1000
	return fake.Manifest{Euid: &n, Unreadable: unreadable}
}

// lazyBinding has a PT_GNU_RELRO segment and no BIND_NOW of any encoding. The
// empty non-nil Dynamic is load-bearing: it is a dynamically linked binary with
// no flags, which is a different file from a static one.
func lazyBinding() elfgen.Spec {
	s := elfgen.Hardened()
	s.Dynamic = []elfgen.Dyn{}
	return s
}

// noCanary references the fortified _chk entry points and no __stack_chk_fail:
// FORTIFY_SOURCE was in effect and the stack protector was not.
func noCanary() elfgen.Spec {
	s := elfgen.Hardened()
	s.Dynsyms = []string{"__printf_chk", "__memcpy_chk", "printf", "memcpy"}
	return s
}

// noFortify references four functions _FORTIFY_SOURCE would have substituted
// and carries no _chk variant of any of them. The canary stays.
func noFortify() elfgen.Spec {
	s := elfgen.Hardened()
	s.Dynsyms = []string{elfgen.Canary, "printf", "memcpy", "sprintf", "strcpy"}
	return s
}

// noPIE is ET_EXEC with an executable stack and no PT_GNU_RELRO segment.
func noPIE() elfgen.Spec {
	s := elfgen.Hardened()
	s.Type = elf.ET_EXEC
	s.Progs = []elf.ProgHeader{elfgen.GNUStack(elf.PF_R | elf.PF_W | elf.PF_X)}
	return s
}

// nothingToFortify references only functions FORTIFY_SOURCE cannot substitute,
// so the question does not arise rather than being answered badly.
func nothingToFortify() elfgen.Spec {
	s := elfgen.Hardened()
	s.Dynsyms = []string{elfgen.Canary, "malloc", "free", "exit"}
	return s
}

// static has no dynamic section and keeps its symbols in .symtab rather than
// .dynsym, which is what proves both tables are read.
func static() elfgen.Spec {
	s := elfgen.Hardened()
	s.Dynamic = nil
	s.Dynsyms = nil
	s.Symtabs = []string{elfgen.Canary, "__printf_chk", "__memcpy_chk", "printf", "memcpy"}
	return s
}

// stripped has no .dynsym and no .symtab: nothing to read a symbol name from.
func stripped() elfgen.Spec {
	s := elfgen.Hardened()
	s.Dynsyms = nil
	s.Symtabs = nil
	return s
}

// noStackHeader is ET_DYN with no PT_GNU_STACK header at all: PIE is
// determined, NX is not.
func noStackHeader() elfgen.Spec {
	s := elfgen.Hardened()
	s.Progs = []elf.ProgHeader{elfgen.GNURelro()}
	return s
}

var blueprints = map[string]blueprint{
	"memory-absent": {
		description: "None of the probed binaries is installed, so every MEMORY check is NOT_APPLICABLE rather than PASS.",
	},
	"memory-hardened": {
		description: "Every installed binary is ET_DYN with a non-executable PT_GNU_STACK, a PT_GNU_RELRO segment, DF_1_NOW, a __stack_chk_fail reference and fortified _chk entry points.",
		elves:       allHardened(),
	},
	"memory-denied": {
		description: "Every probed binary exists and none can be read. The binaries are fully hardened deliberately: a PASS here would be a verdict drawn from a file never opened.",
		elves:       allHardened(),
		manifest:    unprivileged(sudo, su, passwd, sshd),
	},
	"memory-lazy-binding": {
		description: "/usr/bin/sudo has a PT_GNU_RELRO segment and no BIND_NOW of any encoding: partial RELRO, not full.",
		elves:       with(sudo, lazyBinding()),
	},
	"memory-nocanary": {
		description: "/usr/bin/sudo references the fortified _chk entry points and no __stack_chk_fail.",
		elves:       with(sudo, noCanary()),
	},
	"memory-nofortify": {
		description: "/usr/bin/sudo references printf, memcpy, sprintf and strcpy unfortified and carries no _chk variant.",
		elves:       with(sudo, noFortify()),
	},
	"memory-nopie": {
		description: "/usr/bin/sudo is ET_EXEC with an executable stack and no PT_GNU_RELRO segment. The other three are fully hardened.",
		elves:       with(sudo, noPIE()),
	},
	"memory-nopie-denied": {
		description: "One binary is readable and unhardened; another cannot be read at all. The offender found is still an offender, so the verdict is FAIL rather than UNKNOWN.",
		elves:       with(sudo, noPIE()),
		manifest:    unprivileged(sshd),
	},
	"memory-nothing-to-fortify": {
		description: "Every binary references malloc, free and exit and nothing _FORTIFY_SOURCE could substitute, so MEMORY-0004 is NOT_APPLICABLE rather than FAIL.",
		elves: map[string]elfgen.Spec{
			sshd: nothingToFortify(), su: nothingToFortify(),
			sudo: nothingToFortify(), passwd: nothingToFortify(),
		},
	},
	"memory-static": {
		description: "Every binary is statically linked and unstripped: no dynamic section, symbols in .symtab rather than .dynsym.",
		elves: map[string]elfgen.Spec{
			sshd: static(), su: static(), sudo: static(), passwd: static(),
		},
	},
	"memory-stripped": {
		description: "Every binary is fully stripped. PIE and RELRO come from program headers and are still determined; the canary and FORTIFY questions resolve to UNKNOWN.",
		elves: map[string]elfgen.Spec{
			sshd: stripped(), su: stripped(), sudo: stripped(), passwd: stripped(),
		},
	},
	"memory-wrapper": {
		description: "/usr/bin/sudo is a shell wrapper rather than an ELF. /usr/bin/passwd is ET_DYN with no PT_GNU_STACK header at all: PIE is determined, NX is not.",
		elves: map[string]elfgen.Spec{
			sshd: elfgen.Hardened(), su: elfgen.Hardened(), passwd: noStackHeader(),
		},
		raw: map[string]string{sudo: "#!/bin/sh\nexec /usr/bin/sudo.real \"$@\"\n"},
	},
}

// materialize writes a blueprint into a temporary directory and returns its
// root, ready for fake.New. Nothing it writes outlives the test.
func materialize(t *testing.T, name string) string {
	t.Helper()

	bp, ok := blueprints[name]
	if !ok {
		t.Fatalf("no blueprint for fixture %q", name)
	}
	root := t.TempDir()

	write := func(p string, data []byte) {
		real := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
			t.Fatalf("%s: mkdir for %s: %v", name, p, err)
		}
		if err := os.WriteFile(real, data, 0o755); err != nil {
			t.Fatalf("%s: write %s: %v", name, p, err)
		}
	}
	for p, spec := range bp.elves {
		img, err := elfgen.Build(spec)
		if err != nil {
			t.Fatalf("%s: build %s: %v", name, p, err)
		}
		write(p, img)
	}
	for p, body := range bp.raw {
		write(p, []byte(body))
	}

	m := bp.manifest
	m.Description = bp.description
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("%s: encode manifest: %v", name, err)
	}
	write(fake.ManifestPath, data)

	return root
}
