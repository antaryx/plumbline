package remediate_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/remediate"
)

// TestMergeIsIdempotent.
//
// **The property the whole engine rests on, asserted as a property.** A host is
// scanned and remediated over and over, and a fix that appended a line each
// time would grow /etc/sysctl.d/99-plumbline-hardening.conf until something
// else — a parser, a review, a disk — broke on it. So: merging twice must give
// what merging once gave, for every starting file.
//
// The cases are the shapes a real drop-in arrives in, and each one exists
// because a plausible implementation gets exactly that one wrong.
func TestMergeIsIdempotent(t *testing.T) {
	pairs := map[string]string{
		"kernel.dmesg_restrict":   "1",
		"net.ipv4.tcp_syncookies": "1",
	}

	for _, c := range []struct {
		name     string
		existing string
		want     string
	}{
		{
			name:     "an empty file",
			existing: "",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
		{
			// The naive implementation appends unconditionally and doubles
			// this file on every run.
			name:     "the key is already set to the wanted value",
			existing: "kernel.dmesg_restrict = 1\n",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
		{
			name:     "the key is set to something else",
			existing: "kernel.dmesg_restrict = 0\n",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
		{
			// sysctl.conf(5) allows both spellings and any spacing, so a
			// merge that matched on the literal "key = " would miss these and
			// append a duplicate.
			name:     "odd spacing and no spaces at all",
			existing: "kernel.dmesg_restrict=0\n   net.ipv4.tcp_syncookies   =   0   \n",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
		{
			// sysctl.d(5): a leading - means "do not fail if absent". It is
			// still a line that sets the key.
			name:     "the ignore-errors marker",
			existing: "-kernel.dmesg_restrict = 0\n",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
		{
			name:     "a duplicate already in the file is collapsed",
			existing: "kernel.dmesg_restrict = 0\nkernel.dmesg_restrict = 0\n",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
		{
			// Everything that is not one of our keys survives untouched, in
			// the order it was in. An operator's file is not ours to tidy.
			name: "comments and other keys are preserved in place",
			existing: "# written by hand, 2026-01-04\n" +
				"vm.swappiness = 10\n" +
				"\n" +
				"kernel.dmesg_restrict = 0\n" +
				"; a trailing note\n",
			want: "# written by hand, 2026-01-04\n" +
				"vm.swappiness = 10\n" +
				"\n" +
				"kernel.dmesg_restrict = 1\n" +
				"; a trailing note\n" +
				"net.ipv4.tcp_syncookies = 1\n",
		},
		{
			// **The reason this is a replacement and not a delete-and-append.**
			// sysctl applies last-wins within a file, so moving our key to the
			// end would silently promote it over an override an operator had
			// deliberately placed after it.
			name: "a later override keeps its position over ours",
			existing: "kernel.dmesg_restrict = 0\n" +
				"net.ipv4.tcp_syncookies = 1\n" +
				"kernel.dmesg_restrict = 0\n",
			want: "kernel.dmesg_restrict = 1\n" +
				"net.ipv4.tcp_syncookies = 1\n",
		},
		{
			name:     "no trailing newline",
			existing: "kernel.dmesg_restrict = 0",
			want:     "kernel.dmesg_restrict = 1\nnet.ipv4.tcp_syncookies = 1\n",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			once := remediate.Merge(c.existing, pairs)
			if once != c.want {
				t.Errorf("merge:\n got %q\nwant %q", once, c.want)
			}

			// The property itself, and the one that matters: a second run is a
			// no-op. A third is asserted too, because an implementation can be
			// wrong in a way that only shows on the run after the first
			// correction.
			twice := remediate.Merge(once, pairs)
			if twice != once {
				t.Errorf("merging twice changed the file:\n once %q\ntwice %q", once, twice)
			}
			if thrice := remediate.Merge(twice, pairs); thrice != once {
				t.Errorf("merging three times changed the file:\n once %q\nthrice %q", once, thrice)
			}

			// And no key is ever set on more than one line, which is the
			// symptom the property exists to rule out.
			for key := range pairs {
				if n := countSettings(twice, key); n != 1 {
					t.Errorf("%s appears on %d lines, want 1:\n%s", key, n, twice)
				}
			}
		})
	}
}

// countSettings counts the lines that set a key, however they are spelled.
func countSettings(file, key string) int {
	n := 0
	for _, l := range strings.Split(file, "\n") {
		t := strings.TrimLeft(l, " \t")
		t = strings.TrimPrefix(t, "-")
		eq := strings.Index(t, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimRight(t[:eq], " \t") == key {
			n++
		}
	}
	return n
}

// TestTheGeneratedScriptIsIdempotentWhenRun.
//
// **Merge is the rule and the script is a second implementation of it, so the
// script is tested by running it.** plumbline itself will apply a plan with
// Merge — pure Go, through the system seam — but the block `--fix` prints is
// shell, meant to be read and often to be pasted onto a host plumbline is not
// installed on. Two implementations of one rule drift; a test that runs the
// shell and compares its output with Merge's is what stops that being
// discovered on somebody's /etc/sysctl.d.
//
// It runs the script twice, which is the claim: the second run changes nothing.
func TestTheGeneratedScriptIsIdempotentWhenRun(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on this machine: %v", err)
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skipf("no awk on this machine: %v", err)
	}

	dir := t.TempDir()
	dropIn := filepath.Join(dir, "99-plumbline-hardening.conf")

	// A file with something to preserve, something to correct, and a duplicate.
	const existing = "# set by configuration management\n" +
		"vm.swappiness = 10\n" +
		"kernel.dmesg_restrict = 0\n" +
		"fs.protected_hardlinks = 0\n" +
		"fs.protected_hardlinks = 0\n"
	if err := os.WriteFile(dropIn, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := remediate.Generate(failures("KERNEL-0004", "KERNEL-0016", "KERNEL-0026", "KERNEL-0030"),
		remediate.Options{DropIn: dropIn})

	// `sysctl` is not on the PATH this test builds, and running it would change
	// the machine the tests are on. Only the drop-in half is exercised here;
	// the commands are asserted as text in engine_test.go.
	script := onlyDropInLines(t, remediate.Script(plan))

	run := func(pass int) string {
		cmd := exec.Command(sh, "-c", script)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pass %d: %v\n%s\nscript:\n%s", pass, err, out, script)
		}
		b, err := os.ReadFile(dropIn)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	first := run(1)
	second := run(2)

	if first != second {
		t.Errorf("running the script twice changed the file.\nafter one:\n%s\nafter two:\n%s", first, second)
	}

	// The shell and the Go must agree, or plumbline applying a plan and an
	// operator running the printed script produce two different hosts.
	if want := remediate.Merge(existing, plan.Pairs()); first != want {
		t.Errorf("the script and Merge disagree.\n  shell:\n%s\n     Go:\n%s", first, want)
	}

	// And the things the merge promised: the operator's lines kept, ours
	// corrected, the duplicate collapsed.
	for _, want := range []string{
		"# set by configuration management",
		"vm.swappiness = 10",
		"kernel.dmesg_restrict = 1",
		"net.ipv4.tcp_syncookies = 1",
		"net.ipv6.conf.all.accept_ra = 0",
		"net.ipv6.conf.default.accept_ra = 0",
		"fs.protected_hardlinks = 1",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("the applied file is missing %q:\n%s", want, first)
		}
	}
	for _, key := range []string{"kernel.dmesg_restrict", "fs.protected_hardlinks", "vm.swappiness"} {
		if n := countSettings(first, key); n != 1 {
			t.Errorf("%s appears on %d lines after two runs, want 1:\n%s", key, n, first)
		}
	}
}

// onlyDropInLines strips the `sysctl` invocations from a generated script,
// leaving the shell helper and the calls to it.
//
// It is a test convenience and it is honest about what it drops: `sysctl -w`
// writes to the machine running the tests, and `sysctl --system` reloads it.
// Neither belongs in a unit test, and neither touches the drop-in file this
// test is about.
func onlyDropInLines(t *testing.T, script string) string {
	t.Helper()
	var keep []string
	for _, l := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "sysctl ") {
			continue
		}
		keep = append(keep, l)
	}
	out := strings.Join(keep, "\n")
	if !strings.Contains(out, "plumbline_sysctl_set") {
		t.Fatalf("the script has no drop-in step left to run:\n%s", script)
	}
	return out
}

// failures builds one FAILing finding per check ID.
func failures(ids ...string) []finding.Finding {
	out := make([]finding.Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, finding.Finding{
			CheckID:  id,
			Module:   strings.SplitN(id, "-", 2)[0],
			Title:    "the check called " + id,
			Result:   finding.Fail,
			Severity: finding.High,
		})
	}
	return out
}
