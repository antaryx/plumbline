package remediate

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/finding"
)

// TestEveryGeneratedScriptParses.
//
// **A fix that writes shell by hand can write shell that does not parse**, and
// the operator finds out at the top of a root prompt. `set -eu` makes the cost
// of that disproportionate: an unbalanced `if` in one action is a syntax error
// in the whole file, so nothing runs at all — not the action that was wrong,
// and not any of the ones that were right.
//
// The shell's own parser is the only reader whose opinion counts here, so this
// asks it rather than pattern-matching the text. `sh -n` parses and does not
// execute, which is what makes it safe to run over a script full of systemctl
// and chown on a developer's machine.
//
// It is an internal test because it ranges over the registry: a fix added in a
// new file is covered the day it is registered, without this file being one of
// the places somebody has to remember to edit.
func TestEveryGeneratedScriptParses(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on this machine: %v", err)
	}

	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Fatal("no fixes are registered, so this gate is asserting nothing")
	}

	all := make([]finding.Finding, 0, len(ids))
	for _, id := range ids {
		f := finding.Finding{
			CheckID:  id,
			Module:   strings.SplitN(id, "-", 2)[0],
			Title:    "the check called " + id,
			Result:   finding.Fail,
			Severity: finding.High,
		}
		all = append(all, f)
		parses(t, sh, id, Script(Generate([]finding.Finding{f}, Options{})))
	}

	// And every fix at once. A construct can parse alone and still break the
	// script it is concatenated into — an unterminated quote is invisible
	// until there is a line after it.
	parses(t, sh, "every fix in one plan", Script(Generate(all, Options{})))
}

func parses(t *testing.T, sh, name, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plumbline-fix.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", path).CombinedOutput(); err != nil {
		t.Errorf("%s produces shell that does not parse (%v): %s\n%s", name, err, out, script)
	}
}
