// This file is package cli rather than cli_test, which the rest of this
// package's tests are.
//
// useColor and resolveFormat are unexported and are deliberately not going to
// be exported: they are flag-resolution details, not surface. Testing them
// through Execute would need a real pseudo-terminal, which needs a dependency
// this project will not take on for a test. An internal test file is the
// cheaper honesty.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// devNull is a character device, which is the only writer available in a test
// that system.IsTerminal answers "yes" to without allocating a pty. It stands
// in for a terminal here; nothing is asserted about its contents.
func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestUseColorPrefersTheMostExplicitRule. A flag beats an environment
// variable, which beats an inference about the file descriptor, because the
// inference is the only one of the three that can be wrong about what the
// operator wanted.
func TestUseColorPrefersTheMostExplicitRule(t *testing.T) {
	tty := devNull(t)

	t.Run("a terminal gets colour", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		if !useColor(tty, false, false) {
			t.Error("a character device did not get colour")
		}
	})

	t.Run("--no-color wins over a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		if useColor(tty, true, false) {
			t.Error("--no-color was ignored")
		}
	})

	t.Run("NO_COLOR wins over a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		if useColor(tty, false, false) {
			t.Error("NO_COLOR was ignored")
		}
	})

	// The no-color.org convention is that the variable existing at all is the
	// request. Treating NO_COLOR=0 as "colour please" is how a tool ends up
	// ignoring the one setting a user went out of their way to set.
	t.Run("NO_COLOR=0 still means no colour", func(t *testing.T) {
		t.Setenv("NO_COLOR", "0")
		if useColor(tty, false, false) {
			t.Error("NO_COLOR=0 was read as a request for colour")
		}
	})

	t.Run("--output is never coloured", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		if useColor(tty, false, true) {
			t.Error("a file the operator asked to keep was written with escape sequences")
		}
	})

	t.Run("a buffer is not a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		if useColor(&bytes.Buffer{}, false, false) {
			t.Error("a non-file writer was treated as a terminal")
		}
	})

	t.Run("a regular file is not a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		path := filepath.Join(t.TempDir(), "out")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if useColor(f, false, false) {
			t.Error("a regular file was treated as a terminal")
		}
	})
}

func TestResolveFormat(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"the default", nil, FormatTerminal, false},
		{"--json", []string{"--json"}, FormatJSON, false},
		{"--format json", []string{"--format", "json"}, FormatJSON, false},
		{"--format terminal", []string{"--format", "terminal"}, FormatTerminal, false},
		{"both, agreeing", []string{"--format", "json", "--json"}, FormatJSON, false},
		{"mixed case", []string{"--format", "JSON"}, FormatJSON, false},
		{"surrounding space", []string{"--format", " json "}, FormatJSON, false},
		{"--format sarif", []string{"--format", "sarif"}, FormatSARIF, false},
		{"sarif, mixed case", []string{"--format", "SARIF"}, FormatSARIF, false},

		{"both, contradicting", []string{"--format", "terminal", "--json"}, "", true},
		{"--json contradicts sarif", []string{"--format", "sarif", "--json"}, "", true},
		{"nonsense", []string{"--format", "yaml"}, "", true},
		{"empty", []string{"--format", ""}, "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out outputFlags
			cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
			out.register(cmd)
			cmd.SetArgs(tc.args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("parsing %v: %v", tc.args, err)
			}

			got, err := out.resolveFormat(cmd)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveFormat(%v) = %q, want an error", tc.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveFormat(%v): %v", tc.args, err)
			}
			if got != tc.want {
				t.Errorf("resolveFormat(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}
