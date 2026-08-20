// Package cli is the command surface: cobra commands, flag precedence and the
// exit-code ladder. It is the composition root — the only place that knows
// which collectors, checks and renderers exist — and it is a package rather
// than main so that every command is testable without a subprocess.
//
// Flag names and exit codes are a contract (CLI-SPEC.md, VERSIONING.md §5).
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/live"
)

// Execute runs a command line and returns the process exit code.
//
// Nothing here calls os.Exit: the code is returned so that a test can assert
// on it, which is the only way to test an exit-code ladder that matters as much
// as this one does.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := newRoot(stdout, stderr)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.Execute()
	if err == nil {
		return ExitOK
	}

	// A command that resolved its own outcome carries the code with it.
	var coded exitError
	if errors.As(err, &coded) {
		if coded.message != "" {
			fmt.Fprintln(stderr, "plumbline:", coded.message)
		}
		return coded.code
	}

	fmt.Fprintln(stderr, "plumbline:", err)
	var usage errUsage
	if errors.As(err, &usage) {
		return ExitUsage
	}
	// cobra reports unknown flags and bad arguments as plain errors, and those
	// are usage errors: nothing was scanned.
	return ExitUsage
}

// exitError carries a resolved exit code out of a command.
type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("exit %d", e.code)
}

// globals are the flags every command shares.
type globals struct {
	configPath string
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	g := &globals{}

	root := &cobra.Command{
		Use:   "plumbline",
		Short: "Deterministic host security auditor for Linux",
		Long: `Plumbline audits a Linux host and says what it found, what it could not
determine, and why. It never changes anything: there is no --fix flag.

collect and eval are separable on purpose. Collection is the privileged step
and evaluation is not, and a bundle collected today can be re-evaluated
against a later catalog.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare `plumbline` is a usage error rather than a no-op scan of the
		// machine: running a privileged audit must be something the operator
		// asked for by name.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErrorf("no command given; try `plumbline version` or `plumbline scan --help`")
		},
	}

	root.PersistentFlags().StringVar(&g.configPath, "config", "", "explicit configuration file")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		return g.resolveConfig(stderr)
	}

	root.AddCommand(
		newVersionCmd(stdout),
		newCollectCmd(g, stdout, stderr),
		newEvalCmd(g, stdout, stderr),
		newDiffCmd(g, stdout, stderr),
		newScanCmd(g, stdout, stderr),
	)
	return root
}

// resolveConfig applies the config search order and the privilege rule. There
// are no configuration keys yet — CONFIG-REFERENCE.md defines them and does not
// exist — so this resolves and reports the file in effect without parsing it.
// The security rule is in the resolution, which is the part that has to be
// right before there is anything to parse.
func (g *globals) resolveConfig(stderr io.Writer) error {
	cwd, _ := os.Getwd()
	search := ConfigSearch{
		Explicit: g.configPath,
		Env:      os.Getenv("PLUMBLINE_CONFIG"),
		Cwd:      cwd,
		Home:     os.Getenv("HOME"),
		// Through the seam: the euid a scan believes it runs as is a
		// property of the System, and the fake supplies its own.
		Euid: live.New("").Euid(),
	}

	if ignored := IgnoredForPrivilege(search); ignored != "" && system.LocalExists(ignored) {
		fmt.Fprintf(stderr, "plumbline: ignoring %s because this run is privileged; pass --config to use it deliberately\n", ignored)
	}

	// An explicit --config that does not exist is a usage error. Falling back
	// silently would run with settings the operator did not choose while
	// telling them nothing.
	if g.configPath != "" && !system.LocalExists(g.configPath) {
		return usageErrorf("--config %s: no such file", g.configPath)
	}
	return nil
}
