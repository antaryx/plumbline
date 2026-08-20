package cli

import (
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/system"
)

// Output formats. The names are a contract (CLI-SPEC.md §Output): a pipeline
// pins one on a command line and a rename breaks it silently.
const (
	// FormatTerminal is the human-readable report and the default.
	FormatTerminal = "terminal"
	// FormatJSON is findings/v1, which is the actual public API (ADR-0007).
	FormatJSON = "json"
	// FormatSARIF is SARIF 2.1.0 for CI platforms that ingest it. The mapping
	// is specified in ADR-0018; it is a lossy projection of findings/v1 by
	// design — passing checks are counts, not results — and is not the API.
	FormatSARIF = "sarif"
)

// outputFlags are the flags that decide what a command writes and where.
//
// They are one struct shared by eval and scan for the reason renderAndGate is
// one function: two commands that render the same document must not be able to
// drift into rendering it differently.
type outputFlags struct {
	format  string
	output  string
	asJSON  bool
	noColor bool
}

func (o *outputFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.format, "format", FormatTerminal, "output format: terminal, json, sarif")
	f.StringVarP(&o.output, "output", "o", "", "write the document here instead of stdout")
	f.BoolVar(&o.asJSON, "json", false, "shorthand for --format json")
	f.BoolVar(&o.noColor, "no-color", false, "never emit ANSI colour; also honours NO_COLOR and a non-terminal stdout")
}

// resolveFormat applies --json on top of --format and rejects the combination
// that cannot be honoured.
//
// --json is shorthand, not an override. Silently discarding an explicitly set
// --format would be the same class of bug as silently accepting `--fail-on
// hgih`: the operator stated something, the tool did something else, and
// nothing said so. Shorthand over the *default* is unambiguous and is what the
// flag is for; shorthand over an explicit contradiction is a usage error.
func (o *outputFlags) resolveFormat(cmd *cobra.Command) (string, error) {
	format := strings.ToLower(strings.TrimSpace(o.format))

	if o.asJSON {
		if cmd.Flags().Changed("format") && format != FormatJSON {
			return "", usageErrorf("--json and --format %s contradict each other; pass one of them", format)
		}
		format = FormatJSON
	}

	switch format {
	case FormatTerminal, FormatJSON, FormatSARIF:
		return format, nil
	default:
		return "", usageErrorf("unknown --format %q; want one of terminal, json, sarif", format)
	}
}

// useColor resolves the three colour rules, in the order of how explicit they
// are.
//
// A flag beats an environment variable, which beats an inference about the
// descriptor. The inference is last because it is the only one that can be
// wrong: an operator running inside a CI harness that allocates a pty is not
// asking for colour, and one piping through `less -R` is — neither is knowable
// from the descriptor alone, which is exactly why the two explicit rules exist
// above it.
//
// Writing to --output is never coloured. An escape sequence in a file the
// operator asked to keep is not a rendering choice, it is corruption of an
// artefact they will read six months from now in something that is not a
// terminal.
func useColor(w io.Writer, noColorFlag bool, toFile bool) bool {
	switch {
	case noColorFlag:
		return false
	case toFile:
		return false
	// NO_COLOR is honoured on presence, not on value: the convention at
	// no-color.org is that the variable existing at all is the request, and
	// treating NO_COLOR=0 as "colour please" is how a tool ends up ignoring
	// the one setting a user went out of their way to set.
	case os.Getenv("NO_COLOR") != "":
		return false
	default:
		return system.IsTerminal(w)
	}
}
