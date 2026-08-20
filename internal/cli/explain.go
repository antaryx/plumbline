package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/catalog"
	rendertext "github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/version"
)

// newExplainCmd builds `plumbline explain CHECK-ID`.
//
// It reads the catalog and nothing else: no host, no bundle, no privileges,
// no network. A question about what a check asks is a question about this
// binary, and answering it must not require pointing the tool at a machine.
func newExplainCmd(g *globals, stdout, stderr io.Writer) *cobra.Command {
	var out outputFlags

	cmd := &cobra.Command{
		Use:   "explain CHECK-ID",
		Short: "Print what a check asks, and how to fix it",
		Long: `explain prints one catalog entry in full: what the check tests, which facts
it reads, the remediation with every step and command, and the control
mappings.

This is where the remediation procedure lives. A scan report prints only a
summary, because a block running to forty lines per finding is one an operator
scrolls past — the full procedure is here, asked for by ID.

It touches no host and needs no bundle or privileges. The check ID is
case-insensitive.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat := buildCatalog()

			id := normaliseCheckID(args[0])
			check, ok := cat.Get(id)
			if !ok {
				return exitError{code: ExitUsage, message: unknownCheckMessage(cat, id)}
			}

			w, closeOut, err := writeTo(out.output, stdout)
			if err != nil {
				return exitError{code: ExitInternal, message: err.Error()}
			}
			renderErr := rendertext.RenderExplain(w, explainInputFor(check,
				useColor(w, out.noColor, out.output != "")))
			if cerr := closeOut(); renderErr == nil {
				renderErr = cerr
			}
			if renderErr != nil {
				return exitError{code: ExitInternal, message: renderErr.Error()}
			}
			return nil
		},
	}

	// --format is not registered: there is one rendering of a catalog entry
	// and it is for a person. A machine-readable catalog is its own work
	// package with its own schema, and inventing one here as a side effect
	// would freeze a shape nobody designed.
	cmd.Flags().StringVarP(&out.output, "output", "o", "", "write the entry here instead of stdout")
	cmd.Flags().BoolVar(&out.noColor, "no-color", false, "never emit ANSI colour; also honours NO_COLOR and a non-terminal stdout")
	return cmd
}

// normaliseCheckID accepts what an operator actually types.
//
// Check IDs are upper-case by convention and lower-case to type. Rejecting
// `filesys-0010` when `FILESYS-0010` exists would be the tool being right and
// useless at the same time. Surrounding space is trimmed for the same reason:
// an ID pasted out of a report often brings some with it.
func normaliseCheckID(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// unknownCheckMessage refuses, and then helps.
//
// A bare "not found" is correct and unkind: the operator has a real check in
// mind and has mistyped it or misremembered the number. Naming the near misses
// turns a dead end into the answer, and listing the module's range turns a
// wrong number into a right one.
func unknownCheckMessage(cat *catalog.Catalog, id string) string {
	msg := fmt.Sprintf("check %q not found in catalog %d", id, version.Catalog())

	if near := nearMisses(cat, id); len(near) > 0 {
		msg += "\n  did you mean: " + strings.Join(near, ", ")
	} else {
		modules := modulesIn(cat)
		msg += "\n  modules in this catalog: " + strings.Join(modules, ", ")
	}
	msg += fmt.Sprintf("\n  %d checks are available; `plumbline version` reports the catalog", cat.Len())
	return msg
}

// nearMisses returns IDs in the same module, which is the mistake operators
// actually make — the module is remembered and the number is not.
func nearMisses(cat *catalog.Catalog, id string) []string {
	module, _, found := strings.Cut(id, "-")
	if !found || module == "" {
		return nil
	}
	var out []string
	for _, candidate := range cat.IDs() {
		if strings.HasPrefix(candidate, module+"-") {
			out = append(out, candidate)
		}
	}
	sort.Strings(out)
	// Enough to orient, not so many that the error becomes a listing.
	const show = 6
	if len(out) > show {
		out = append(out[:show:show], fmt.Sprintf("… and %d more", len(out)-show))
	}
	return out
}

func modulesIn(cat *catalog.Catalog) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range cat.IDs() {
		if module, _, found := strings.Cut(id, "-"); found && !seen[module] {
			seen[module] = true
			out = append(out, module)
		}
	}
	sort.Strings(out)
	return out
}

// explainInputFor flattens a catalog entry into the renderer's shape. The
// renderer cannot import the catalog — internal/catalog imports
// internal/finding, and a renderer reaching back into the catalog would make
// that dependency run both ways — so the flattening happens here.
func explainInputFor(c catalog.Check, color bool) rendertext.ExplainInput {
	in := rendertext.ExplainInput{
		ID:           c.ID,
		Module:       c.Module,
		Title:        c.Title,
		Description:  c.Description,
		BaseSeverity: c.BaseSeverity,
		Tags:         c.Tags,
		Remediation:  c.Remediation,
		Mappings:     c.Mappings,
		References:   c.References,
		SinceCatalog: c.SinceCatalog,
		Color:        color,
	}
	for _, f := range c.Requires {
		in.Requires = append(in.Requires, string(f))
	}
	if c.Deprecated != nil {
		in.Deprecated = c.Deprecated.Reason
		in.DeprecatedSince = c.Deprecated.SinceCatalog
		in.DeprecatedReplace = c.Deprecated.ReplacedBy
	}
	return in
}
