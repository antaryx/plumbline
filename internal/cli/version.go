package cli

import (
	stdjson "encoding/json"
	"fmt"
	"io"

	"github.com/antaryx/plumbline/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCmd(stdout io.Writer) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print tool, catalog and schema versions",
		Long: `All three matter. The tool version says what code ran, the catalog version
says which checks existed, and the schema version says how to read the output.
A findings document is only interpretable with all three.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if asJSON {
				enc := stdjson.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Tool    string `json:"tool"`
					Version string `json:"version"`
					Commit  string `json:"commit"`
					Date    string `json:"date"`
					Catalog int    `json:"catalog_version"`
					Schema  string `json:"schema"`
				}{
					Tool: "plumbline", Version: version.Version, Commit: version.Commit,
					Date: version.Date, Catalog: version.Catalog(), Schema: version.Schema,
				})
			}
			fmt.Fprintf(stdout, "plumbline %s\n", version.Version)
			fmt.Fprintf(stdout, "commit:  %s\n", version.Commit)
			fmt.Fprintf(stdout, "built:   %s\n", version.Date)
			fmt.Fprintf(stdout, "catalog: %d\n", version.Catalog())
			fmt.Fprintf(stdout, "schema:  %s\n", version.Schema)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}
