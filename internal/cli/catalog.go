package cli

import (
	"github.com/antaryx/plumbline/internal/catalog"
	sshdchecks "github.com/antaryx/plumbline/internal/catalog/checks/sshd"

	// Collectors register themselves at init. Importing them here, in the
	// composition root, is what puts them in the default registry; nothing
	// deeper in the tree reaches for a collector by name.
	_ "github.com/antaryx/plumbline/internal/collect/collectors/sshd"
)

// buildCatalog assembles the catalog this binary carries.
//
// The list is explicit rather than discovered. A check that is in the tree but
// not in this list does not run, which is easy to see here and impossible to
// see if the catalog assembled itself by init side effect: "why did SSHD-0002
// not run" should be answerable by reading one function.
func buildCatalog() *catalog.Catalog {
	return catalog.MustNew(
		sshdchecks.Check0002,
	)
}
