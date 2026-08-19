package cli

import (
	"github.com/antaryx/plumbline/internal/catalog"
	cronchecks "github.com/antaryx/plumbline/internal/catalog/checks/cron"
	kernelchecks "github.com/antaryx/plumbline/internal/catalog/checks/kernel"
	loggingchecks "github.com/antaryx/plumbline/internal/catalog/checks/logging"
	serviceschecks "github.com/antaryx/plumbline/internal/catalog/checks/services"
	sshdchecks "github.com/antaryx/plumbline/internal/catalog/checks/sshd"
	userschecks "github.com/antaryx/plumbline/internal/catalog/checks/users"

	// Collectors register themselves at init. Importing them here, in the
	// composition root, is what puts them in the default registry; nothing
	// deeper in the tree reaches for a collector by name.
	_ "github.com/antaryx/plumbline/internal/collect/collectors/cron"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/kernel"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/logging"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/services"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/sshd"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/users"
)

// buildCatalog assembles the catalog this binary carries.
//
// The list is explicit rather than discovered. A check that is in the tree but
// not in this list does not run, which is easy to see here and impossible to
// see if the catalog assembled itself by init side effect: "why did SSHD-0002
// not run" should be answerable by reading one function.
func buildCatalog() *catalog.Catalog {
	return catalog.MustNew(
		cronchecks.Check0001,
		cronchecks.Check0002,
		cronchecks.Check0003,
		cronchecks.Check0004,
		cronchecks.Check0005,
		kernelchecks.Check0001,
		kernelchecks.Check0002,
		kernelchecks.Check0003,
		kernelchecks.Check0004,
		kernelchecks.Check0005,
		kernelchecks.Check0006,
		kernelchecks.Check0007,
		kernelchecks.Check0008,
		kernelchecks.Check0009,
		kernelchecks.Check0010,
		kernelchecks.Check0011,
		kernelchecks.Check0012,
		kernelchecks.Check0013,
		kernelchecks.Check0014,
		kernelchecks.Check0015,
		kernelchecks.Check0016,
		loggingchecks.Check0001,
		loggingchecks.Check0002,
		loggingchecks.Check0003,
		loggingchecks.Check0004,
		loggingchecks.Check0005,
		serviceschecks.Check0001,
		serviceschecks.Check0002,
		serviceschecks.Check0003,
		serviceschecks.Check0004,
		serviceschecks.Check0005,
		sshdchecks.Check0002,
		sshdchecks.Check0003,
		sshdchecks.Check0004,
		sshdchecks.Check0005,
		sshdchecks.Check0006,
		sshdchecks.Check0007,
		sshdchecks.Check0008,
		sshdchecks.Check0009,
		sshdchecks.Check0010,
		sshdchecks.Check0011,
		sshdchecks.Check0012,
		sshdchecks.Check0013,
		sshdchecks.Check0014,
		sshdchecks.Check0015,
		sshdchecks.Check0016,
		sshdchecks.Check0017,
		sshdchecks.Check0018,
		sshdchecks.Check0019,
		sshdchecks.Check0020,
		userschecks.Check0001,
		userschecks.Check0002,
		userschecks.Check0003,
		userschecks.Check0004,
		userschecks.Check0005,
		userschecks.Check0006,
		userschecks.Check0007,
		userschecks.Check0008,
		userschecks.Check0009,
		userschecks.Check0010,
	)
}
