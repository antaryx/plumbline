package cli

// Exit codes. These are a contract (docs/VERSIONING.md §5): CI pipelines
// branch on them, so a code that changes meaning breaks builds silently.
const (
	ExitOK          = 0   // completed; every gate satisfied
	ExitUsage       = 1   // usage or configuration error — nothing was scanned
	ExitFindings    = 2   // completed; findings at or above --fail-on
	ExitThreshold   = 3   // completed; posture below --threshold
	ExitDegraded    = 4   // completed degraded — a collector failed, or coverage below --min-coverage
	ExitPrivileges  = 10  // insufficient privileges, with --strict-privileges
	ExitTimeout     = 11  // the scan budget expired
	ExitInternal    = 70  // a panic escaped, or a bundle is corrupt
	ExitInterrupted = 130 // SIGINT
)

// Outcome is everything that can influence the exit code. It is a struct of
// independent facts rather than a code, because several of them are true at
// once in the runs that matter most: a scan can be degraded *and* failing, and
// which one CI hears about must not depend on the order the code checked them.
type Outcome struct {
	// Interrupted: the operator stopped the run.
	Interrupted bool
	// Internal: a panic escaped, or a bundle could not be parsed. The tool is
	// broken, and nothing it said about the host can be trusted.
	Internal bool
	// TimedOut: the whole-scan budget expired.
	TimedOut bool
	// Usage: bad flags or bad configuration. Nothing was scanned.
	Usage bool
	// Privileges: the run lacked privileges it needed and --strict-privileges
	// was set.
	Privileges bool
	// Degraded: a collector failed, or coverage fell below --min-coverage.
	// The scanner could not see the host properly.
	Degraded bool
	// Failing: findings at or above --fail-on. The host is misconfigured.
	Failing bool
	// BelowThreshold: posture below --threshold.
	BelowThreshold bool
}

// ExitCode resolves an outcome to a single code.
//
// The ladder is fixed and documented as a contract (ARCHITECTURE.md §9):
//
//	130 > 70 > 11 > 1 > 10 > 4 > 2 > 3 > 0
//
// It exists as one function, with one ordering, for a reason the audit found
// the hard way: the design this replaces had three codes matching a single
// common outcome with no tiebreak, so which one CI saw depended on the order
// the implementation happened to test them in (audit A-20). Two runs of the
// same tool over the same host could exit differently.
//
// The ordering itself says something. Everything above 4 means the tool did
// not do its job. 4 outranks 2 because "the scanner could not see your host"
// has to be louder than "your host is misconfigured": a pipeline that is told
// about failures it can fix, while quietly not being told about the half of
// the host nobody could read, is a pipeline that believes it is green.
func ExitCode(o Outcome) int {
	switch {
	case o.Interrupted:
		return ExitInterrupted
	case o.Internal:
		return ExitInternal
	case o.TimedOut:
		return ExitTimeout
	case o.Usage:
		return ExitUsage
	case o.Privileges:
		return ExitPrivileges
	case o.Degraded:
		return ExitDegraded
	case o.Failing:
		return ExitFindings
	case o.BelowThreshold:
		return ExitThreshold
	default:
		return ExitOK
	}
}
