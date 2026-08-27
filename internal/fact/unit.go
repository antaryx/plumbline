package fact

// This file holds the vocabulary for reading a systemd unit off the disk: what
// became of each file that contributes to one, and what the assembled result
// may be read as. It is shared rather than per-module because systemd's rules
// for finding and layering unit files are systemd's, and a second reading of
// them would be a second set of verdicts.
//
// **UnitState is not UnitStatus, and the two are one letter apart on purpose
// only in the sense that neither name is available for the other.** UnitStatus
// in services.go is a unit's *enablement*: enabled, masked, not-enabled,
// absent — a question about symlinks, answered without opening a unit file.
// UnitState here is whether a unit file could be *read at all*. A unit can be
// StatusEnabled and UnitDenied at once: systemd will start it and this scan
// could not see what it says.

// UnitState is what a collector was able to observe about a unit file or one
// of its drop-ins.
//
// It is a separate enumeration from DockerConfigState and not a reuse of it,
// even though four of the values have the same names. The states a JSON
// document can be in are not the states a systemd unit can be in — a unit can
// be *masked*, which has no analogue in a configuration file and is the one
// state here that means "this file exists and systemd deliberately ignores
// it".
//
// The wire values are the ones this type shipped with when it was
// UnitState, and they do not change. A bundle recorded before the rename
// decodes into this type unaltered, which is the promise DATA-MODEL.md §6.1
// makes about old bundles staying re-evaluable.
type UnitState string

const (
	// UnitPresent means the file was found and read. A fact's typed fields are
	// meaningful only for fragments in this state.
	UnitPresent UnitState = "present"
	// UnitAbsent means no such unit exists in any unit search directory.
	//
	// Unlike a missing configuration file this really is an absence rather
	// than a configuration. A unit file that does not exist starts nothing,
	// and there are no compiled-in defaults for systemd to fall back on. It
	// does not follow that the software is not running — a daemon started by
	// hand, by another init system, or by a unit under a different name is
	// invisible — which is why a check reading this may not say the daemon is
	// not running. It may only say this host has no such unit.
	UnitAbsent UnitState = "absent"
	// UnitMasked means the unit is a symbolic link to /dev/null.
	//
	// That is what `systemctl mask` writes, and systemd refuses to start a
	// masked unit at all, by hand or as a dependency. Whatever the vendor unit
	// underneath says is not in force, so its directives are not evidence of
	// anything about this host.
	UnitMasked UnitState = "masked"
	// UnitDenied means the file exists and could not be read.
	UnitDenied UnitState = "denied"
	// UnitNotRegular means something is at the path and it is neither a
	// regular file nor a symlink to one.
	UnitNotRegular UnitState = "not_regular"
	// UnitTruncated means the read hit the cap, so directives past the cut are
	// unread and no absence may be concluded.
	UnitTruncated UnitState = "truncated"
	// UnitError means the read failed for a reason worth recording verbatim.
	UnitError UnitState = "error"
)

// UnitFragmentKind distinguishes the parts a systemd unit is assembled from.
type UnitFragmentKind string

const (
	// FragmentUnit is the unit file itself.
	FragmentUnit UnitFragmentKind = "unit"
	// FragmentDropIn is one .conf under a <unit>.d directory.
	FragmentDropIn UnitFragmentKind = "drop_in"
	// FragmentDropInDir is a <unit>.d directory whose listing failed. It is
	// recorded because a directory that could not be listed may hold a drop-in
	// that changes the answer, and nothing may conclude absence from a listing
	// that did not happen.
	FragmentDropInDir UnitFragmentKind = "drop_in_dir"
)

// UnitFragment is one file that did, or would have, contributed to an
// effective unit.
//
// The list exists so that a check can say *why* it does not know. "The unit
// sets no such directive" and "the unit sets no such directive that I could
// see" are different claims, and an override.conf that could not be read is
// exactly the file most likely to contain the setting — adding one is the
// documented way to change a vendor unit without editing it.
type UnitFragment struct {
	Path  string           `json:"path"`
	Kind  UnitFragmentKind `json:"kind"`
	State UnitState        `json:"state"`
	// Resolved is where a symlinked fragment actually pointed. Empty when the
	// path was not a link.
	Resolved string `json:"resolved,omitempty"`
	// Digest is the sha256 of the bytes read, so a finding can cite the exact
	// text it drew a conclusion from. Unit fragments are read through the
	// seam's opaque path, so the bytes themselves are not in the bundle and
	// the digest is what an auditor reproduces on the host.
	Digest string `json:"digest,omitempty"`
	Msg    string `json:"msg,omitempty"`
	// Shadowed marks a drop-in systemd would not apply, because a
	// higher-precedence directory holds a .conf of the same name. It is
	// recorded rather than dropped: a shadowed override is a file an operator
	// edited and a daemon never read, which is a mistake worth being able to
	// see.
	Shadowed bool `json:"shadowed,omitempty"`
	// ShadowedBy is the path that won.
	ShadowedBy string `json:"shadowed_by,omitempty"`
}

// IncompleteFragments returns the fragments that were not read, excluding
// shadowed ones — systemd would not have applied those, so failing to read one
// changes nothing.
//
// It is a free function rather than a method because every fact that assembles
// a unit holds its own fragment list and they all need the same answer.
func IncompleteFragments(frags []UnitFragment) []UnitFragment {
	var out []UnitFragment
	for _, f := range frags {
		if f.Shadowed || f.State == UnitPresent {
			continue
		}
		out = append(out, f)
	}
	return out
}
