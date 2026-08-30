package fact

import "sort"

// AppArmorID names the AppArmor mandatory-access-control fact.
const AppArmorID ID = "services.apparmor"

// AppArmorState is what the collector could establish about AppArmor itself,
// before any question about profiles.
//
// **Absent and Disabled are kept apart and the difference decides a verdict.**
// A RHEL host has no AppArmor because it runs SELinux, and reporting that as a
// failure would tell an operator to install a second LSM alongside the one
// already confining their processes. A Debian host with AppArmor built in and
// switched off is a different thing entirely: the machinery is there, the
// profiles are probably installed, and nothing is being confined.
type AppArmorState string

const (
	// AppArmorEnabled: the LSM is present and switched on.
	AppArmorEnabled AppArmorState = "enabled"
	// AppArmorDisabled: the LSM is present and switched off — built into the
	// kernel but not active, which is what `apparmor=0` on the command line
	// produces.
	AppArmorDisabled AppArmorState = "disabled"
	// AppArmorAbsent: this kernel has no AppArmor. Not a finding on its own;
	// the host may be confining processes with something else.
	AppArmorAbsent AppArmorState = "absent"
	// AppArmorDenied: the interface exists and we were refused. securityfs is
	// root-only on most distributions, so this is the ordinary state of an
	// unprivileged scan.
	AppArmorDenied AppArmorState = "denied"
	// AppArmorError: the read failed for a reason that is none of the above.
	AppArmorError AppArmorState = "error"
)

// AppArmorMode is what one profile does when a confined process steps outside
// it.
type AppArmorMode string

const (
	// AppArmorEnforce denies and logs. This is confinement.
	AppArmorEnforce AppArmorMode = "enforce"
	// AppArmorComplain logs and allows. This is a profile in training: it
	// records what the program does so a profile can be written, and confines
	// nothing while it does so.
	AppArmorComplain AppArmorMode = "complain"
	// AppArmorKill denies and kills the process. Stricter than enforce.
	AppArmorKill AppArmorMode = "kill"
	// AppArmorUnconfined is a profile loaded and applied to nothing.
	AppArmorUnconfined AppArmorMode = "unconfined"
	// AppArmorPrompt asks userspace. Present on newer kernels; it is not
	// confinement without something answering.
	AppArmorPrompt AppArmorMode = "prompt"
	// AppArmorOther is a mode this build does not recognise. Recorded rather
	// than dropped: a mode nobody here has heard of must not be silently
	// counted as enforcement.
	AppArmorOther AppArmorMode = "other"
)

// Confining reports whether a profile in this mode actually denies anything.
//
// **complain is the mode this check exists for.** A host with two hundred
// profiles all in complain looks confined to anything counting profiles, and
// is confining nothing at all — every one of them logs the violation and
// permits it.
func (m AppArmorMode) Confining() bool {
	return m == AppArmorEnforce || m == AppArmorKill
}

// AppArmorProfile is one loaded profile.
type AppArmorProfile struct {
	Name string       `json:"name"`
	Mode AppArmorMode `json:"mode"`
}

// AppArmor is the state of the AppArmor LSM and the profiles it has loaded.
//
// **The profile names are capped and the counts are not.** A loaded profile is
// named for the binary it confines, so the full list is an inventory of what is
// installed and what it is called on this host — and a bundle travels. The
// counts answer every question the checks ask; the sample exists so a finding
// can name something an operator recognises, and is drawn from the profiles
// that are *not* confining, because those are the ones there is anything to do
// about.
type AppArmor struct {
	// State is what could be established about the LSM itself.
	State AppArmorState `json:"state"`
	// Path is where State was read from, for evidence.
	Path string `json:"path,omitempty"`
	// Msg explains a state that is not Enabled or Disabled.
	Msg string `json:"message,omitempty"`

	// ProfilesPath is the securityfs interface the profiles were read from,
	// and ProfilesState how that read went. It is separate from State because
	// the LSM can be enabled while the interface is unreadable, which is an
	// unprivileged scan of a confined host.
	ProfilesPath  string        `json:"profiles_path,omitempty"`
	ProfilesState AppArmorState `json:"profiles_state,omitempty"`
	ProfilesMsg   string        `json:"profiles_message,omitempty"`
	Digest        string        `json:"digest,omitempty"`

	// Counts is how many loaded profiles are in each mode.
	Counts map[AppArmorMode]int `json:"counts,omitempty"`

	// Unconfining samples the profiles that are loaded and confining nothing,
	// so a finding can name one. Capped; Counts carries the total.
	Unconfining []AppArmorProfile `json:"unconfining,omitempty"`

	// ProfileDir reports whether a profile directory is installed, which is
	// what tells "AppArmor is off" from "AppArmor was never set up". It is
	// also the only half of this fact a mounted image can answer.
	ProfileDir      string      `json:"profile_dir,omitempty"`
	ProfileDirState SourceState `json:"profile_dir_state,omitempty"`
	// ProfileFiles counts the profiles on disk, loaded or not.
	ProfileFiles int `json:"profile_files,omitempty"`
}

func (AppArmor) FactID() ID       { return AppArmorID }
func (AppArmor) FactVersion() int { return 1 }

// Loaded is how many profiles are loaded, in any mode.
func (a AppArmor) Loaded() int {
	n := 0
	for _, c := range a.Counts {
		n += c
	}
	return n
}

// Confined is how many loaded profiles actually deny something.
func (a AppArmor) Confined() int {
	return a.Counts[AppArmorEnforce] + a.Counts[AppArmorKill]
}

// Modes returns the modes present, in a fixed order, so a finding built from
// them is deterministic without the caller sorting a map.
func (a AppArmor) Modes() []AppArmorMode {
	out := make([]AppArmorMode, 0, len(a.Counts))
	for m, n := range a.Counts {
		if n > 0 {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Installed reports whether AppArmor exists on this host at all — as a kernel
// LSM, or as a profile directory a package put there.
//
// It is what separates a host that has turned AppArmor off from one that runs
// SELinux instead, and it is the difference between a FAIL and a
// NOT_APPLICABLE.
func (a AppArmor) Installed() bool {
	return a.State != AppArmorAbsent || a.ProfileDirState == SourcePresent
}
