// Package fake implements system.System against a fixture directory on disk.
// A fixture is a partial filesystem tree plus a manifest describing everything
// that is not a file: euid, wall clock, command output.
//
// Format is specified in docs/FIXTURES.md. The manifest lives at
// _plumbline/fixture.json inside the fixture root and is the only file in the
// tree that is not part of the simulated system.
package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/antaryx/plumbline/internal/system"
)

// ManifestPath is the fixture-relative location of the manifest.
const ManifestPath = "_plumbline/fixture.json"

// Manifest describes the non-filesystem aspects of a fixture.
type Manifest struct {
	// Description is free text shown in test failure output.
	Description string `json:"description"`
	// Euid the scan should believe it is running as. Defaults to 0.
	Euid *int `json:"euid,omitempty"`
	// Now is the frozen wall clock, RFC3339. Defaults to 2026-01-01T00:00:00Z.
	Now string `json:"now,omitempty"`
	// Exec maps a space-joined argv to a canned result.
	Exec map[string]ExecFixture `json:"exec,omitempty"`
	// Unreadable lists paths that must fail with ErrPermission even though
	// they exist in the tree. This is how a fixture simulates an unprivileged
	// run without needing real permissions in git.
	Unreadable []string `json:"unreadable,omitempty"`
	// Missing lists paths that must fail with ErrNotExist even if present.
	Missing []string `json:"missing,omitempty"`
	// Unstattable lists paths whose *metadata* must fail with ErrPermission.
	//
	// It is separate from Unreadable because the two are different situations
	// on a real host and produce different verdicts. A file at mode 0640 that
	// you do not own is unreadable but perfectly stat-able: `stat /etc/shadow`
	// succeeds for any user. What defeats a stat is a *parent directory*
	// without execute permission, and that is what this key simulates. Folding
	// the two together would have made every unreadable-file fixture also
	// claim its ownership was unknown, which is not what such a host looks
	// like.
	Unstattable []string `json:"unstattable,omitempty"`
	// Modes overrides file modes, since git only preserves the execute bit.
	// Keys are absolute simulated paths, values are octal strings ("0600").
	Modes map[string]string `json:"modes,omitempty"`
	// Owners overrides uid/gid, formatted "uid:gid".
	Owners map[string]string `json:"owners,omitempty"`
	// Inodes overrides device and inode identity, formatted "dev:ino". It is
	// how a fixture simulates a bind mount: two paths reporting one identity
	// is exactly what a bind-mount cycle is, and it is the only aspect of a
	// filesystem that a directory tree in git cannot express at all. Creating
	// a real one needs root and a mount namespace; hardlinking a directory is
	// forbidden by every Linux filesystem. See ADR-0013.
	Inodes map[string]string `json:"inodes,omitempty"`
}

// ExecFixture is a canned command result.
type ExecFixture struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// System is a fixture-backed system.System.
type System struct {
	dir      string // real path to the fixture root
	manifest Manifest
	now      time.Time
	euid     int
	deny     map[string]bool
	missing  map[string]bool
	denyStat map[string]bool
	modes    map[string]fs.FileMode
	owners   map[string][2]uint32
	inodes   map[string][2]uint64
}

var _ system.System = (*System)(nil)

// New loads a fixture from dir. A missing manifest is not an error; a fixture
// that is only a filesystem tree is valid and common.
func New(dir string) (*System, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("fixture %q is not a directory", dir)
	}

	s := &System{
		dir:      abs,
		now:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		euid:     0,
		deny:     map[string]bool{},
		missing:  map[string]bool{},
		denyStat: map[string]bool{},
		modes:    map[string]fs.FileMode{},
		owners:   map[string][2]uint32{},
		inodes:   map[string][2]uint64{},
	}

	raw, err := os.ReadFile(filepath.Join(abs, filepath.FromSlash(ManifestPath)))
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.manifest); err != nil {
			return nil, fmt.Errorf("fixture %s: %w", ManifestPath, err)
		}
	case os.IsNotExist(err):
		// fine: tree-only fixture
	default:
		return nil, err
	}

	if s.manifest.Euid != nil {
		s.euid = *s.manifest.Euid
	}
	if s.manifest.Now != "" {
		t, err := time.Parse(time.RFC3339, s.manifest.Now)
		if err != nil {
			return nil, fmt.Errorf("fixture now: %w", err)
		}
		s.now = t.UTC()
	}
	for _, p := range s.manifest.Unreadable {
		s.deny[path.Clean(p)] = true
	}
	for _, p := range s.manifest.Missing {
		s.missing[path.Clean(p)] = true
	}
	for _, p := range s.manifest.Unstattable {
		s.denyStat[path.Clean(p)] = true
	}
	for p, m := range s.manifest.Modes {
		var mode uint32
		if _, err := fmt.Sscanf(m, "%o", &mode); err != nil {
			return nil, fmt.Errorf("fixture mode %q for %s: %w", m, p, err)
		}
		s.modes[path.Clean(p)] = modeFromUnix(mode)
	}
	for p, o := range s.manifest.Owners {
		var uid, gid uint32
		if _, err := fmt.Sscanf(o, "%d:%d", &uid, &gid); err != nil {
			return nil, fmt.Errorf("fixture owner %q for %s: %w", o, p, err)
		}
		s.owners[path.Clean(p)] = [2]uint32{uid, gid}
	}
	for p, id := range s.manifest.Inodes {
		var dev, ino uint64
		if _, err := fmt.Sscanf(id, "%d:%d", &dev, &ino); err != nil {
			return nil, fmt.Errorf("fixture inode %q for %s: %w", id, p, err)
		}
		if dev == 0 && ino == 0 {
			// Zero means "not recorded" on the seam (ADR-0012). A fixture that
			// set it deliberately would be asking for an identity that reads
			// as no identity, which silently disables cycle detection for that
			// path — the opposite of what anyone writing this field wants.
			return nil, fmt.Errorf("fixture inode %q for %s: 0:0 means \"not recorded\"; use a non-zero device or inode", id, p)
		}
		s.inodes[path.Clean(p)] = [2]uint64{dev, ino}
	}
	return s, nil
}

// Description returns the fixture's human-readable description.
func (s *System) Description() string { return s.manifest.Description }

func (s *System) Root() string { return s.dir }

// resolve maps a simulated absolute path onto the fixture tree, refusing
// anything that would escape it.
func (s *System) resolve(p string) (string, string, error) {
	clean := path.Clean("/" + strings.TrimPrefix(path.Clean(p), "/"))
	real := filepath.Join(s.dir, filepath.FromSlash(clean))
	if !strings.HasPrefix(real, s.dir+string(filepath.Separator)) && real != s.dir {
		return "", "", system.ErrEscapesRoot
	}
	if s.missing[clean] {
		return clean, real, system.ErrNotExist
	}
	return clean, real, nil
}

func (s *System) Stat(p string) (system.FileInfo, error) {
	clean, real, err := s.resolve(p)
	if err != nil {
		return system.FileInfo{}, err
	}
	// A parent directory that refuses traversal. Nothing about the path can be
	// observed — not its mode, not its owner, not whether it exists at all —
	// which is a materially different situation from a file we may stat and
	// may not read.
	if s.denyStat[clean] {
		return system.FileInfo{}, system.ErrPermission
	}
	st, err := os.Lstat(real)
	if err != nil {
		if os.IsNotExist(err) {
			return system.FileInfo{}, system.ErrNotExist
		}
		return system.FileInfo{}, err
	}
	return s.infoFor(clean, st), nil
}

func (s *System) infoFor(clean string, st os.FileInfo) system.FileInfo {
	fi := system.FileInfo{
		Path:      clean,
		Mode:      st.Mode(),
		Size:      st.Size(),
		ModTime:   st.ModTime().UTC(),
		IsDir:     st.IsDir(),
		IsRegular: st.Mode().IsRegular(),
		IsSymlink: st.Mode()&fs.ModeSymlink != 0,
	}
	// Real device and inode from the fixture tree's own files, so two fixture
	// paths are genuinely distinct and a cycle-detection test is testing the
	// set rather than testing this fake (ADR-0012).
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		fi.Dev, fi.Ino = sys.Dev, sys.Ino
	}
	// Fixture overrides win: git cannot carry modes or ownership faithfully.
	if m, ok := s.modes[clean]; ok {
		// The type is only replaced when the fixture actually named one.
		// "0644" is a statement about permissions and says nothing about what
		// the inode is; clearing the type for it would turn every directory
		// with a mode override into a regular file, and the walk would stop at
		// it without ever saying why.
		mask := fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
		if m&fs.ModeType != 0 {
			mask |= fs.ModeType
		}
		fi.Mode = (fi.Mode &^ mask) | (m & mask)
		// The type bits decide what this inode *is*, so the derived booleans
		// have to be recomputed from the override rather than left describing
		// the placeholder file that stands in for it in git.
		fi.IsDir = fi.Mode.IsDir()
		fi.IsRegular = fi.Mode.IsRegular()
		fi.IsSymlink = fi.Mode&fs.ModeSymlink != 0
	}
	if o, ok := s.owners[clean]; ok {
		fi.UID, fi.GID = o[0], o[1]
	}
	if id, ok := s.inodes[clean]; ok {
		fi.Dev, fi.Ino = id[0], id[1]
	}
	return fi
}

// modeFromUnix converts an octal Unix mode — the number a fixture author reads
// out of `stat -c %a` or `ls -l` — into Go's fs.FileMode.
//
// The translation is not a cast. Go encodes setuid, sticky and the file type
// in high bits of its own choosing, so fs.FileMode(0o4755) is 0o755 with a bit
// set that means nothing: a fixture asking for a SUID binary would silently
// get an ordinary one, and the SUID check written against it would silently
// pass. That is exactly the class of quiet wrongness fixtures exist to catch,
// so the conversion is explicit.
//
// The type bits matter for the same reason. A FIFO, a socket and a character
// device cannot be committed to git, and creating a character device needs
// root, so a fixture describes them here instead. The shared filesystem walker
// must never open any of them, and that rule needs a test.
func modeFromUnix(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	switch mode & 0o170000 {
	case 0o140000:
		m |= fs.ModeSocket
	case 0o120000:
		m |= fs.ModeSymlink
	case 0o060000:
		m |= fs.ModeDevice
	case 0o040000:
		m |= fs.ModeDir
	case 0o020000:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case 0o010000:
		m |= fs.ModeNamedPipe
	}
	return m
}

func (s *System) ReadFile(p string, maxBytes int64) (system.ReadResult, error) {
	clean, real, err := s.resolve(p)
	if err != nil {
		return system.ReadResult{}, err
	}
	if s.deny[clean] {
		return system.ReadResult{}, system.ErrPermission
	}
	if maxBytes <= 0 {
		maxBytes = system.DefaultMaxRead
	}

	st, err := os.Lstat(real)
	if err != nil {
		if os.IsNotExist(err) {
			return system.ReadResult{}, system.ErrNotExist
		}
		return system.ReadResult{}, err
	}
	if !st.Mode().IsRegular() {
		return system.ReadResult{}, system.ErrNotRegular
	}

	data, err := os.ReadFile(real)
	if err != nil {
		return system.ReadResult{}, err
	}
	res := system.ReadResult{Path: clean, Size: int64(len(data))}
	if int64(len(data)) > maxBytes {
		data = data[:maxBytes]
		res.Truncated = true
	}
	res.Data = data
	sum := sha256.Sum256(data)
	res.SHA256 = hex.EncodeToString(sum[:])
	return res, nil
}

func (s *System) ReadDir(p string, maxEntries int) (system.DirResult, error) {
	clean, real, err := s.resolve(p)
	if err != nil {
		return system.DirResult{}, err
	}
	if s.deny[clean] {
		return system.DirResult{}, system.ErrPermission
	}
	if maxEntries <= 0 {
		maxEntries = system.DefaultMaxDirEntries
	}

	entries, err := os.ReadDir(real)
	if err != nil {
		if os.IsNotExist(err) {
			return system.DirResult{}, system.ErrNotExist
		}
		return system.DirResult{}, err
	}

	res := system.DirResult{Path: clean}
	kept := 0
	for _, e := range entries {
		if clean == "/" && e.Name() == "_plumbline" {
			// The manifest is not part of the simulated system. Its absence is
			// by design, so it must not mark the listing truncated.
			continue
		}
		if kept >= maxEntries {
			res.Truncated = true
			break
		}
		st, err := e.Info()
		if err != nil {
			res.Truncated = true
			continue
		}
		res.Entries = append(res.Entries, s.infoFor(path.Join(clean, e.Name()), st))
		kept++
	}
	return res, nil
}

func (s *System) Glob(pattern string) ([]string, error) {
	clean, real, err := s.resolve(pattern)
	if err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(real)
	if err != nil {
		return nil, err
	}
	prefix := s.dir
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		rel := filepath.ToSlash(strings.TrimPrefix(m, prefix))
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}
		if s.missing[rel] {
			continue
		}
		out = append(out, rel)
	}
	_ = clean
	return out, nil
}

func (s *System) Exec(_ context.Context, argv []string) (system.ExecResult, error) {
	key := strings.Join(argv, " ")
	f, ok := s.manifest.Exec[key]
	if !ok {
		return system.ExecResult{Argv: argv}, fmt.Errorf(
			"fixture %s has no exec entry for %q; add it to %s",
			s.manifest.Description, key, ManifestPath)
	}
	return system.ExecResult{
		Argv:     argv,
		Stdout:   []byte(f.Stdout),
		Stderr:   []byte(f.Stderr),
		ExitCode: f.ExitCode,
	}, nil
}

func (s *System) Now() time.Time { return s.now }
func (s *System) Euid() int      { return s.euid }
