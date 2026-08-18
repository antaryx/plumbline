// Package live implements system.System against the running host.
//
// It also implements the --root prefixing described in ARCHITECTURE.md §2.1:
// a live scan is just a rooted scan with an empty root. That is why there is
// no separate "rooted" package. Scanning a mounted image, a container's host
// mount, or a fixture tree in production all take the same path.
//
// Safety rules enforced here (THREAT-MODEL.md):
//   - symlinks are never followed on a privileged read
//   - only regular files are ever opened, so a FIFO cannot hang the scanner
//   - every read is size-capped
//   - Exec takes argv and runs with a sanitised environment; there is no shell
package live

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/antaryx/plumbline/internal/system"
)

// System is a live (optionally rooted) system.System.
type System struct {
	root string // "" means the real filesystem root
}

var _ system.System = (*System)(nil)

// New returns a System scanning under root. An empty root scans the host.
func New(root string) *System {
	if root == "/" {
		root = ""
	}
	return &System{root: strings.TrimSuffix(root, "/")}
}

func (s *System) Root() string { return s.root }

// resolve maps a simulated absolute path to a real one and refuses escapes.
func (s *System) resolve(p string) (string, string, error) {
	clean := path.Clean("/" + strings.TrimPrefix(path.Clean(p), "/"))
	if s.root == "" {
		return clean, clean, nil
	}
	real := filepath.Join(s.root, filepath.FromSlash(clean))
	if real != s.root && !strings.HasPrefix(real, s.root+string(filepath.Separator)) {
		return "", "", system.ErrEscapesRoot
	}
	return clean, real, nil
}

func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return system.ErrNotExist
	case errors.Is(err, os.ErrPermission):
		return system.ErrPermission
	default:
		return err
	}
}

func (s *System) Stat(p string) (system.FileInfo, error) {
	clean, real, err := s.resolve(p)
	if err != nil {
		return system.FileInfo{}, err
	}
	st, err := os.Lstat(real)
	if err != nil {
		return system.FileInfo{}, translate(err)
	}
	return infoFor(clean, st), nil
}

func infoFor(clean string, st os.FileInfo) system.FileInfo {
	fi := system.FileInfo{
		Path:      clean,
		Mode:      st.Mode(),
		Size:      st.Size(),
		ModTime:   st.ModTime().UTC(),
		IsDir:     st.IsDir(),
		IsRegular: st.Mode().IsRegular(),
		IsSymlink: st.Mode()&fs.ModeSymlink != 0,
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		fi.UID, fi.GID = sys.Uid, sys.Gid
	}
	return fi
}

func (s *System) ReadFile(p string, maxBytes int64) (system.ReadResult, error) {
	clean, real, err := s.resolve(p)
	if err != nil {
		return system.ReadResult{}, err
	}
	if maxBytes <= 0 {
		maxBytes = system.DefaultMaxRead
	}

	// O_NOFOLLOW defeats the terminal-symlink swap. O_NONBLOCK means that if
	// this somehow is a FIFO despite the mode check below, the open returns
	// instead of blocking a root process indefinitely.
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return system.ReadResult{}, system.ErrNotRegular
		}
		return system.ReadResult{}, translate(err)
	}
	defer f.Close()

	// Verify after opening, not before: checking then opening is the TOCTOU
	// window this ordering closes.
	st, err := f.Stat()
	if err != nil {
		return system.ReadResult{}, translate(err)
	}
	if !st.Mode().IsRegular() {
		return system.ReadResult{}, system.ErrNotRegular
	}

	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return system.ReadResult{}, translate(err)
	}

	res := system.ReadResult{Path: clean, Size: n}
	data := buf.Bytes()
	if n > maxBytes {
		data = data[:maxBytes]
		res.Truncated = true
		res.Size = maxBytes
	}
	res.Data = data
	sum := sha256.Sum256(data)
	res.SHA256 = hex.EncodeToString(sum[:])
	return res, nil
}

func (s *System) ReadDir(p string) ([]system.FileInfo, error) {
	clean, real, err := s.resolve(p)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return nil, translate(err)
	}
	out := make([]system.FileInfo, 0, len(entries))
	for _, e := range entries {
		st, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, infoFor(path.Join(clean, e.Name()), st))
	}
	return out, nil
}

func (s *System) Glob(pattern string) ([]string, error) {
	_, real, err := s.resolve(pattern)
	if err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(real)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		p := filepath.ToSlash(m)
		if s.root != "" {
			p = strings.TrimPrefix(p, filepath.ToSlash(s.root))
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// execEnv is the only environment external commands ever see. Locale is
// pinned because parsing localised command output is a silent-wrong-answer
// bug, and PATH is minimal so that a writable directory earlier in the
// operator's PATH cannot substitute a binary.
var execEnv = []string{
	"LC_ALL=C",
	"LANG=C",
	"TZ=UTC",
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
}

func (s *System) Exec(ctx context.Context, argv []string) (system.ExecResult, error) {
	if len(argv) == 0 {
		return system.ExecResult{}, errors.New("empty argv")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = execEnv
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := system.ExecResult{Argv: argv, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return res, nil
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
		return res, nil // a non-zero exit is data, not a failure to execute
	default:
		return res, err
	}
}

func (s *System) Now() time.Time { return time.Now().UTC() }
func (s *System) Euid() int      { return os.Geteuid() }
