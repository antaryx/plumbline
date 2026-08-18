package walker

import (
	"path"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/system"
)

// MountInfoPath is the kernel's authoritative mount table for the calling
// process. It is read through the seam like everything else, so a fixture can
// supply one and the fstype skip list is tested against a described mount
// table rather than against whatever the test machine happens to have mounted.
const MountInfoPath = "/proc/self/mountinfo"

// skipFSTypes are filesystem types the walk never descends into.
//
// Two different hazards share one list. The virtual filesystems (proc, sysfs,
// cgroup, tracefs, debugfs, devtmpfs) are not storage: walking them wastes the
// inode budget on kernel objects no security check asserts anything about, and
// some of them are effectively infinite. The network and userspace ones (nfs,
// cifs, fuse, autofs) are the classic hang — a dead NFS server blocks the
// stat in uninterruptible kernel sleep, where no timeout of ours can reach it
// and the collector's context deadline cannot save us. The only defence is to
// never make the call.
//
// Entries ending in "*" are prefix matches, which is how the cgroup and fuse
// families are covered without enumerating every variant a kernel may report.
var skipFSTypes = []string{
	"proc",
	"sysfs",
	"devtmpfs",
	"devpts",
	"cgroup*",
	"tracefs",
	"debugfs",
	"fuse*",
	"nfs*",
	"cifs",
	"smb*",
	"autofs",
	"rpc_pipefs",
	"binfmt_misc",
	"securityfs",
	"pstore",
	"bpf",
	"configfs",
	"mqueue",
	"hugetlbfs",
}

// SkippedFSType reports whether fstype is on the skip list, honouring the "*"
// prefix forms.
func SkippedFSType(fstype string) bool {
	for _, pat := range skipFSTypes {
		if strings.HasSuffix(pat, "*") {
			if strings.HasPrefix(fstype, strings.TrimSuffix(pat, "*")) {
				return true
			}
			continue
		}
		if fstype == pat {
			return true
		}
	}
	return false
}

// mountTable maps a mount point to the type of the filesystem mounted there.
type mountTable struct {
	// byPoint is the fstype at each mount point. When a path is mounted over
	// more than once, the last entry wins, because that is the one the kernel
	// resolves through — mountinfo is in mount order.
	byPoint map[string]string
	// known is false when the table could not be read. A caller must not treat
	// an unknown table as an empty one: "nothing is mounted here" and "we
	// could not find out what is mounted here" lead to opposite decisions
	// about whether it is safe to descend.
	known bool
}

// fstypeAt returns the filesystem type mounted exactly at dir.
func (t mountTable) fstypeAt(dir string) (string, bool) {
	ft, ok := t.byPoint[path.Clean(dir)]
	return ft, ok
}

// readMountTable parses /proc/self/mountinfo through the seam.
//
// It never returns an error: a mount table we could not read is a fact about
// the walk, recorded as mountTable.known == false and handled by the caller,
// not a reason to abandon a traversal that is still perfectly able to stay on
// one device.
func readMountTable(s system.System) mountTable {
	t := mountTable{byPoint: map[string]string{}}

	res, err := s.ReadFile(MountInfoPath, 4<<20)
	if err != nil {
		return t
	}
	// A truncated mount table is a table with mounts missing from the end of
	// it, and the missing ones may be exactly the NFS mount we must not walk
	// into. Refuse to trust a partial answer.
	if res.Truncated {
		return t
	}

	for _, line := range strings.Split(string(res.Data), "\n") {
		point, fstype, ok := parseMountInfoLine(line)
		if !ok {
			continue
		}
		t.byPoint[point] = fstype
	}
	t.known = true
	return t
}

// parseMountInfoLine extracts the mount point and filesystem type from one
// line of mountinfo(5):
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime shared:1 - ext3 /dev/root rw
//	                       ^ point                    ^ fstype
//
// Field 7 onwards is a variable number of optional fields terminated by a
// single "-", which is why the type cannot be read at a fixed index.
func parseMountInfoLine(line string) (point, fstype string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return "", "", false
	}
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(fields) {
		return "", "", false
	}
	return path.Clean(unescapeMountField(fields[4])), fields[sep+1], true
}

// unescapeMountField undoes the octal escaping the kernel applies to mount
// points containing space, tab, newline or backslash. A mount point named
// "/mnt/my\040share" is really "/mnt/my share", and comparing the escaped form
// against a path from ReadDir would silently fail to match — which for a skip
// list means walking into the filesystem we meant to avoid.
func unescapeMountField(in string) string {
	if !strings.Contains(in, `\`) {
		return in
	}
	var b strings.Builder
	b.Grow(len(in))
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' || i+3 >= len(in) {
			b.WriteByte(in[i])
			continue
		}
		n, err := strconv.ParseUint(in[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(in[i])
			continue
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String()
}
