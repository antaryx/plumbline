package remediate

import (
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// jsonSetFunc merges one key into a JSON object file.
//
// **/etc/docker/daemon.json is not a file to edit with sed.** It is JSON that
// the daemon refuses to start on if it is malformed, so a substitution that got
// a comma wrong takes Docker down at the next restart — which on many hosts is
// every workload on the machine. This parses it, sets one key, and writes it
// back, or refuses and says why.
//
// **It reads the file on the host at the moment it runs and embeds nothing from
// the scan.** daemon.json holds registry mirrors, proxy URLs and storage paths,
// which is why the collector records its top-level key names and never their
// values (ADR-0015) — and a generated script that pasted the current contents
// in would put exactly what the bundle refuses to carry into a file an operator
// might paste into a ticket.
//
// python3 rather than jq: it is present on every distribution that ships
// Docker, jq frequently is not, and a hand-rolled alternative for a host with
// neither would be sed on JSON, which is the thing this exists to avoid. The
// absence is reported as an instruction rather than worked around.
//
// The early exit when the key already holds the wanted value is what makes a
// second run a true no-op — the file is not rewritten at all, so its mtime and
// its formatting are left alone.
const jsonSetFunc = `
# Set KEY to VALUE in a JSON object file, creating the file if it is absent.
# The file is copied to FILE.bak once before the first change, and a run that
# finds the key already correct rewrites nothing at all.
plumbline_json_set() {
	pl_file=$1 pl_key=$2 pl_val=$3
	if ! command -v python3 >/dev/null 2>&1; then
		echo "plumbline: python3 is needed to edit $pl_file safely." >&2
		echo "plumbline: set \"$pl_key\": \"$pl_val\" by hand instead." >&2
		return 1
	fi
	if [ -e "$pl_file" ]; then
		plumbline_backup "$pl_file"
	fi
	python3 - "$pl_file" "$pl_key" "$pl_val" <<'PLUMBLINE_PY'
import errno, json, os, sys

path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path) as fh:
        text = fh.read().strip()
    doc = json.loads(text) if text else {}
except IOError as err:
    if err.errno != errno.ENOENT:
        raise
    doc = {}
except ValueError as err:
    sys.exit("plumbline: %s is not valid JSON (%s); refusing to rewrite it" % (path, err))

if not isinstance(doc, dict):
    sys.exit("plumbline: %s is not a JSON object; refusing to rewrite it" % path)
if doc.get(key) == value:
    sys.exit(0)

doc[key] = value
parent = os.path.dirname(path)
if parent and not os.path.isdir(parent):
    os.makedirs(parent)
with open(path, "w") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
PLUMBLINE_PY
}
`

// dockerJSONFix sets one key in the Docker daemon's configuration.
type dockerJSONFix struct {
	checkID  string
	title    string
	fallback string
	key      string
	value    string
	notes    []string
}

func (d dockerJSONFix) CheckID() string { return d.checkID }

func (d dockerJSONFix) Build(f finding.Finding, _ Options) (Action, bool) {
	// The finding's subject is the daemon configuration path the collector
	// actually found, which is not always /etc/docker/daemon.json — a daemon
	// started with --config-file uses another, and writing the default would
	// produce a file the running daemon never reads.
	path := f.Subject
	if !strings.HasPrefix(path, "/") {
		if p := keepPaths(pathsFrom(f)); len(p) > 0 {
			path = p[0]
		} else {
			path = d.fallback
		}
	}

	a := Action{CheckID: d.checkID, Title: titleOf(f, d.title)}
	for _, n := range d.notes {
		note(&a, n)
	}
	note(&a, "The file is copied to "+path+".bak before it is changed.")
	command(&a, "plumbline_json_set", path, d.key, d.value)
	return a, true
}

func init() {
	register(dockerJSONFix{
		checkID:  "CONTAINERS-0001",
		title:    "The Docker daemon remaps container users to unprivileged host uids",
		fallback: "/etc/docker/daemon.json",
		key:      "userns-remap",
		value:    "default",
		notes: []string{
			"Restart the daemon afterwards: dockerd reads this only at startup.",
			"**Existing containers, images and volumes are not migrated.** The remapped daemon",
			"uses a separate storage root, so everything already on this host becomes invisible",
			"to it until it is re-imported. Do not run this on a host with running workloads",
			"without planning that first.",
		},
	})
}
