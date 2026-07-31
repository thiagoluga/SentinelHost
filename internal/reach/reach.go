// Package reach answers one question about a path: can a visitor fetch this file over
// the web right now?
//
// It changes urgency, never truth. A webshell in the document root can be executed by
// anyone with the URL, this minute. The same webshell in the account's trash cannot be
// executed by anybody — and it is still a webshell, still reported at its real level,
// still counted.
//
// That distinction is what a person needs in order to decide what to do first, and it is
// deliberately kept out of the score. Adjusting a verdict by context is the mechanism
// through which real findings quietly stop being seen, and D-003 keeps the consensus
// showing its votes rather than a number somebody tuned. What this package feeds is the
// ACTION and the report — the same place the whitelist acts (D-006).
package reach

import (
	"path/filepath"
	"strings"
)

// Location says where a file sits relative to what the web serves.
type Location string

const (
	// LocationWebReachable: inside a document root. A visitor can request it.
	LocationWebReachable Location = "web_reachable"
	// LocationTrash: a control panel's deleted-files area.
	//
	// Its own category rather than folding into "outside the document root", because
	// the two need different sentences. Trash is RESTORABLE with one click: the user
	// deliberately deleted this, and putting it back puts the malware back with it.
	LocationTrash Location = "trash"
	// LocationOutsideDocRoot: on the account, but not served — backups, a home
	// directory, a directory above the site.
	LocationOutsideDocRoot Location = "outside_docroot"
	// LocationUnknown: no document root was configured, so nothing can be said.
	//
	// Explicitly not "outside": claiming a file is unreachable when the question was
	// never answerable is the kind of reassurance this project exists to avoid.
	LocationUnknown Location = "unknown"
)

// Reachable answers whether a visitor could fetch the file.
//
// Unknown counts as reachable. When the answer is not known, the safe reading is the
// urgent one — the opposite default would quietly downgrade findings on any installation
// whose document roots were not configured.
func (l Location) Reachable() bool {
	return l == LocationWebReachable || l == LocationUnknown
}

// Explain is the sentence a user reads next to a finding.
//
// Each says what the location means for them AND what it does not mean, because
// "unreachable" is the half of the message that invites the wrong conclusion.
func (l Location) Explain() string {
	switch l {
	case LocationWebReachable:
		return "served by the web: a visitor can request this file"
	case LocationTrash:
		return "in the account's trash, so nothing serves it — but the trash restores " +
			"with one click, and restoring the site restores this with it"
	case LocationOutsideDocRoot:
		return "outside every document root, so nothing serves it — it is still on the " +
			"account, and a copy or a restore brings it back into play"
	default:
		return "no document root is configured, so whether the web serves this is unknown"
	}
}

// trashMarkers are the deleted-files directories the control panels use.
//
// Matched as a whole path SEGMENT, never as a substring. `.trash` is distinctive enough,
// but `trash` is a word people name their own directories — a site with
// `public_html/trash/` full of drafts must not have its findings downgraded because of a
// folder name.
//
// This is the D-026 lesson applied before it can bite: the exclusion of our own data
// directory used to key off the literal name `.sentinelhost`, so anybody who renamed it
// silently lost the protection. Names are a hint; paths are the answer, and the document
// roots below are what actually decide.
var trashMarkers = map[string]bool{
	".trash":   true, // cPanel
	".cpanel":  false,
	".plesk":   false,
	"__trash":  true, // some panels
	".deleted": true,
}

// Classifier answers about paths, given where the site's document roots are.
type Classifier struct {
	docRoots []string
	trashes  []string
}

// New builds a classifier.
//
// docRoots are directories the web server serves. trashDirs are extra deleted-files
// locations beyond the ones recognized by name; both are made absolute and normalized so
// a configuration written with a trailing slash, or in the other separator, still works.
func New(docRoots, trashDirs []string) *Classifier {
	return &Classifier{docRoots: normalizeAll(docRoots), trashes: normalizeAll(trashDirs)}
}

func normalizeAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p = normalize(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalize(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return strings.TrimSuffix(filepath.ToSlash(p), "/")
}

// Of classifies one path.
//
// Trash is checked BEFORE the document roots, and the order matters. A trash directory
// can sit inside one — cPanel's `.trash` lives in the home directory, but a user can
// point a root at anything — and "the web serves this" would be the wrong headline for a
// file the account has already deleted.
func (c *Classifier) Of(path string) Location {
	p := normalize(path)
	if p == "" {
		return LocationUnknown
	}

	if c.inTrash(p) {
		return LocationTrash
	}
	if len(c.docRoots) == 0 {
		return LocationUnknown
	}
	for _, root := range c.docRoots {
		if under(p, root) {
			return LocationWebReachable
		}
	}
	return LocationOutsideDocRoot
}

func (c *Classifier) inTrash(p string) bool {
	for _, t := range c.trashes {
		if under(p, t) {
			return true
		}
	}
	// A recognized marker as a whole segment. Splitting rather than using strings.Contains
	// is the point: `/home/u/public_html/contrash/x.php` contains ".trash" nowhere, but
	// `/home/u/mytrash/x.php` contains "trash", and neither is a deleted file.
	for _, seg := range strings.Split(p, "/") {
		if trashMarkers[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// under answers whether p is dir itself or something inside it.
//
// Compared segment by segment, because a prefix comparison says `/home/u/public_html2`
// is inside `/home/u/public_html`, and it is not — that is somebody else's site
// directory being classified as this one's.
func under(p, dir string) bool {
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, dir+"/")
}
