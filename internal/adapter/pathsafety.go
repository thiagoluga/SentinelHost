package adapter

import (
	"path/filepath"
	"strings"
)

// UnscannablePathName is the skip reason for a path that cannot be handed to an engine.
//
// It is a REASON, not a silent drop, because the whole point is that these files were not
// scanned. A file nobody looked at must never be indistinguishable from a file that was
// looked at and found clean.
const UnscannablePathName = "unscannable_path_name"

// PathIsExpressible reports whether a path can be given to an engine without changing
// meaning on the way.
//
// A filename on Linux may contain any byte except `/` and NUL — including a newline. The
// engines that take a scope take it as a file with one path per line (`yara --scan-list`,
// `maldet -f`), so a file named
//
//	uploads/x<LF>.php
//
// becomes TWO lines. Neither exists, so neither engine ever opens the payload — while it
// stays reachable and executable, because the web server keys on the trailing `.php`. All
// three malware engines then report zero findings on a live webshell, which is exactly the
// failure this project exists to prevent, produced by one `rename()`.
//
// The same primitive works in reverse. A name like
//
//	a<LF>/home/user/mail/secret
//
// injects an absolute path into the scan list, so an engine reads a file outside every
// configured root and past every exclusion.
//
// A carriage return is refused for the same reason on any engine that trims it, and NUL
// because every one of these tools is C and treats it as end-of-string — a path truncated
// at a NUL names a different file than the one that was walked.
func PathIsExpressible(path string) bool {
	return !strings.ContainsAny(path, "\n\r\x00")
}

// FilterExpressiblePaths splits a scope into what can be scanned and what cannot.
//
// Returns the usable paths and the ones refused, so the caller can COUNT the refusals
// into the report rather than quietly scanning fewer files than it was asked to.
func FilterExpressiblePaths(paths []string) (usable, refused []string) {
	for _, p := range paths {
		if PathIsExpressible(p) {
			usable = append(usable, p)
			continue
		}
		refused = append(refused, p)
	}
	return usable, refused
}

// PathIsWithin reports whether path lies inside root.
//
// Engine output is text, and a path parsed out of it is acted on: it becomes a verdict,
// and a verdict can be quarantined. Nothing between the parser and `os.Remove` asserted
// that the path was one we asked about, so a name that forged its way into a report — see
// the AMWScan `File:` header — could name any file on the account.
//
// Compared after cleaning both sides, and with a separator check, so that `/home/user2`
// is not treated as being inside `/home/user`.
func PathIsWithin(path, root string) bool {
	if root == "" {
		return false
	}
	p := filepath.ToSlash(filepath.Clean(path))
	r := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(root)), "/")
	if p == r {
		return true
	}
	return strings.HasPrefix(p, r+"/")
}

// PathIsWithinAny reports whether path lies inside any of the roots.
func PathIsWithinAny(path string, roots []string) bool {
	for _, r := range roots {
		if PathIsWithin(path, r) {
			return true
		}
	}
	return false
}
