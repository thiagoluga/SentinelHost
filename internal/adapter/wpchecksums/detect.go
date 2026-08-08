// Package wpchecksums implements the native WordPress integrity adapter: it
// compares the core files against the official checksums published by
// WordPress.org.
//
// It is the only engine in the MVP that votes POSITIVELY for legitimacy. That
// vote becomes a veto in the verdict engine: a file identical to the official
// checksum is never quarantined, no matter how many engines flag it
// (DECISIONS.md D-005).
package wpchecksums

import (
	"bufio"
	"crypto/md5" // the WordPress.org API publishes MD5; this is not cryptographic use
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Slug of the engine.
const Slug = "wp-checksums"

// ErrNotWordPress means the root is not a WordPress installation.
//
// A site that is not WordPress (Laravel, Joomla, static) is a normal case, not
// a failure: the adapter abstains without penalizing the other engines' score.
var ErrNotWordPress = errors.New("this does not look like a WordPress installation")

// versionRe extracts the version from wp-includes/version.php.
var versionRe = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)

// Install is what was detected about the installation.
type Install struct {
	Root    string
	Version string
	Locale  string
}

// Detect looks for a WordPress installation under the root.
func Detect(root string) (Install, error) {
	versionFile := filepath.Join(root, "wp-includes", "version.php")
	f, err := os.Open(versionFile) // path derived from the root the user configured
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Install{}, fmt.Errorf("%w: %s does not exist", ErrNotWordPress, versionFile)
		}
		return Install{}, fmt.Errorf("%w: could not read %s: %v", ErrNotWordPress, versionFile, err)
	}
	defer func() { _ = f.Close() }()

	// version.php is small; reading it line by line avoids loading a huge file
	// if someone points the root at the wrong place.
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for sc.Scan() {
		if m := versionRe.FindStringSubmatch(sc.Text()); m != nil {
			return Install{Root: root, Version: m[1], Locale: "en_US"}, nil
		}
	}
	if err := sc.Err(); err != nil {
		return Install{}, fmt.Errorf("%w: reading %s: %v", ErrNotWordPress, versionFile, err)
	}
	return Install{}, fmt.Errorf("%w: %s does not declare $wp_version", ErrNotWordPress, versionFile)
}

// Search bounds for DetectAll.
//
// The walk is over an account's home directory on shared hosting, so it has to be
// bounded in three directions at once — how deep, how many installations, and how many
// directories examined — and it has to SAY when a bound stopped it. A search that gave
// up silently would report "no WordPress here" for an account that has one, which is
// the same lie this adapter's abstention is designed to avoid.
const (
	// DefaultSearchDepth counts directories below each configured root. A cPanel
	// account keeps its sites at public_html/<domain>/ or public_html/<domain>/blog/,
	// which is two or three; six leaves room without walking an entire disk.
	DefaultSearchDepth = 6
	// DefaultMaxInstalls is a ceiling, not an expectation. Accounts with dozens of
	// addon domains exist, and each installation costs an API round trip and a full
	// core inventory on every cycle.
	DefaultMaxInstalls = 25
	// DefaultMaxDirs bounds the walk itself, for the account whose uploads directory
	// holds a hundred thousand folders.
	DefaultMaxDirs = 50000
)

// skipDirs are never descended into while looking for a WordPress.
//
// None of them can contain the ROOT of an installation. wp-content is the interesting
// case: a WordPress inside another WordPress's content directory is somebody's backup or
// a staging copy, and scanning it as a separate site would double every finding.
var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	".svn":         true,
	".cache":       true,
	"cache":        true,
	"wp-content":   true,
	"wp-includes":  true,
	"wp-admin":     true,
}

// SearchResult is what a look for WordPress installations found, and what stopped it.
type SearchResult struct {
	Installs []Install
	// DirsWalked is evidence that the search happened at all. A zero here with no
	// installations means the roots were unreadable, not that the account has no
	// WordPress, and those are different answers.
	DirsWalked int
	// Roots searched, in the order given.
	Roots []string
	Depth int
	// StoppedAt names the bound that cut the search short, empty when none did.
	// Reported rather than swallowed: a truncated search that reads as a complete one
	// is how "we found nothing" comes to mean "we stopped looking".
	StoppedAt string
	// Unreadable roots, which are a coverage gap and not an absence of WordPress.
	Unreadable []string
}

// DetectAll finds every WordPress installation at or under the given roots.
//
// Detect() answers a narrower question — is THIS directory a WordPress — and that was
// the only question ever asked. On a hosting account it is almost always the wrong one:
// the configured root is the account's home, and WordPress lives at
// public_html/<domain>/. The adapter reported "this does not look like a WordPress
// installation: /home/user/wp-includes/version.php does not exist" for accounts running
// several of them.
//
// That silence is expensive beyond the missing coverage. This is the only engine that
// votes FOR legitimacy, and that vote is a veto: a file matching the official checksum is
// never quarantined however many heuristics flag it (D-005). With the engine abstaining,
// genuine core files face AMWScan and YARA with nothing speaking for them.
//
// Finding an installation does not stop the descent, and that is deliberate. On cPanel
// the main site is public_html/ and every addon domain is public_html/<domain>/ — so one
// WordPress routinely sits inside another's directory and is a completely separate site.
// Refusing to descend cost exactly that case in the first draft of this function.
//
// What keeps a backup out is skipDirs: wp-content is never descended into, and that is
// where a staging or backup copy lives. Treating one of those as its own site would
// report every finding in it twice.
func DetectAll(roots []string, depth, maxInstalls, maxDirs int) SearchResult {
	if depth <= 0 {
		depth = DefaultSearchDepth
	}
	if maxInstalls <= 0 {
		maxInstalls = DefaultMaxInstalls
	}
	if maxDirs <= 0 {
		maxDirs = DefaultMaxDirs
	}

	res := SearchResult{Roots: roots, Depth: depth}
	seen := map[string]bool{}

	for _, root := range roots {
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			abs = root
		}
		if _, err := os.Stat(abs); err != nil {
			res.Unreadable = append(res.Unreadable, root)
			continue
		}
		if res.StoppedAt != "" {
			break
		}
		walkForWordPress(abs, depth, maxInstalls, maxDirs, seen, &res)
	}
	return res
}

// walkForWordPress descends one root, breadth-first by level so the shallowest
// installations are found first — those are the real sites, and a ceiling on the number
// found should keep them rather than whatever the walker reached first.
func walkForWordPress(root string, depth, maxInstalls, maxDirs int, seen map[string]bool, res *SearchResult) {
	level := []string{root}

	for d := 0; d <= depth && len(level) > 0; d++ {
		var next []string
		for _, dir := range level {
			if res.DirsWalked >= maxDirs {
				res.StoppedAt = fmt.Sprintf(
					"the search stopped after examining %d directories", maxDirs)
				return
			}
			res.DirsWalked++

			if inst, err := Detect(dir); err == nil && !seen[inst.Root] {
				seen[inst.Root] = true
				res.Installs = append(res.Installs, inst)
				if len(res.Installs) >= maxInstalls {
					res.StoppedAt = fmt.Sprintf(
						"the search stopped at %d installations", maxInstalls)
					return
				}
			}

			if d == depth {
				// The last level is examined but not expanded.
				continue
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				// One unreadable directory is not the search failing. It is counted
				// through DirsWalked and the rest of the level proceeds.
				continue
			}
			for _, e := range entries {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || skipDirs[e.Name()] {
					continue
				}
				next = append(next, filepath.Join(dir, e.Name()))
			}
		}
		level = next
	}
}

// LocalFile is the on-disk state of a core file.
type LocalFile struct {
	// RelPath is relative to the root, always with forward slashes (the format
	// the WordPress.org API uses).
	RelPath string `json:"rel_path"`
	AbsPath string `json:"abs_path"`
	MD5     string `json:"md5"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Perms   string `json:"perms"`
	MTime   int64  `json:"mtime"`
}

// inventory computes the MD5 and SHA-256 of the core files listed in the
// checksums.
//
// Only the files the API knows about are read: walking the whole installation
// here would duplicate the orchestrator's walker and burn the user account's CPU
// for nothing.
func inventory(root string, checksums map[string]string) (map[string]LocalFile, []string) {
	out := make(map[string]LocalFile, len(checksums))
	var missing []string

	for rel := range checksums {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			// A core file that should exist and does not is a finding, not a read
			// error.
			missing = append(missing, rel)
			continue
		}
		md5sum, sha, err := hashFile(abs)
		if err != nil {
			// Unreadable is not the same as missing, nor as tampered with. It
			// stays out of the inventory and does not become a finding: asserting
			// anything about a file we could not read would be a guess.
			continue
		}
		out[rel] = LocalFile{
			RelPath: rel,
			AbsPath: abs,
			MD5:     md5sum,
			SHA256:  sha,
			Size:    info.Size(),
			Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
			MTime:   info.ModTime().Unix(),
		}
	}
	return out, missing
}

// hashFile computes the MD5 (to compare against the API) and the SHA-256 (the
// schema's key) in a single read of the file.
func hashFile(path string) (string, string, error) {
	f, err := os.Open(path) // path derived from the configured root
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()

	m := md5.New() // format imposed by the WordPress.org API
	s := sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

// extraFiles looks for files inside wp-admin/ and wp-includes/ that the API does
// not know about. The official core has no extra files; a new .php in there is
// one of the most reliable signs of compromise.
func extraFiles(root string, checksums map[string]string, maxDepth int) []LocalFile {
	var out []LocalFile
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable directory does not take down the walk
			}
			if d.IsDir() {
				if depthOf(root, path) > maxDepth {
					return fs.SkipDir
				}
				return nil
			}
			// A symlink is never followed: a link pointing outside the root would
			// take the scanner out of the directory the user authorized.
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			slashRel := filepath.ToSlash(rel)
			if _, known := checksums[slashRel]; known {
				return nil
			}
			// Only executable code matters: an extra .txt in wp-includes is
			// sloppiness, an extra .php is a back door.
			if !isExecutableExt(slashRel) {
				return nil
			}
			info, statErr := d.Info()
			if statErr != nil {
				return nil
			}
			md5sum, sha, hashErr := hashFile(path)
			if hashErr != nil {
				return nil
			}
			out = append(out, LocalFile{
				RelPath: slashRel,
				AbsPath: path,
				MD5:     md5sum,
				SHA256:  sha,
				Size:    info.Size(),
				Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
				MTime:   info.ModTime().Unix(),
			})
			return nil
		})
	}
	return out
}

func depthOf(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/")
}

func isExecutableExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc":
		return true
	}
	return false
}
