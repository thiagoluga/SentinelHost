// Package pathmatch matches paths against glob patterns with `**` support.
//
// The standard library's `filepath.Match` does not understand `**`, and every
// useful pattern over a site tree needs it: `**/wp-content/cache/**` is the
// natural way to say "cache at any depth". Without `**` the user would have to
// write per-level exclusions, would get one wrong, and would end up with the
// scanner walking what they thought they had excluded.
package pathmatch

import (
	"path/filepath"
	"strings"
)

// Match answers whether the path matches the pattern.
//
// Rules:
//   - `*`  matches any sequence without a separator
//   - `?`  matches one character that is not a separator
//   - `**` matches any sequence, including separators and including nothing
//   - comparison uses `/` as the separator on every operating system
//
// `**` matching nothing means `a/**` also matches `a`. That is the useful
// behaviour for exclusions: someone writing `**/cache/**` wants the `cache`
// directory gone entirely, not left behind as a stray entry in the report.
//
// Comparison is case-sensitive: Linux filesystems — the project's target — are
// case-sensitive, and ignoring that would make a whitelist entry for
// `Config.php` also protect a `config.php` an attacker planted.
func Match(pattern, path string) bool {
	// The PATTERN is always normalized: it is hand-written in the TOML, and
	// whoever edits it in a Windows editor writes `**\uploads\**` without
	// thinking. A literal backslash has no legitimate use in a glob here.
	pattern = strings.ReplaceAll(pattern, `\`, "/")

	// The PATH uses the operating system's conversion, which is a no-op on
	// Linux. Converting `\` to `/` on Linux would corrupt legitimate file
	// names — backslash is a valid character in a POSIX file name, and Linux is
	// precisely the project's target.
	path = filepath.ToSlash(path)

	return matchSegments(splitPattern(pattern), strings.Split(strings.Trim(path, "/"), "/"))
}

// MatchAny answers whether any pattern matches.
func MatchAny(patterns []string, path string) bool {
	for _, p := range patterns {
		if Match(p, path) {
			return true
		}
	}
	return false
}

// WhichMatches returns the first pattern that matches, or "".
//
// It exists because the user needs to know WHICH whitelist rule protected a
// file — "why was this file not quarantined?" is a question the tool has to
// answer precisely (Principle V).
func WhichMatches(patterns []string, path string) string {
	for _, p := range patterns {
		if Match(p, path) {
			return p
		}
	}
	return ""
}

func splitPattern(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// matchSegments matches segment by segment, backtracking on `**`.
func matchSegments(pattern, path []string) bool {
	// No pattern left: it matches if no path is left either.
	if len(pattern) == 0 {
		return len(path) == 0
	}

	if pattern[0] == "**" {
		// A trailing `**` matches everything that remains, including nothing.
		if len(pattern) == 1 {
			return true
		}
		// Try consuming 0, 1, 2... segments with the `**`.
		for i := 0; i <= len(path); i++ {
			if matchSegments(pattern[1:], path[i:]) {
				return true
			}
		}
		return false
	}

	if len(path) == 0 {
		return false
	}
	ok, err := filepath.Match(pattern[0], path[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], path[1:])
}
