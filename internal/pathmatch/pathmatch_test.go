package pathmatch_test

import (
	"runtime"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern  string
		path     string
		expected bool
		why      string
	}{
		// ** at any depth — the reason this package exists.
		{"**/wp-content/cache/**", "/home/u/public_html/wp-content/cache/a/b/c.php", true, "cache at depth"},
		{"**/wp-content/cache/**", "/home/u/wp-content/cache/x.php", true, "shallow cache"},
		{"**/wp-content/cache/**", "/home/u/wp-content/cache", true, "a trailing `**` matches zero segments, so the directory itself is excluded too"},
		{"**/node_modules/**", "/site/a/b/node_modules/pkg/index.js", true, "nested node_modules"},

		// * does not cross a separator.
		{"/home/*/public_html/x.php", "/home/user/public_html/x.php", true, "one level"},
		{"/home/*/public_html/x.php", "/home/a/b/public_html/x.php", false, "* does not cross a separator"},

		// Extensions.
		{"**/uploads/**/*.jpg", "/site/wp-content/uploads/2026/07/photo.jpg", true, "extension at depth"},
		{"**/uploads/**/*.jpg", "/site/wp-content/uploads/2026/07/x.php", false, "wrong extension"},

		// ? matches one character.
		{"/site/x?.php", "/site/x1.php", true, "question mark"},
		{"/site/x?.php", "/site/x12.php", false, "question mark matches only one"},

		// ** at the end matches nothing.
		{"/site/**", "/site", true, "** matches empty"},
		{"/site/**", "/site/a/b/c", true, "** matches several"},

		// Exact path.
		{"/site/wp-config.php", "/site/wp-config.php", true, "exact"},
		{"/site/wp-config.php", "/site/wp-config.php.bak", false, "a prefix is not enough"},
	}

	for _, c := range cases {
		if got := pathmatch.Match(c.pattern, c.path); got != c.expected {
			t.Errorf("Match(%q, %q) = %v, expected %v (%s)", c.pattern, c.path, got, c.expected, c.why)
		}
	}
}

func TestMatchIsCaseSensitive(t *testing.T) {
	// Ignoring case would make a whitelist entry for Config.php also protect the
	// config.php an attacker planted.
	if pathmatch.Match("/site/Config.php", "/site/config.php") {
		t.Error("comparison should be case-sensitive")
	}
}

func TestPatternWithBackslashIsNormalized(t *testing.T) {
	// Whoever edits the TOML in a Windows editor writes `**\uploads\**` without
	// thinking.
	if !pathmatch.Match(`**\uploads\**`, "/site/wp-content/uploads/2026/x.php") {
		t.Error("a pattern with backslashes should be normalized")
	}
}

func TestPathUsesTheSystemSeparator(t *testing.T) {
	// The path follows the operating system's convention. On Windows the walker
	// produces backslashes and they have to match; on Linux a backslash is a
	// valid character in a file name and must NOT be rewritten — converting
	// would corrupt legitimate names.
	if runtime.GOOS == "windows" {
		if !pathmatch.Match("**/uploads/**", `C:\site\wp-content\uploads\2026\x.php`) {
			t.Error("on Windows a path with backslashes should match")
		}
		return
	}
	// On Linux this "path" is a single file name with backslashes inside it, and
	// must not be mistaken for a hierarchy.
	if pathmatch.Match("**/uploads/**", `file\weird\uploads\x.php`) {
		t.Error("on Linux a backslash must not be treated as a separator")
	}
}

func TestWhichMatchesNamesTheRuleThatProtected(t *testing.T) {
	// The user needs to know WHICH whitelist rule protected a file.
	patterns := []string{
		"**/node_modules/**",
		"**/wp-content/plugins/my-plugin/**",
		"**/vendor/**",
	}
	got := pathmatch.WhichMatches(patterns, "/site/wp-content/plugins/my-plugin/loader.php")
	if got != "**/wp-content/plugins/my-plugin/**" {
		t.Errorf("expected the plugin rule, got %q", got)
	}
	if pathmatch.WhichMatches(patterns, "/site/index.php") != "" {
		t.Error("a path with no matching rule should return empty")
	}
}

func TestMatchAny(t *testing.T) {
	patterns := []string{"**/cache/**", "**/*.log"}
	if !pathmatch.MatchAny(patterns, "/site/var/cache/x.php") {
		t.Error("should match the first pattern")
	}
	if !pathmatch.MatchAny(patterns, "/site/debug.log") {
		t.Error("should match the second pattern")
	}
	if pathmatch.MatchAny(patterns, "/site/index.php") {
		t.Error("should not match")
	}
	if pathmatch.MatchAny(nil, "/site/index.php") {
		t.Error("an empty list matches nothing")
	}
}
