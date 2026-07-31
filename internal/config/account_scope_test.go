package config_test

import (
	"path/filepath"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
)

// Scanning a whole hosting account is the right scope: a webshell in a secondary domain
// is exactly as executable as one in the primary, and watching a single document root
// leaves the rest invisible.
//
// An account is not only sites, though, and the numbers from a real one are lopsided —
// mail 9,206 files and 2.4 GB, tmp 5,655 and 338 MB, none of it served by the web and
// none of it executable. The 98 "PHP files" under mail/ are e-mail attachments.
//
// What must not happen is the correction going too far. These are exclusions, counted and
// reported; the trash is not among them, because it holds almost all the PHP on that
// account and hiding it would be a gift to anyone who noticed.

// The furniture exclusions are static defaults, so Default() is enough here. The
// data-dir one is derived at load time and goes through Load below.
func defaults(t *testing.T) *config.Config {
	t.Helper()
	return config.Default()
}

func TestTheAccountsFurnitureIsExcluded(t *testing.T) {
	ex := defaults(t).Limits.Exclude

	for _, p := range []string{
		"/home/u/mail/domain.com/cur/1234.msg",
		"/home/u/mail/domain.com/cur/attachment.php", // an e-mail attachment, not the site
		"/home/u/tmp/webalizer/index.html",
		"/home/u/logs/access.log",
		"/home/u/.cpanel/userdata/main",
		"/home/u/.softaculous/cache.php",
		"/home/u/etc/domain.com/passwd",
		"/home/u/ssl/keys/private.key",
	} {
		if !pathmatch.MatchAny(ex, p) {
			t.Errorf("%s is scanned: none of this is served by the web, and mail alone is "+
				"2.4 GB on a real account", p)
		}
	}
}

// The one that must NOT be excluded. The trash held 11,140 of the 11,399 PHP files on the
// account this was measured against; excluding it would hide almost everything scannable
// and reward anyone who worked that out.
func TestTheTrashIsScannedRatherThanHidden(t *testing.T) {
	ex := defaults(t).Limits.Exclude

	if pathmatch.MatchAny(ex, "/home/u/.trash/wordpress/wp-admin/x.php") {
		t.Error("the trash is excluded from scanning. It is where most of the PHP on a real " +
			"account lives, and an attacker who noticed would keep their payload there. " +
			"It is meant to be scanned, classified as trash, and left alone by the " +
			"automatic action instead (D-038)")
	}
}

// And the sites themselves, obviously — including a secondary domain, which is the case
// that motivated widening the scope in the first place.
func TestEverySiteIsStillScanned(t *testing.T) {
	ex := defaults(t).Limits.Exclude

	for _, p := range []string{
		"/home/u/public_html/index.php",
		"/home/u/public_html/seconddomain.com/wp-content/uploads/shell.php",
		"/home/u/anotherdomain.com/index.php",
	} {
		if pathmatch.MatchAny(ex, p) {
			t.Errorf("%s is excluded — a secondary domain is exactly as executable as the "+
				"primary one", p)
		}
	}
}

// A directory whose name merely resembles one of these is the user's own. `public_html/
// mailings/` is a site directory; excluding it would hide live content.
func TestASiteDirectoryWithASimilarNameIsNotExcluded(t *testing.T) {
	ex := defaults(t).Limits.Exclude

	for _, p := range []string{
		"/home/u/public_html/mailings/index.php",
		"/home/u/public_html/tmpl/header.php",
		"/home/u/public_html/logstash/x.php",
	} {
		if pathmatch.MatchAny(ex, p) {
			t.Errorf("%s is excluded because its name resembles an account directory; this "+
				"is the user's own content, inside a served root", p)
		}
	}
}

// The exclusions must not swallow our own data directory's protection, which is derived
// from the configured path rather than a name (D-026).
func TestOurOwnDataDirectoryIsStillExcludedByPath(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, "my-scanner")
	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(home)+
		"]\ndata_dir = "+tomlPath(data)+"\n")

	if !pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(data, "quarantine", "x")) {
		t.Error("a data directory with a name of its own is no longer excluded")
	}
}
