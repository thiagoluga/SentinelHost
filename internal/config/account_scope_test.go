package config_test

import (
	"os"
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

// The furniture exclusions are anchored to the account's home at load time, so these go
// through Load with the real home — the same path a user's configuration takes.
func loadedAtHome(t *testing.T) (*config.Config, string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory on this machine")
	}
	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(home)+"]\n")
	return cfg, filepath.ToSlash(home)
}

func TestTheAccountsFurnitureIsExcluded(t *testing.T) {
	cfg, home := loadedAtHome(t)

	for _, rel := range []string{
		"mail/domain.com/cur/1234.msg",
		"mail/domain.com/cur/attachment.php", // an e-mail attachment, not the site
		"tmp/webalizer/index.html",
		"logs/access.log",
		".cpanel/userdata/main",
		".softaculous/cache.php",
		"etc/domain.com/passwd",
		"ssl/keys/private.key",
	} {
		if p := home + "/" + rel; !pathmatch.MatchAny(cfg.Limits.Exclude, p) {
			t.Errorf("%s is scanned: none of this is served by the web, and mail alone is "+
				"2.4 GB on a real account", p)
		}
	}
}

// The failure CI caught, kept as its own case.
//
// These were `**/mail/**` and `**/tmp/**`, which match a directory of that NAME at any
// depth. On Linux that excluded /tmp — where the suite builds its fixtures, so the
// 20,000-file benchmark scanned nothing — and it would exclude public_html/app/tmp/,
// which is a stock directory in Laravel and CakePHP. Live site content, silently skipped.
//
// The same mistake as D-026, D-038 and D-040: a name is not a path. Third time it was
// written down, first time it was actually made.
func TestOnlyTheHomesOwnDirectoriesAreExcludedNotEveryDirectoryOfThatName(t *testing.T) {
	cfg, home := loadedAtHome(t)

	for _, rel := range []string{
		"public_html/app/tmp/cache.php", // Laravel, CakePHP
		"public_html/tmp/upload.php",
		"public_html/mail/contact.php", // a contact form, not a maildir
		"public_html/site/logs/viewer.php",
		"public_html/etc/config.php",
	} {
		if p := home + "/" + rel; pathmatch.MatchAny(cfg.Limits.Exclude, p) {
			t.Errorf("%s is excluded because a directory in its path shares a name with an "+
				"account directory — this is live site content", p)
		}
	}

	// And nothing outside the home at all.
	for _, p := range []string{"/tmp/fixture/x.php", "/var/tmp/y.php"} {
		if pathmatch.MatchAny(cfg.Limits.Exclude, p) {
			t.Errorf("%s is excluded: the pattern reaches outside the account entirely", p)
		}
	}
}

// The one that must NOT be excluded. The trash held 11,140 of the 11,399 PHP files on the
// account this was measured against; excluding it would hide almost everything scannable
// and reward anyone who worked that out.
func TestTheTrashIsScannedRatherThanHidden(t *testing.T) {
	cfg, home := loadedAtHome(t)

	if pathmatch.MatchAny(cfg.Limits.Exclude, home+"/.trash/wordpress/wp-admin/x.php") {
		t.Error("the trash is excluded from scanning. It is where most of the PHP on a real " +
			"account lives, and an attacker who noticed would keep their payload there. " +
			"It is meant to be scanned, classified as trash, and left alone by the " +
			"automatic action instead (D-038)")
	}
}

// And the sites themselves, obviously — including a secondary domain, which is the case
// that motivated widening the scope in the first place.
func TestEverySiteIsStillScanned(t *testing.T) {
	cfg, home := loadedAtHome(t)

	for _, rel := range []string{
		"public_html/index.php",
		"public_html/seconddomain.com/wp-content/uploads/shell.php",
		"anotherdomain.com/index.php",
	} {
		p := home + "/" + rel
		if pathmatch.MatchAny(cfg.Limits.Exclude, p) {
			t.Errorf("%s is excluded — a secondary domain is exactly as executable as the "+
				"primary one", p)
		}
	}
}

// A directory whose name merely resembles one of these is the user's own. `public_html/
// mailings/` is a site directory; excluding it would hide live content.
func TestASiteDirectoryWithASimilarNameIsNotExcluded(t *testing.T) {
	cfg, home := loadedAtHome(t)

	for _, rel := range []string{
		"public_html/mailings/index.php",
		"public_html/tmpl/header.php",
		"public_html/logstash/x.php",
	} {
		p := home + "/" + rel
		if pathmatch.MatchAny(cfg.Limits.Exclude, p) {
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

// The home must be findable without the environment.
//
// os.UserHomeDir() reads $HOME on Unix, and $HOME is not always set: cron runs with a
// minimal environment, so does a CGI process, and so does the panel when a web server
// starts it. Those are not edge cases — cron is this project's default schedule mode
// precisely because shared hosting rarely keeps a daemon alive.
//
// And the failure is silent. Without a home, the account exclusions simply do not apply:
// the scan walks the maildir, reports findings about e-mail attachments, and looks
// entirely successful. Observed on a real account, where the effective exclude list came
// back holding the WordPress defaults and nothing else.
func TestTheAccountHomeIsFoundWithoutTheEnvironment(t *testing.T) {
	// Unset what os.UserHomeDir() reads, on either platform, so the fallback is what is
	// actually being measured. t.Setenv restores them when the test ends.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	fake := t.TempDir()
	for _, d := range []string{"public_html", "mail", ".cpanel", ".trash"} {
		if err := os.MkdirAll(filepath.Join(fake, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(fake)+"]\n")

	maildir := filepath.Join(fake, "mail", "domain.com", "cur", "attachment.php")
	if !pathmatch.MatchAny(cfg.Limits.Exclude, maildir) {
		t.Errorf("with no HOME in the environment the account exclusions did not apply, so "+
			"the scan walks the maildir and reports findings about e-mail attachments — "+
			"and looks entirely successful doing it.\nexclusions: %v", cfg.Limits.Exclude)
	}
	// And the sites inside that same home are still scanned.
	if pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(fake, "public_html", "index.php")) {
		t.Error("the fallback excluded the site along with the furniture")
	}
}

func TestADirectoryWithOneMarkerIsNotAnAccountHome(t *testing.T) {
	lonely := t.TempDir()
	if err := os.MkdirAll(filepath.Join(lonely, "mail"), 0o755); err != nil {
		t.Fatal(err)
	}
	if looksLikeHomeFromOutside(lonely) {
		t.Error("a directory containing only `mail` was taken for an account home; anchoring " +
			"the exclusions there would skip somebody's actual content")
	}
}

// looksLikeHomeFromOutside mirrors the package's own rule, so the test states the
// expectation independently rather than asking the code whether it agrees with itself.
func looksLikeHomeFromOutside(dir string) bool {
	found := 0
	for _, m := range []string{"public_html", ".cpanel", "mail", ".trash", "etc", "logs"} {
		if info, err := os.Stat(filepath.Join(dir, m)); err == nil && info.IsDir() {
			found++
		}
	}
	return found >= 2
}

// The tool must not spend its credibility reporting itself.
//
// The PHP bridge lives IN the document root — that is what makes the panel reachable on
// shared hosting — so the data-directory exclusion never covered it. And it genuinely
// calls exec(), because starting the panel is its whole job, so AMWScan flags it as
// `Function` on every cycle. Observed on a real account: a permanent `suspicious` finding
// about a file this project installed.
func TestOurOwnComponentsAreNotScanned(t *testing.T) {
	root := t.TempDir()
	bridge := filepath.Join(root, "sentinel")
	if err := os.MkdirAll(bridge, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bridge, ".sentinelhost-component"), []byte("ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(root)+"]\n")

	if !pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(bridge, "index.php")) {
		t.Errorf("the bridge is scanned, so it is flagged on every cycle for calling exec() "+
			"— which is its entire purpose.\nexclusions: %v", cfg.Limits.Exclude)
	}
}

// By the marker, never by the name. A scanner that trusted directory names would be told
// what to ignore by whoever it was scanning — and this is the fourth time in this project
// that a name has been mistaken for a path (D-026, D-038, D-040).
func TestADirectoryNamedLikeOursIsStillScanned(t *testing.T) {
	root := t.TempDir()
	impostor := filepath.Join(root, "sentinel")
	if err := os.MkdirAll(impostor, 0o755); err != nil {
		t.Fatal(err)
	}
	// No marker file: it is just a directory somebody named `sentinel`.

	cfg := writeConfig(t, "[general]\nroots = ["+tomlPath(root)+"]\n")

	if pathmatch.MatchAny(cfg.Limits.Exclude, filepath.Join(impostor, "shell.php")) {
		t.Error("a directory was excluded for being called `sentinel`. An attacker who read " +
			"this code would put their payload in one")
	}
}
