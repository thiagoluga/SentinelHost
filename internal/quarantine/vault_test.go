package quarantine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

type env struct {
	vault *quarantine.Vault
	store *store.Store
	site  string
	vdir  string
}

func setup(t *testing.T) env {
	t.Helper()
	base := t.TempDir()
	site := filepath.Join(base, "public_html")
	vdir := filepath.Join(base, "quarantine")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	st, err := store.Open(context.Background(), filepath.Join(base, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Default().Quarantine
	return env{
		vault: quarantine.New(vdir, cfg, st),
		store: st,
		site:  site,
		vdir:  vdir,
	}
}

func createFile(t *testing.T, dir, name, content string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	sha, err := baseline.HashFile(path)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return path, sha
}

// SC-003: byte-for-byte round trip ---------------------------------------------

func TestTheRoundTripGivesTheFileBackByteForByte(t *testing.T) {
	// SC-003: 100% of the quarantine -> restore -> compare-hash tests have to
	// pass. It is the promise that makes the automation acceptable.
	e := setup(t)
	ctx := context.Background()

	contents := []string{
		"<?php echo 'small';",
		strings.Repeat("A", 1<<20),                      // 1 MiB
		"line1\nline2\r\nbinary:\x00\x01\x02\xff\xfe\n", // binary and CRLF
		"",                               // empty file
		"accents and emoji: café 🎯 naïve", // multibyte UTF-8
	}

	for i, content := range contents {
		name := filepath.Join("wp-content", "uploads", "sample"+string(rune('a'+i))+".php")
		path, originalSHA := createFile(t, e.site, name, content)

		item, err := e.vault.Quarantine(ctx, "v_1", path, originalSHA)
		if err != nil {
			t.Fatalf("Quarantine(%d): %v", i, err)
		}

		// The original left its place.
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("case %d: the original file is still in place", i)
		}

		restored, err := e.vault.Restore(ctx, item.Ref)
		if err != nil {
			t.Fatalf("Restore(%d): %v", i, err)
		}
		if restored.Status != store.QuarantineRestored {
			t.Errorf("case %d: status after the restore: %q", i, restored.Status)
		}

		finalSHA, err := baseline.HashFile(path)
		if err != nil {
			t.Fatalf("hash after the restore (%d): %v", i, err)
		}
		if finalSHA != originalSHA {
			t.Errorf("case %d: the file did NOT come back byte for byte: %s -> %s", i, originalSHA, finalSHA)
		}

		back, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading the restored file (%d): %v", i, err)
		}
		if string(back) != content {
			t.Errorf("case %d: different content after the restore", i)
		}
	}
}

func TestTheRestorePreservesPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions do not apply on Windows (D-002)")
	}
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	item, err := e.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if _, err := e.vault.Restore(ctx, item.Ref); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("the permissions were not restored: expected 0640, got %v", info.Mode().Perm())
	}
}

// FR-018: re-hash before acting ------------------------------------------------

func TestItRefusesToQuarantineIfTheFileChangedSinceTheScan(t *testing.T) {
	// An explicit edge case in the spec: a file that changes between the scan and
	// the action. In those minutes the user may have cleaned the file themselves.
	e := setup(t)
	ctx := context.Background()

	path, oldSHA := createFile(t, e.site, "x.php", "<?php // dirty version")
	// The user fixes the file before the action runs.
	if err := os.WriteFile(path, []byte("<?php // clean version"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := e.vault.Quarantine(ctx, "v_1", path, oldSHA)
	if !errors.Is(err, quarantine.ErrHashMismatch) {
		t.Fatalf("expected ErrHashMismatch, got %v", err)
	}
	// And most importantly: the file is still in place.
	if _, err := os.Stat(path); err != nil {
		t.Error("the user's file was touched despite the divergent hash")
	}
	content, _ := os.ReadFile(path)
	if string(content) != "<?php // clean version" {
		t.Error("the content the user fixed was altered")
	}
}

func TestAFileThatVanishedBeforeTheActionDoesNotTakeThingsDown(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	_, err := e.vault.Quarantine(ctx, "v_1", filepath.Join(e.site, "does-not-exist.php"), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, quarantine.ErrHashMismatch) {
		t.Error("a missing file is not the same as an altered file")
	}
}

// Neutralization ---------------------------------------------------------------

func TestTheFileInTheVaultIsNeutralized(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "backdoor.php", "<?php // sample")
	item, err := e.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	// Neutralized extension: if the vault ends up inside a directory served over
	// the web, the file must not be executable by the server.
	if filepath.Ext(item.VaultPath) != ".quarantined" {
		t.Errorf("the extension was not neutralized: %s", item.VaultPath)
	}
	if strings.HasSuffix(item.VaultPath, ".php") {
		t.Errorf("the file in the vault still has an executable extension: %s", item.VaultPath)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(item.VaultPath)
		if err != nil {
			t.Fatalf("stat of the vault copy: %v", err)
		}
		perm := info.Mode().Perm()
		if perm&0o111 != 0 {
			t.Errorf("the file in the vault kept its execute permission: %v", perm)
		}
		if perm&0o077 != 0 {
			t.Errorf("the file in the vault is accessible by group or others: %v", perm)
		}
		// The owner MUST be able to read it: without that, restoring and verifying
		// the vault stop working and the promise of reversibility dies. This defect
		// is invisible on Windows, which ignores POSIX permissions.
		if perm&0o400 == 0 {
			t.Errorf("the owner cannot read the copy in the vault (%v): the restore would be impossible", perm)
		}
	}

	// And the practical proof: the file is still readable by whoever will restore it.
	if _, err := os.ReadFile(item.VaultPath); err != nil {
		t.Errorf("the copy in the vault cannot be read: %v", err)
	}
}

func TestTheRestoreMetadataIsRecorded(t *testing.T) {
	// Without this metadata the file in the vault is undecipherable garbage.
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "wp-content/x.php", "<?php")
	item, err := e.vault.Quarantine(ctx, "v_42", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	stored, err := e.store.GetQuarantineItem(ctx, item.Ref)
	if err != nil {
		t.Fatalf("GetQuarantineItem: %v", err)
	}
	if stored.OriginalPath != path {
		t.Errorf("the original path was lost: %q", stored.OriginalPath)
	}
	if stored.SHA256 != sha {
		t.Errorf("the hash was lost: %q", stored.SHA256)
	}
	if stored.VerdictID != "v_42" {
		t.Errorf("the originating verdict was lost: %q", stored.VerdictID)
	}
	if stored.Perms == "" {
		t.Error("the original permissions were not recorded")
	}
	if stored.RetentionUntil.IsZero() {
		t.Error("the retention was not calculated")
	}
}

// Vault failures ---------------------------------------------------------------

func TestAVaultWithoutPermissionDoesNotDeleteTheUsersFile(t *testing.T) {
	// This is THE test that keeps the tool from destroying a site: if the vault
	// does not accept the copy, the original must NOT be removed.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions do not apply on Windows (D-002)")
	}
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php // important content")

	// A vault that exists but has no write permission.
	if err := os.MkdirAll(e.vdir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.vdir, 0o700) })

	_, err := e.vault.Quarantine(ctx, "v_1", path, sha)
	if err == nil {
		t.Fatal("expected a failure with an unwritable vault")
	}
	if !errors.Is(err, quarantine.ErrVaultUnwritable) {
		t.Errorf("expected ErrVaultUnwritable, got %v", err)
	}

	// The user's file is still intact.
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the user's file was removed despite the vault failure")
	}
	finalSHA, _ := baseline.HashFile(path)
	if finalSHA != sha {
		t.Error("the user's file was altered")
	}
}

func TestTheRestoreDoesNotOverwriteAnExistingFile(t *testing.T) {
	// If there is a file at the original path, it may be the clean version the
	// user has already put back.
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php // dirty")
	item, err := e.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := os.WriteFile(path, []byte("<?php // put back by the user"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = e.vault.Restore(ctx, item.Ref)
	if !errors.Is(err, quarantine.ErrRestoreTargetExists) {
		t.Fatalf("expected ErrRestoreTargetExists, got %v", err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "<?php // put back by the user" {
		t.Error("the file the user put back was overwritten")
	}
}

func TestTheRestoreDetectsACorruptedVault(t *testing.T) {
	// Restoring a file different from the one that was quarantined would be worse
	// than not restoring.
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php // original")
	item, err := e.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if err := os.Chmod(item.VaultPath, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.WriteFile(item.VaultPath, []byte("swapped content"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = e.vault.Restore(ctx, item.Ref)
	if !errors.Is(err, quarantine.ErrVaultCorrupted) {
		t.Fatalf("expected ErrVaultCorrupted, got %v", err)
	}
}

func TestRestoringTwiceFails(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php")
	item, _ := e.vault.Quarantine(ctx, "v_1", path, sha)
	if _, err := e.vault.Restore(ctx, item.Ref); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	if _, err := e.vault.Restore(ctx, item.Ref); !errors.Is(err, quarantine.ErrNotInVault) {
		t.Errorf("expected ErrNotInVault, got %v", err)
	}
}

// Retention and purge ----------------------------------------------------------

func TestThePurgeRefusesAnItemInsideItsRetention(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php")
	item, _ := e.vault.Quarantine(ctx, "v_1", path, sha)

	if err := e.vault.Purge(ctx, item.Ref, false); err == nil {
		t.Fatal("a purge inside the retention should have been refused")
	}
	if _, err := os.Stat(item.VaultPath); err != nil {
		t.Error("the copy in the vault was removed despite the refusal")
	}
}

func TestAManualPurgeIgnoresTheRetention(t *testing.T) {
	// The constitution allows a permanent purge by manual user action.
	e := setup(t)
	ctx := context.Background()

	path, sha := createFile(t, e.site, "x.php", "<?php")
	item, _ := e.vault.Quarantine(ctx, "v_1", path, sha)

	if err := e.vault.Purge(ctx, item.Ref, true); err != nil {
		t.Fatalf("Purge(force): %v", err)
	}
	if _, err := os.Stat(item.VaultPath); !os.IsNotExist(err) {
		t.Error("the copy should have been removed")
	}
	stored, _ := e.store.GetQuarantineItem(ctx, item.Ref)
	if stored.Status != store.QuarantinePurged {
		t.Errorf("status: %q", stored.Status)
	}
}

func TestPurgeExpiredOnlyTakesTheExpiredOnes(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	oldPath, oldSHA := createFile(t, e.site, "old.php", "<?php // old")
	newPath, newSHA := createFile(t, e.site, "new.php", "<?php // new")

	// The old item was quarantined 60 days ago (default retention: 30).
	past := time.Now().AddDate(0, 0, -60)
	old := quarantine.New(e.vdir, config.Default().Quarantine, e.store).
		WithClock(func() time.Time { return past })
	oldItem, err := old.Quarantine(ctx, "v_1", oldPath, oldSHA)
	if err != nil {
		t.Fatalf("Quarantine(old): %v", err)
	}
	newItem, err := e.vault.Quarantine(ctx, "v_2", newPath, newSHA)
	if err != nil {
		t.Fatalf("Quarantine(new): %v", err)
	}

	n, err := e.vault.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged item, got %d", n)
	}

	expired, _ := e.store.GetQuarantineItem(ctx, oldItem.Ref)
	if expired.Status != store.QuarantinePurged {
		t.Errorf("the expired item should have been purged, it is %q", expired.Status)
	}
	recent, _ := e.store.GetQuarantineItem(ctx, newItem.Ref)
	if recent.Status != store.QuarantineActive {
		t.Errorf("the recent item must not be purged, it is %q", recent.Status)
	}
	if _, err := os.Stat(newItem.VaultPath); err != nil {
		t.Error("the recent item's copy was removed")
	}
}

func TestARetentionOfZeroNeverExpires(t *testing.T) {
	// Better to occupy disk than to delete a file by mistake.
	e := setup(t)
	ctx := context.Background()

	cfg := config.Default().Quarantine
	cfg.RetentionDays = 0
	v := quarantine.New(e.vdir, cfg, e.store)

	path, sha := createFile(t, e.site, "x.php", "<?php")
	item, err := v.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if !item.RetentionUntil.IsZero() {
		t.Error("with a retention of 0 the item should have no expiry date")
	}

	n, err := v.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("an item with no expiry must not be purged automatically, got %d", n)
	}
}

// Integrity verification -------------------------------------------------------

func TestVerifyDetectsACorruptedCopy(t *testing.T) {
	// The promise of reversibility only holds if it can be checked before the
	// moment the user needs to restore.
	e := setup(t)
	ctx := context.Background()

	okPath, okSHA := createFile(t, e.site, "ok.php", "<?php // ok")
	badPath, badSHA := createFile(t, e.site, "bad.php", "<?php // bad")
	if _, err := e.vault.Quarantine(ctx, "v_1", okPath, okSHA); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	badItem, err := e.vault.Quarantine(ctx, "v_2", badPath, badSHA)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	_ = os.Chmod(badItem.VaultPath, 0o600)
	if err := os.WriteFile(badItem.VaultPath, []byte("corrupted"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	problems, err := e.vault.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problems) != 1 {
		t.Fatalf("expected 1 problem, got %d: %v", len(problems), problems)
	}
	if !strings.Contains(problems[0], badItem.Ref) {
		t.Errorf("the problem should name the item: %q", problems[0])
	}
}

func TestLevelAllowsActionOnlyForConfirmed(t *testing.T) {
	if !quarantine.LevelAllowsAction(schema.LevelConfirmed) {
		t.Error("confirmed should authorize an action")
	}
	for _, l := range []schema.Level{schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean, ""} {
		if quarantine.LevelAllowsAction(l) {
			t.Errorf("level %q must not authorize an automatic action", l)
		}
	}
}
