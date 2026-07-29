// Package quarantine implements the reversible vault.
//
// This package is where Principle I lives: quarantine means move + record +
// block, NEVER delete. A false positive handled here can never take the user's
// site down permanently.
//
// The order of operations is not negotiable:
//  1. re-hash the file IMMEDIATELY before acting (FR-018)
//  2. copy it into the vault
//  3. verify the copy is intact
//  4. only then remove the original
//
// Swapping 3 and 4 would mean, on a full disk, deleting the user's file and
// keeping a truncated copy. That is the only way this tool could destroy a site —
// which is why the order is written down here and tested.
package quarantine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

var (
	// ErrHashMismatch means the file changed between the scan and the action.
	ErrHashMismatch = errors.New("the file changed since the scan")
	// ErrVaultUnwritable means the vault has no permission, or the disk is full.
	ErrVaultUnwritable = errors.New("could not write to the quarantine vault")
	// ErrNotInVault means the item does not exist or was already restored.
	ErrNotInVault = errors.New("the item is not in the vault")
	// ErrRestoreTargetExists means a file already exists at the original path.
	ErrRestoreTargetExists = errors.New("a file already exists at the original path")
	// ErrVaultCorrupted means the copy in the vault does not match the recorded
	// hash.
	ErrVaultCorrupted = errors.New("the copy in the vault does not match the recorded hash")
)

// Vault is the quarantine vault.
type Vault struct {
	dir   string
	cfg   config.QuarantineConfig
	store *store.Store
	// now is injectable in the retention tests.
	now func() time.Time
}

// New creates the vault.
func New(dir string, cfg config.QuarantineConfig, st *store.Store) *Vault {
	return &Vault{dir: dir, cfg: cfg, store: st, now: time.Now}
}

// WithClock swaps the clock. Tests only.
func (v *Vault) WithClock(fn func() time.Time) *Vault {
	v.now = fn
	return v
}

// Dir returns the vault's directory.
func (v *Vault) Dir() string { return v.dir }

// Quarantine neutralizes a file reversibly.
//
// expectedSHA is the hash the verdict saw. If the file changed since then, the
// function refuses to act and returns ErrHashMismatch — the caller should re-scan
// rather than quarantine blindly (an explicit edge case in the spec).
func (v *Vault) Quarantine(ctx context.Context, verdictID, path, expectedSHA string) (store.QuarantineItem, error) {
	var item store.QuarantineItem

	// 1. Re-hash IMMEDIATELY before acting. There is no shortcut here: the
	//    verdict's hash may be minutes old, and in those minutes the user may have
	//    fixed the file themselves.
	current, err := baseline.HashFile(path)
	if err != nil {
		return item, fmt.Errorf("could not re-read the file before acting: %w", err)
	}
	if expectedSHA != "" && current != expectedSHA {
		return item, fmt.Errorf("%w: the verdict saw %s, the disk has %s", ErrHashMismatch, short(expectedSHA), short(current))
	}

	info, err := os.Stat(path)
	if err != nil {
		return item, fmt.Errorf("reading the file's metadata: %w", err)
	}

	ref, err := newRef(v.now())
	if err != nil {
		return item, err
	}

	// Neutralized extension: if the vault ends up inside a directory served over
	// the web (the user pointed data_dir at public_html), the file must not be
	// executable by the server.
	vaultPath := filepath.Join(v.vaultSubdir(), ref+v.neutralizedExt())
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		return item, fmt.Errorf("%w: %v", ErrVaultUnwritable, err)
	}

	// 2 and 3. Copy and verify BEFORE touching the original.
	copiedSHA, size, err := copyAndVerify(path, vaultPath)
	if err != nil {
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("%w: %v", ErrVaultUnwritable, err)
	}
	if copiedSHA != current {
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("%w: the copy came out with hash %s, the original has %s",
			ErrVaultUnwritable, short(copiedSHA), short(current))
	}

	// Neutralization: no execution, no writing, and no access at all for group or
	// others. The vault directory is already 0700 and the extension has already
	// been swapped; this closes the last path.
	//
	// 0400 rather than 0000 on purpose: the owner has to be able to READ the copy
	// in order to restore it and for `quarantine verify` to check the hash. With
	// 0000 the promise of reversibility dies on any system that honours POSIX
	// permissions — and Windows does not, which is what makes this defect go
	// unnoticed on the workstation and show up only in production.
	if err := os.Chmod(vaultPath, 0o400); err != nil {
		// Not fatal: on some filesystems chmod fails. The file is already
		// neutralized by the extension and by the 0700 directory.
		_ = err
	}

	item = store.QuarantineItem{
		Ref:            ref,
		VerdictID:      verdictID,
		OriginalPath:   path,
		VaultPath:      vaultPath,
		SHA256:         current,
		SizeBytes:      size,
		Perms:          fmt.Sprintf("%04o", info.Mode().Perm()),
		Owner:          ownerOf(info),
		OriginalMTime:  info.ModTime(),
		QuarantinedAt:  v.now(),
		RetentionUntil: v.retentionUntil(),
		Status:         store.QuarantineActive,
	}

	// 4. Record it BEFORE removing the original. If the process dies between the
	//    record and the removal, what is left is a recorded item with the file
	//    still in place — harmless and detectable. In the reverse order, what would
	//    be left is a file in the vault with no record of how to restore it:
	//    undecipherable garbage.
	if err := v.store.InsertQuarantineItem(ctx, item); err != nil {
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("recording the quarantine item: %w", err)
	}

	if err := os.Remove(path); err != nil {
		// The file is still in place and the item is recorded. Mark it as a failure
		// so the panel shows "could not neutralize" instead of lying that it
		// quarantined.
		_ = v.store.ForcePurge(ctx, ref)
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("the copy was made but the original %s could not be removed: %w", path, err)
	}

	return item, nil
}

// Restore puts the file back at its original path, byte for byte.
func (v *Vault) Restore(ctx context.Context, ref string) (store.QuarantineItem, error) {
	item, err := v.store.GetQuarantineItem(ctx, ref)
	if err != nil {
		return item, err
	}
	if item.Status != store.QuarantineActive {
		return item, fmt.Errorf("%w: %s is marked as %q", ErrNotInVault, ref, item.Status)
	}

	// Is the copy in the vault still what we recorded? Restoring a file different
	// from the one that was quarantined would be worse than not restoring.
	current, err := baseline.HashFile(item.VaultPath)
	if err != nil {
		return item, fmt.Errorf("reading the copy in the vault: %w", err)
	}
	if current != item.SHA256 {
		return item, fmt.Errorf("%w: recorded %s, the vault has %s",
			ErrVaultCorrupted, short(item.SHA256), short(current))
	}

	// It overwrites nothing: if there is a file at the original path, it may be the
	// clean version the user has already put back.
	if _, err := os.Stat(item.OriginalPath); err == nil {
		return item, fmt.Errorf("%w: %s", ErrRestoreTargetExists, item.OriginalPath)
	}

	if err := os.MkdirAll(filepath.Dir(item.OriginalPath), 0o755); err != nil {
		return item, fmt.Errorf("re-creating the destination directory: %w", err)
	}

	restoredSHA, _, err := copyAndVerify(item.VaultPath, item.OriginalPath)
	if err != nil {
		_ = os.Remove(item.OriginalPath)
		return item, fmt.Errorf("restoring the file: %w", err)
	}
	if restoredSHA != item.SHA256 {
		_ = os.Remove(item.OriginalPath)
		return item, fmt.Errorf("%w: the restore came out with hash %s", ErrVaultCorrupted, short(restoredSHA))
	}

	// Original permissions and mtime: restoring has to give the file back exactly
	// as it was, not "similar to how it was".
	if perm, err := parsePerms(item.Perms); err == nil {
		_ = os.Chmod(item.OriginalPath, perm)
	}
	if !item.OriginalMTime.IsZero() {
		_ = os.Chtimes(item.OriginalPath, item.OriginalMTime, item.OriginalMTime)
	}

	if err := v.store.MarkRestored(ctx, ref, item.OriginalPath); err != nil {
		return item, fmt.Errorf("recording the restore: %w", err)
	}

	// The copy leaves the vault only after the record confirms the restore.
	if err := os.Remove(item.VaultPath); err != nil && !os.IsNotExist(err) {
		// An orphaned copy in the vault wastes disk, it is not a risk. Do not fail
		// the restore over it.
		_ = err
	}

	item.Status = store.QuarantineRestored
	item.RestoredAt = v.now()
	item.RestoredTo = item.OriginalPath
	return item, nil
}

// Purge removes an item for good.
//
// force ignores the retention and exists because the constitution allows a
// permanent purge by manual user action. Without force, only expired items pass.
func (v *Vault) Purge(ctx context.Context, ref string, force bool) error {
	item, err := v.store.GetQuarantineItem(ctx, ref)
	if err != nil {
		return err
	}
	if item.Status != store.QuarantineActive {
		return fmt.Errorf("%w: %s is marked as %q", ErrNotInVault, ref, item.Status)
	}

	if force {
		if err := v.store.ForcePurge(ctx, ref); err != nil {
			return err
		}
	} else {
		// The store refuses an item still inside its retention. It is the last
		// barrier before an irreversible action.
		if err := v.store.MarkPurged(ctx, ref, v.now()); err != nil {
			return err
		}
	}

	if err := os.Remove(item.VaultPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing the copy from the vault: %w", err)
	}
	return nil
}

// PurgeExpired removes the items whose retention has passed.
//
// It returns how many were purged. It only runs when auto_purge is on — the
// default is off, because deleting the user's file is their decision.
func (v *Vault) PurgeExpired(ctx context.Context) (int, error) {
	items, err := v.store.ExpiredItems(ctx, v.now())
	if err != nil {
		return 0, err
	}
	n := 0
	var failures []error
	for _, it := range items {
		if err := v.Purge(ctx, it.Ref, false); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", it.Ref, err))
			continue
		}
		n++
	}
	return n, errors.Join(failures...)
}

// Verify checks the integrity of every active item in the vault.
//
// It exists because the promise of reversibility only holds if it can be checked:
// a vault with corrupted copies finds that out at the very moment the user most
// needs to restore.
func (v *Vault) Verify(ctx context.Context) ([]string, error) {
	items, err := v.store.ListQuarantineItems(ctx, store.QuarantineActive, 0)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, it := range items {
		current, err := baseline.HashFile(it.VaultPath)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: unreadable copy at %s (%v)", it.Ref, it.VaultPath, err))
			continue
		}
		if current != it.SHA256 {
			problems = append(problems, fmt.Sprintf("%s: the hash diverges (recorded %s, vault %s)",
				it.Ref, short(it.SHA256), short(current)))
		}
	}
	return problems, nil
}

// Helpers ---------------------------------------------------------------------

func (v *Vault) vaultSubdir() string {
	t := v.now()
	return filepath.Join(v.dir, t.Format("2006"), t.Format("01"))
}

func (v *Vault) neutralizedExt() string {
	if v.cfg.NeutralizedExtension == "" {
		return ".quarantined"
	}
	if !strings.HasPrefix(v.cfg.NeutralizedExtension, ".") {
		return "." + v.cfg.NeutralizedExtension
	}
	return v.cfg.NeutralizedExtension
}

func (v *Vault) retentionUntil() time.Time {
	if v.cfg.RetentionDays <= 0 {
		// With no retention configured the item never expires on its own. Better to
		// occupy disk than to delete a file by mistake.
		return time.Time{}
	}
	return v.now().AddDate(0, 0, v.cfg.RetentionDays)
}

// newRef generates a unique, time-sortable reference.
func newRef(t time.Time) (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating the quarantine reference: %w", err)
	}
	return fmt.Sprintf("q_%s_%s", t.UTC().Format("20060102150405"), hex.EncodeToString(buf)), nil
}

// copyAndVerify copies source->destination and returns the sha256 of what was
// WRITTEN.
//
// The hash is computed over the write stream, not over the source: that is how a
// full disk, a partial write and corruption along the way get detected.
func copyAndVerify(source, destination string) (string, int64, error) {
	src, err := os.Open(source) // path comes from the verdict over the configured root
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}

	h := newHasher()
	n, copyErr := io.Copy(io.MultiWriter(dst, h), src)
	if copyErr != nil {
		_ = dst.Close()
		return "", 0, copyErr
	}
	// Sync before declaring success: without it, "I copied" only means "I handed it
	// to the system cache", and a kill of the process would take the user's only
	// copy of the file with it.
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return "", 0, err
	}
	if err := dst.Close(); err != nil {
		return "", 0, err
	}
	return h.hex(), n, nil
}

func parsePerms(s string) (os.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(s, "%o", &mode); err != nil {
		return 0, err
	}
	return os.FileMode(mode), nil
}

func short(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

// LevelAllowsAction answers whether a level authorizes an automatic quarantine.
//
// Only confirmed. Repeated here, alongside schema.Verdict.Actionable(), so that
// whoever calls this package directly also goes through the same rule.
func LevelAllowsAction(l schema.Level) bool {
	return l == schema.LevelConfirmed
}
