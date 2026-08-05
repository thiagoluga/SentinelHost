package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// setupTokenFile is where the first-access token is written.
//
// Inside the data directory, which is 0700 and lives outside the document root. That
// placement is the whole mechanism: reading it requires access to the account's own
// filesystem, which is exactly the thing the person setting the panel up has and a
// visitor does not.
const setupTokenFile = "setup-token"

// SetupToken returns the token that must accompany the first-access request, creating it
// if there is none.
//
// Before this, `POST /api/setup` was guarded only by "has a password been set yet". That
// is not a check on who is asking — it is a race, and the panel is published at a
// guessable URL (`/sentinel/` is the documented example, and the .htaccess IP restriction
// ships commented out). Whoever issued the request first became the administrator and was
// handed a session immediately. `GET /api/session` even reports `password_set`, so the
// claimable state could be polled.
//
// What the winner gets is not just the panel: an administrator can point an engine's
// binary path at a file they uploaded and trigger a scan, which executes it as the hosting
// account. The window reopens if the database is ever deleted — and a webshell running as
// the account user can delete it.
//
// So first access now requires something only the account holder can read.
func SetupToken(dataDir string) (string, error) {
	path := filepath.Join(dataDir, setupTokenFile)

	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating the setup token: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("creating the data directory: %w", err)
	}
	// 0600: the token is equivalent to the panel password until it is used.
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing the setup token: %w", err)
	}
	return tok, nil
}

// clearSetupToken removes the token once the password exists.
//
// A token that outlives its purpose is a second credential nobody is watching.
func clearSetupToken(dataDir string) {
	// Failure is not worth failing the setup over: the token is refused from here on
	// because passwordSet() is true. Removing it is tidiness, not the control.
	_ = os.Remove(filepath.Join(dataDir, setupTokenFile))
}

// validSetupToken compares in constant time.
func (s *Server) validSetupToken(ctx context.Context, given string) bool {
	_ = ctx
	s.cfgMu.RLock()
	dataDir := s.cfg.General.DataDir
	s.cfgMu.RUnlock()

	want, err := os.ReadFile(filepath.Join(dataDir, setupTokenFile))
	if err != nil {
		// No token on disk and no password set means the file was removed. Refuse rather
		// than fall back to letting anyone through: an unreadable control must not become
		// an absent one.
		return false
	}
	expected := strings.TrimSpace(string(want))
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(strings.TrimSpace(given))) == 1
}
