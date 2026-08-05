package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/thiagoluga/SentinelHost/internal/store"
)

// argon2id parameters.
//
// 64 MiB and 1 iteration with 4 threads is the "interactive" profile RFC 9106
// recommends. On shared hosting, memory is the scarcest resource — but that is
// exactly the protection that makes the hash expensive to crack, and one login per
// 12-hour session does not weigh on the account's budget.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

const sessionCookie = "sentinelhost_session"

// ErrNoPassword means the password has not been set yet.
var ErrNoPassword = errors.New("the panel password has not been set yet")

// hashPassword generates an argon2id hash in the PHC format.
func hashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating the salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword checks the password against the hash.
//
// The comparison runs in constant time. Comparing a hash with `==` would leak,
// through the response time, how many leading bytes the attacker got right.
func verifyPassword(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	// Require exactly the length hashPassword produces, and derive with the
	// constant — with no int-to-uint32 conversion at all.
	//
	// This is not formalism: deriving with a length taken from the stored hash
	// itself would let a tampered database pick the parameter, and a truncated
	// conversion would make argon2 generate a key of a different length than
	// expected, comparing incomparable things.
	if len(expected) != argonKeyLen {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, t, m, p, argonKeyLen)
	return subtle.ConstantTimeCompare(computed, expected) == 1
}

// newToken generates a session token.
func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// rateLimiter caps login attempts per IP, counting in the store rather than in memory.
//
// Without it, an exposed panel (even by accident) becomes a brute-force target, and the
// panel's single password is the only thing between the attacker and a button that moves
// the site's files.
//
// The count used to live in a map here. That works for exactly one deployment shape —
// `serve`, where a single process sees every request — and fails silently for every
// other one. Under any per-request model the map is empty on arrival, so the lock-out
// does not exist while the panel looks and behaves exactly as before, and nothing says
// the protection was switched off. Counting in the same SQLite the sessions already use
// costs one small query and removes the whole class of surprise.
type rateLimiter struct {
	store  *store.Store
	perMin int
	window time.Duration
}

func newRateLimiter(st *store.Store, perMin int) *rateLimiter {
	if perMin <= 0 {
		perMin = 10
	}
	return &rateLimiter{store: st, perMin: perMin, window: time.Minute}
}

// allow records an attempt and says whether it is permitted.
//
// A store error allows the attempt. That is the deliberate direction: a database hiccup
// must not lock the legitimate owner out of their own panel, and the failure is loud
// enough elsewhere. The opposite default would turn a transient error into a denial of
// service against the one person entitled to log in.
func (r *rateLimiter) allow(ctx context.Context, ip string, now time.Time) bool {
	recent, err := r.store.RecentLoginAttempts(ctx, ip, now.Add(-r.window))
	if err != nil {
		return true
	}
	if len(recent) >= r.perMin {
		// Rewritten anyway, so the window keeps sliding rather than pinning an IP
		// forever on the strength of one old burst.
		_ = r.store.RecordLoginAttempt(ctx, ip, recent)
		return false
	}
	_ = r.store.RecordLoginAttempt(ctx, ip, append(recent, now))
	return true
}

// reset clears an IP's history after a successful login.
func (r *rateLimiter) reset(ctx context.Context, ip string) {
	_ = r.store.ClearLoginAttempts(ctx, ip)
}

// clientIP extracts the request's IP.
//
// It does NOT trust X-Forwarded-For: the panel listens on localhost by default,
// and accepting a header the client controls would let any attacker reset their own
// attempt limit by sending a different IP on every request.
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// authenticated answers whether the request has a valid session.
func (s *Server) authenticated(req *http.Request) bool {
	c, err := req.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	ok, err := s.store.SessionValid(req.Context(), c.Value)
	return err == nil && ok
}

// passwordSet answers whether a password has already been set.
func (s *Server) passwordSet(ctx context.Context) bool {
	h, err := s.store.GetSetting(ctx, store.KeyPanelPasswordHash)
	if err != nil {
		// Fail CLOSED. This value gates /api/setup, so answering "no password is set"
		// because the database could not be read would reopen first access on a panel
		// that already has an owner. GetSetting maps a missing row to ("", nil), so a
		// real error here means the store is broken, not that the panel is new.
		return true
	}
	return h != ""
}

// setCookie writes the session cookie.
func (s *Server) setCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		// SameSite=Strict: the panel has actions that move files. A malicious link
		// in another tab must not be able to carry the credential along.
		SameSite: http.SameSiteStrictMode,
		// Secure only when there is real TLS. Marking Secure on a panel accessed
		// over http://127.0.0.1 would make the browser drop the cookie and the
		// login would never work.
		Secure: secure,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}
