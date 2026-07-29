package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
	"github.com/thiagoluga/SentinelHost/internal/web"
)

// This file covers SC-004 through the HTTP API, with no browser (DECISIONS.md
// D-017): first access -> set the password -> see a finding -> decide -> configure
// e-mail -> trigger a webhook test.
//
// What it does NOT cover, stated plainly: rendering, layout and the part of SC-004
// that is real usability. That remains manual validation.

type panel struct {
	srv    *httptest.Server
	http   *http.Client
	cfg    *config.Config
	store  *store.Store
	site   string
	cfgDir string
}

func setupPanel(t *testing.T) *panel {
	t.Helper()
	ctx := context.Background()
	base := t.TempDir()
	site := filepath.Join(base, "public_html")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := config.Default()
	cfg.General.Roots = []string{site}
	cfg.General.DataDir = filepath.Join(base, "data")
	cfg.SetPath(filepath.Join(base, "config.toml"))
	if err := cfg.EnsureDataDirs(); err != nil {
		t.Fatalf("EnsureDataDirs: %v", err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	st, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	reg := adapter.NewRegistry()
	vault := quarantine.New(cfg.QuarantineDir(), cfg.Quarantine, st)
	disp := alert.NewDispatcher(ctx, cfg, st)
	runner := cycle.New(cfg, st, reg, vault)

	srv := httptest.NewServer(web.New(cfg, st, reg, vault, disp, runner).Handler())
	t.Cleanup(srv.Close)

	// A client with a cookie jar: the panel authenticates with a session cookie.
	jar := &simpleJar{cookies: map[string]*http.Cookie{}}
	return &panel{
		srv: srv, http: &http.Client{Jar: jar, Timeout: 30 * time.Second},
		cfg: cfg, store: st, site: site, cfgDir: base,
	}
}

// simpleJar is a minimal cookie jar (net/http/cookiejar requires a public-suffix
// list, which makes no sense for 127.0.0.1).
type simpleJar struct{ cookies map[string]*http.Cookie }

func (j *simpleJar) SetCookies(_ *urlURL, cookies []*http.Cookie) {
	for _, c := range cookies {
		if c.MaxAge < 0 {
			delete(j.cookies, c.Name)
			continue
		}
		j.cookies[c.Name] = c
	}
}

func (j *simpleJar) Cookies(_ *urlURL) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		out = append(out, c)
	}
	return out
}

func (p *panel) req(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	var err error
	if body != nil {
		b, _ := json.Marshal(body)
		r, err = http.NewRequest(method, p.srv.URL+path, bytes.NewReader(b))
		if r != nil {
			r.Header.Set("Content-Type", "application/json")
		}
	} else {
		r, err = http.NewRequest(method, p.srv.URL+path, nil)
	}
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}

	resp, err := p.http.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestSC004TheCompletePanelFlow walks the non-technical user's path.
func TestSC004TheCompletePanelFlow(t *testing.T) {
	p := setupPanel(t)
	ctx := context.Background()

	// 1. Before anything else, the panel is closed.
	st, _ := p.req(t, "GET", "/api/session", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/session: %d", st)
	}
	st, _ = p.req(t, "GET", "/api/status", nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("the API should require authentication, got %d", st)
	}

	// 2. First access: set the password.
	st, body := p.req(t, "POST", "/api/setup", map[string]any{"password": "short"})
	if st != http.StatusBadRequest {
		t.Fatalf("a short password should be refused, got %d", st)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "10 characters") {
		t.Errorf("the message should explain the minimum, got %q", msg)
	}

	st, _ = p.req(t, "POST", "/api/setup", map[string]any{"password": "strong-test-password"})
	if st != http.StatusOK {
		t.Fatalf("setup: %d", st)
	}

	// 3. Setting the password already authenticates; the API opens.
	st, status := p.req(t, "GET", "/api/status", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/status after setup: %d", st)
	}
	// The coverage always travels with the summary.
	if _, ok := status["engines"]; !ok {
		t.Error("the status should carry the engines' coverage")
	}
	if _, ok := status["automatic_action"]; !ok {
		t.Error("the status should say whether the automatic action is allowed")
	}

	// 4. A second setup is refused: otherwise anyone who reached the port could
	//    reset the password.
	st, _ = p.req(t, "POST", "/api/setup", map[string]any{"password": "some-other-password"})
	if st != http.StatusConflict {
		t.Fatalf("resetting the password through /api/setup should be refused, got %d", st)
	}

	// 5. A pending finding shows up in the list.
	file := filepath.Join(p.site, "backdoor.php")
	if err := os.WriteFile(file, []byte("<?php // test sample\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	v := createVerdict(t, ctx, p.store, file)

	st, list := p.req(t, "GET", "/api/verdicts?pending=1", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/verdicts: %d", st)
	}
	vs, _ := list["verdicts"].([]any)
	if len(vs) != 1 {
		t.Fatalf("expected 1 pending finding, got %d", len(vs))
	}

	// 6. The detail carries the votes: that is what answers "why this file?".
	st, detail := p.req(t, "GET", "/api/verdicts/"+v.VerdictID, nil)
	if st != http.StatusOK {
		t.Fatalf("GET detail: %d", st)
	}
	dv, _ := detail["verdict"].(map[string]any)
	votes, _ := dv["votes"].([]any)
	if len(votes) == 0 {
		t.Error("the verdict's detail came back with no votes")
	}

	// 7. Decide: quarantine.
	st, dec := p.req(t, "POST", "/api/verdicts/"+v.VerdictID+"/decide",
		map[string]any{"action": "quarantine"})
	if st != http.StatusOK {
		t.Fatalf("deciding to quarantine: %d (%v)", st, dec)
	}
	ref, _ := dec["quarantine_ref"].(string)
	if ref == "" {
		t.Fatal("the quarantine did not return the reference")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("the file should have left its place")
	}

	// 8. The item shows up in the quarantine and comes back byte for byte.
	st, vault := p.req(t, "GET", "/api/quarantine", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/quarantine: %d", st)
	}
	items, _ := vault["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 item in the vault, got %d", len(items))
	}

	st, rest := p.req(t, "POST", "/api/quarantine/"+ref+"/restore", nil)
	if st != http.StatusOK {
		t.Fatalf("restoring: %d (%v)", st, rest)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("the file did not come back: %v", err)
	}
	if string(content) != "<?php // test sample\n" {
		t.Error("the file did not come back byte for byte")
	}

	// 9. Configure e-mail from the panel — and the TOML has to reflect it (FR-014).
	st, _ = p.req(t, "PUT", "/api/config", map[string]any{
		"email": map[string]any{
			"enabled": true,
			"host":    "smtp.example.test",
			"port":    587,
			"from":    "sentinel@example.test",
			"to":      []string{"owner@example.test"},
			"levels":  []string{"confirmed"},
		},
	})
	if st != http.StatusOK {
		t.Fatalf("PUT /api/config: %d", st)
	}

	fromDisk, err := config.Load(p.cfg.Path())
	if err != nil {
		t.Fatalf("re-reading the TOML: %v", err)
	}
	if !fromDisk.Alerts.Email.Enabled || fromDisk.Alerts.Email.Host != "smtp.example.test" {
		t.Errorf("the panel's change did not reach the TOML: %+v", fromDisk.Alerts.Email)
	}

	// 10. Secrets never leave through the API.
	st, cfgResp := p.req(t, "GET", "/api/config", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /api/config: %d", st)
	}
	if strings.Contains(mustJSON(t, cfgResp), "strong-test-password") {
		t.Error("the panel's password leaked through the configuration API")
	}

	// 11. Webhook test: the REAL result goes to the screen.
	rec := &receiver{status: http.StatusTeapot}
	hookSrv := httptest.NewServer(rec.handler())
	defer hookSrv.Close()

	st, _ = p.req(t, "PUT", "/api/config", map[string]any{
		"webhooks": []map[string]any{{
			"id": "my-hook", "enabled": true, "url": hookSrv.URL,
			"secret": "s3cr3t", "events": []string{"verdict.confirmed"},
		}},
	})
	if st != http.StatusOK {
		t.Fatalf("saving the webhook: %d", st)
	}

	st, test := p.req(t, "POST", "/api/alert/test",
		map[string]any{"channel": "webhook", "id": "my-hook"})
	if st != http.StatusOK {
		t.Fatalf("webhook test: %d", st)
	}
	if ok, _ := test["ok"].(bool); ok {
		t.Error("the test should have failed with HTTP 418")
	}
	if hs, _ := test["http_status"].(float64); int(hs) != http.StatusTeapot {
		t.Errorf("the endpoint's real status should show up, got %v", test["http_status"])
	}

	// 12. Signing out closes the panel.
	st, _ = p.req(t, "POST", "/api/logout", nil)
	if st != http.StatusOK {
		t.Fatalf("logout: %d", st)
	}
	st, _ = p.req(t, "GET", "/api/status", nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("after signing out the API should close, got %d", st)
	}
}

func TestThePanelRequiresATextualConfirmationToPurge(t *testing.T) {
	p := setupPanel(t)
	ctx := context.Background()
	authenticate(t, p)

	file := filepath.Join(p.site, "x.php")
	if err := os.WriteFile(file, []byte("<?php\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	v := createVerdict(t, ctx, p.store, file)
	_, dec := p.req(t, "POST", "/api/verdicts/"+v.VerdictID+"/decide",
		map[string]any{"action": "quarantine"})
	ref, _ := dec["quarantine_ref"].(string)

	// An accidental click must not be enough for the only irreversible operation.
	st, _ := p.req(t, "POST", "/api/quarantine/"+ref+"/purge", map[string]any{"confirm": "yes"})
	if st != http.StatusBadRequest {
		t.Fatalf("a purge without the exact word should be refused, got %d", st)
	}
	item, err := p.store.GetQuarantineItem(ctx, ref)
	if err != nil || item.Status != store.QuarantineActive {
		t.Fatalf("the item should still be in the vault: %+v (%v)", item, err)
	}

	st, _ = p.req(t, "POST", "/api/quarantine/"+ref+"/purge", map[string]any{"confirm": "purge"})
	if st != http.StatusOK {
		t.Fatalf("confirmed purge: %d", st)
	}
}

func TestThePanelLimitsLoginAttempts(t *testing.T) {
	// With no limit, a panel exposed by accident becomes a brute-force target.
	p := setupPanel(t)
	st, _ := p.req(t, "POST", "/api/setup", map[string]any{"password": "strong-test-password"})
	if st != http.StatusOK {
		t.Fatalf("setup: %d", st)
	}
	_, _ = p.req(t, "POST", "/api/logout", nil)

	limit := p.cfg.Web.LoginRateLimit
	blocked := false
	for i := 0; i < limit+3; i++ {
		st, _ := p.req(t, "POST", "/api/login", map[string]any{"password": "wrong"})
		if st == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Errorf("the panel accepted more than %d attempts in a row without blocking", limit)
	}
}

func TestThePanelAppliesTheSecurityHeaders(t *testing.T) {
	p := setupPanel(t)
	resp, err := p.http.Get(p.srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The CSP is the last barrier: the panel displays paths chosen by the attacker.
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP with no restricted script-src: %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("the CSP allows inline script")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("the panel can be embedded in an iframe")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff is missing")
	}
	if !strings.Contains(resp.Header.Get("X-Robots-Tag"), "noindex") {
		t.Error("the panel could be indexed")
	}
}

// TestThePanelSupportsConcurrentConfigAndScan exists for CI's `-race`.
//
// The panel EDITS the configuration while a cycle triggered by /api/scan READS it —
// shared maps and slices, with no synchronization at all in the first version. The
// race detector only reports it if both really happen at the same time, and no other
// test does that.
func TestThePanelSupportsConcurrentConfigAndScan(t *testing.T) {
	p := setupPanel(t)
	authenticate(t, p)

	const rounds = 12
	ready := make(chan struct{})
	var wg sync.WaitGroup

	// Configuration writers.
	for i := 0; i < rounds; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-ready
			// Every write touches slices and maps — exactly what a shallow copy would
			// share with whoever is reading.
			st, _ := p.req(t, "PUT", "/api/config", map[string]any{
				"whitelist": []string{fmt.Sprintf("**/plugin-%d/**", n)},
				"exclude":   []string{fmt.Sprintf("**/cache-%d/**", n)},
				"engines": map[string]any{
					"amwscan": map[string]any{"weight": 0.5 + float64(n)/100},
				},
			})
			// 409 is a legitimate answer: a scan is holding the configuration.
			if st != http.StatusOK && st != http.StatusConflict {
				t.Errorf("PUT /api/config returned %d", st)
			}
		}(i)
	}

	// Concurrent readers and scans.
	for i := 0; i < rounds; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			if st, _ := p.req(t, "GET", "/api/status", nil); st != http.StatusOK {
				t.Errorf("GET /api/status returned %d", st)
			}
			if st, _ := p.req(t, "POST", "/api/scan", map[string]any{"full": false}); st != http.StatusOK && st != http.StatusConflict {
				t.Errorf("POST /api/scan returned %d", st)
			}
		}()
	}

	close(ready)
	wg.Wait()

	// The configuration on disk has to stay valid and readable: a concurrent write
	// must not leave the TOML half-written.
	fromDisk, err := config.Load(p.cfg.Path())
	if err != nil {
		t.Fatalf("the configuration became unreadable after concurrent writes: %v", err)
	}
	if res := fromDisk.Validate(); res.HasErrors() {
		t.Errorf("the configuration became invalid after concurrent writes: %v", res.Errors())
	}
}

func TestThePanelRefusesAnInvalidConfiguration(t *testing.T) {
	// An invalid configuration must never get to touch the file: otherwise the tool
	// does not start afterwards.
	p := setupPanel(t)
	authenticate(t, p)

	before, err := os.ReadFile(p.cfg.Path())
	if err != nil {
		t.Fatalf("reading the config: %v", err)
	}

	st, _ := p.req(t, "PUT", "/api/config", map[string]any{
		"confirmed_at": 0.3, "likely_at": 0.6, // out of order
	})
	if st != http.StatusBadRequest {
		t.Fatalf("out-of-order thresholds should be refused, got %d", st)
	}

	after, _ := os.ReadFile(p.cfg.Path())
	if !bytes.Equal(before, after) {
		t.Error("the configuration file was changed despite the refusal")
	}
}

// Helpers ----------------------------------------------------------------------

func authenticate(t *testing.T, p *panel) {
	t.Helper()
	st, _ := p.req(t, "POST", "/api/setup", map[string]any{"password": "strong-test-password"})
	if st != http.StatusOK {
		t.Fatalf("setup: %d", st)
	}
}

func createVerdict(t *testing.T, ctx context.Context, st *store.Store, file string) schema.Verdict {
	t.Helper()
	sha, err := hashOf(file)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     verdict.FindingID("s_panel", "test", "rule", sha),
		FileSHA256:    sha,
		FilePath:      file,
		FileSize:      64,
		Level:         schema.LevelConfirmed,
		Score:         0.95,
		Votes: []schema.Vote{
			{Engine: "maldet", Weight: 1.0, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 1.0, Rule: "php.test", Category: schema.CategoryBackdoor},
			{Engine: "amwscan", Weight: 0.8, Confidence: schema.ConfidenceSignature,
				EffectiveWeight: 0.8, Rule: "KNOWN_MALWARE", Category: schema.CategoryBackdoor},
		},
		ActionTaken: schema.ActionNone,
		ScanID:      "s_panel",
		CreatedAt:   time.Now(),
	}
	if err := st.SaveVerdict(ctx, v); err != nil {
		t.Fatalf("SaveVerdict: %v", err)
	}
	return v
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
