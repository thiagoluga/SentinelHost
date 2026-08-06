package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/housekeeping"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Authentication ---------------------------------------------------------------

func (s *Server) handleSession(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": s.authenticated(req),
		"password_set":  s.passwordSet(req.Context()),
	})
}

// handleSetup sets the password on first access.
func (s *Server) handleSetup(w http.ResponseWriter, req *http.Request) {
	if s.passwordSet(req.Context()) {
		// Without this check, anyone who reached the port could reset the panel's
		// password at any time.
		writeErr(w, http.StatusConflict, "the password has already been set; use the login")
		return
	}

	var body struct {
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if err := decodeBody(req, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Something only the account holder can read. Being first is not a credential: the
	// panel sits at a guessable URL, and whoever won that race was handed a session and,
	// with it, the ability to point an engine at a file they uploaded and run it.
	if !s.validSetupToken(req.Context(), body.SetupToken) {
		writeErr(w, http.StatusForbidden,
			"first access needs the setup token. It is printed when the panel starts and "+
				"stored in %s inside the data directory, which only this account can read",
			setupTokenFile)
		return
	}
	if len(body.Password) < 10 {
		writeErr(w, http.StatusBadRequest,
			"the password needs at least 10 characters: it is the only thing between the internet and a button that moves your site's files")
		return
	}

	hash, err := hashPassword(body.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if err := s.store.SetSetting(req.Context(), store.KeyPanelPasswordHash, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	// The token has done its job. Leaving it on disk would keep a second credential alive
	// for a panel that now has a password — one nobody is watching, and one that would let
	// whoever reads it claim the panel again if the database were ever removed.
	s.cfgMu.RLock()
	dataDir := s.cfg.General.DataDir
	s.cfgMu.RUnlock()
	clearSetupToken(dataDir)
	_ = s.store.Log(req.Context(), store.Event{
		Level: "info", Category: store.CatAuth,
		Message: "the panel password was set on first access",
	})

	s.startSession(w, req)
}

func (s *Server) handleLogin(w http.ResponseWriter, req *http.Request) {
	ip := clientIP(req)
	if !s.limiter.allow(req.Context(), ip, s.now()) {
		writeErr(w, http.StatusTooManyRequests,
			"too many login attempts; wait a minute")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(req, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	hash, err := s.store.GetSetting(req.Context(), store.KeyPanelPasswordHash)
	if err != nil || hash == "" {
		writeErr(w, http.StatusPreconditionRequired, "the password has not been set yet")
		return
	}
	if !verifyPassword(body.Password, hash) {
		_ = s.store.Log(req.Context(), store.Event{
			Level: "warn", Category: store.CatAuth,
			Message: "login attempt with the wrong password",
			Fields:  map[string]any{"ip": ip},
		})
		// A generic message on purpose: saying "wrong password" versus "no such
		// user" is what lets accounts be enumerated. There is only one password
		// here, but the habit is the same.
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.limiter.reset(req.Context(), ip)
	s.startSession(w, req)
}

func (s *Server) startSession(w http.ResponseWriter, req *http.Request) {
	token, err := newToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "generating the session: %v", err)
		return
	}
	expires := s.now().Add(s.config().Web.SessionTTL.Duration)
	if err := s.store.CreateSession(req.Context(), token, expires,
		req.UserAgent(), clientIP(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, "writing the session: %v", err)
		return
	}
	s.setCookie(w, token, expires, isSecureRequest(req))
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "expires_at": expires})
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) {
	if c, err := req.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(req.Context(), c.Value)
	}
	s.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// Overview ---------------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Errors are reported, not rendered as zeros.
	//
	// Every one of these was discarded and the handler still answered 200, so a database
	// the panel could not read produced {confirmed:0, likely:0, suspicious:0},
	// pending_count 0 and engines {available:0}. That is indistinguishable from a healthy,
	// clean account — the same lie by omission the scan report goes out of its way to
	// prevent, on the screen a user checks to decide whether anything is wrong.
	var failures []string
	note := func(what string, err error) {
		// "There is no scan yet" is an answer, not a failure. A fresh install has no last
		// scan, and reporting that as a broken panel would make the first visit look like
		// an outage. Only a real read error means the number below would be a zero that
		// means "unknown".
		// Both spellings: LastScan returns sql.ErrNoRows raw, the rest wrap ErrNotFound.
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, sql.ErrNoRows) {
			failures = append(failures, what)
		}
	}

	last, errLast := s.store.LastScan(ctx)
	note("the last scan", errLast)
	levels, errLevels := s.store.CountByLevel(ctx, "")
	note("the verdict counts", errLevels)
	vault, errVault := s.store.CountQuarantine(ctx)
	note("the quarantine", errVault)
	engines, errEngines := s.store.ListEngineStates(ctx)
	note("the engines", errEngines)

	pending, errPending := s.store.ListVerdicts(ctx, store.VerdictFilter{PendingOnly: true, Limit: 200})
	note("the pending findings", errPending)

	cfg := s.config()
	allowed, reason := cfg.AutomaticActionAllowed(s.now())

	// The coverage always travels with the summary. A panel that shows "0 threats"
	// without saying that half the engines are down hides exactly the information
	// the user needs in order to trust the number.
	available, unavailable := 0, 0
	for _, e := range engines {
		if e.Available {
			available++
		} else {
			unavailable++
		}
	}

	// A partial answer says so, in the payload, rather than passing zeros off as facts.
	if len(failures) > 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "the panel could not read " + strings.Join(failures, ", ") +
				". The numbers below would be zeros that mean 'unknown', not 'none', so " +
				"they are not being shown",
			"unavailable": failures,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"roots": cfg.General.Roots,
		"last_scan": map[string]any{
			"scan_id":          last.ScanID,
			"mode":             last.Mode,
			"started_at":       last.StartedAt,
			"finished_at":      last.FinishedAt,
			"status":           last.Status,
			"files_considered": last.FilesConsidered,
			"files_scanned":    last.FilesScanned,
		},
		"verdicts": map[string]int{
			"confirmed":  levels[schema.LevelConfirmed],
			"likely":     levels[schema.LevelLikely],
			"suspicious": levels[schema.LevelSuspicious],
			"clean":      levels[schema.LevelClean],
		},
		"pending_count": len(pending),
		"quarantine": map[string]int{
			"active":   vault[store.QuarantineActive],
			"restored": vault[store.QuarantineRestored],
			"purged":   vault[store.QuarantinePurged],
		},
		"engines": map[string]int{
			"available":   available,
			"unavailable": unavailable,
		},
		"automatic_action": map[string]any{
			"allowed":          allowed,
			"reason":           reason,
			"observation_mode": cfg.General.ObservationMode,
			"grace_ends_at":    cfg.GracePeriodEndsAt(),
		},
	})
}

// Findings ---------------------------------------------------------------------

func (s *Server) handleVerdicts(w http.ResponseWriter, req *http.Request) {
	f := store.VerdictFilter{Limit: 200}
	if req.URL.Query().Get("pending") == "1" {
		f.PendingOnly = true
	}
	if lv := req.URL.Query().Get("level"); lv != "" {
		f.Levels = []schema.Level{schema.Level(lv)}
	}
	if req.URL.Query().Get("include_clean") == "1" {
		f.IncludeClean = true
	}

	vs, err := s.store.ListVerdicts(req.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verdicts": vs})
}

func (s *Server) handleVerdictDetail(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	v, err := s.store.GetVerdict(req.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}
	// Each engine's raw findings travel with the verdict: it is what answers "why
	// was this file flagged?" in detail.
	//
	// Scoped to the verdict's own cycle. Asking by content hash alone returns every
	// finding for that file across every cycle, and a cron running every fifteen minutes
	// re-detects the same file all day — the panel showed one wp-checksums vote above
	// three identical wp-checksums evidence blocks, contradicting the votes printed
	// directly above it.
	findings, _ := s.store.FindingsForVerdict(req.Context(), v.FileSHA256, v.ScanID, v.FilePath)
	writeJSON(w, http.StatusOK, map[string]any{
		"verdict":  v,
		"findings": findings,
		// Stated so the panel can tell "this cycle recorded no evidence" apart from
		// "the request failed", which look identical in an empty list.
		"findings_count": len(findings),
	})
}

// handleDecide applies the user's decision about a finding.
func (s *Server) handleDecide(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	var body struct {
		Action string `json:"action"` // quarantine | ignore | whitelist
	}
	if err := decodeBody(req, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	v, err := s.store.GetVerdict(req.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}

	switch body.Action {
	case "quarantine":
		item, err := s.vault.Quarantine(req.Context(), v.VerdictID, v.FilePath, v.FileSHA256)
		if err != nil {
			// The real error goes to the screen. "Failed to quarantine" helps nobody
			// find out that the file changed since the scan.
			writeErr(w, http.StatusConflict, "%v", err)
			return
		}
		_ = s.store.UpdateVerdictAction(req.Context(), id, schema.ActionQuarantined, item.Ref, "")
		_ = s.store.AcknowledgeVerdict(req.Context(), id)
		s.logAction(req, "file quarantined from the panel: "+v.FilePath, map[string]any{"ref": item.Ref})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "quarantine_ref": item.Ref})

	case "ignore":
		_ = s.store.UpdateVerdictAction(req.Context(), id, schema.ActionIgnored, "", "ignored by the user")
		_ = s.store.AcknowledgeVerdict(req.Context(), id)
		s.logAction(req, "finding ignored by the user: "+v.FilePath, nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case "whitelist":
		// The whitelist is permanent and lives in the TOML, which is the source of
		// truth shared with the CLI (FR-014). It is a configuration WRITE like any
		// other, and goes through the same lock.
		err := s.mutateConfig(func(c *config.Config) error {
			c.Verdict.Whitelist = append(c.Verdict.Whitelist, v.FilePath)
			return c.Save()
		})
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, ErrBusy) {
				status = http.StatusConflict
			}
			writeErr(w, status, "writing the whitelist: %v", err)
			return
		}
		_ = s.store.UpdateVerdictAction(req.Context(), id, schema.ActionSkippedWhitelist, "",
			"added to the whitelist by the user")
		_ = s.store.AcknowledgeVerdict(req.Context(), id)
		s.logAction(req, "file added to the whitelist: "+v.FilePath, nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeErr(w, http.StatusBadRequest, "unknown action %q (use quarantine, ignore or whitelist)", body.Action)
	}
}

// Quarantine -------------------------------------------------------------------

func (s *Server) handleQuarantineList(w http.ResponseWriter, req *http.Request) {
	status := store.QuarantineActive
	if req.URL.Query().Get("all") == "1" {
		status = ""
	}
	items, err := s.store.ListQuarantineItems(req.Context(), status, 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleRestore(w http.ResponseWriter, req *http.Request) {
	ref := req.PathValue("ref")
	item, err := s.vault.Restore(req.Context(), ref)
	if err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	s.logAction(req, "file restored from the panel: "+item.OriginalPath, map[string]any{"ref": ref})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restored_to": item.OriginalPath})
}

func (s *Server) handlePurge(w http.ResponseWriter, req *http.Request) {
	ref := req.PathValue("ref")

	var body struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeBody(req, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	// Explicit confirmation in text: this is the project's ONLY irreversible
	// operation, and an accidental click must not be enough.
	if body.Confirm != "purge" {
		writeErr(w, http.StatusBadRequest,
			`the purge is irreversible; send {"confirm":"purge"} to confirm`)
		return
	}

	if err := s.vault.Purge(req.Context(), ref, true); err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	s.logAction(req, "item permanently purged from the panel", map[string]any{"ref": ref})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Engines ----------------------------------------------------------------------

func (s *Server) handleEngines(w http.ResponseWriter, req *http.Request) {
	cfg := s.config()
	states, _ := s.store.ListEngineStates(req.Context())
	bySlug := map[string]store.EngineState{}
	for _, e := range states {
		bySlug[e.Slug] = e
	}

	var out []map[string]any
	for _, slug := range s.registry.Slugs() {
		a, _ := s.registry.Get(slug)
		info := a.Info()
		st := bySlug[slug]
		out = append(out, map[string]any{
			"slug":                  slug,
			"name":                  info.Name,
			"license":               info.License,
			"homepage":              info.Homepage,
			"cost":                  info.Cost,
			"enabled":               cfg.EngineEnabled(slug),
			"weight":                cfg.WeightFor(slug),
			"default_weight":        info.DefaultWeight,
			"available":             st.Available,
			"unavailable_reason":    st.UnavailableReason,
			"version":               st.Version,
			"signatures_updated_at": st.SignaturesUpdatedAt,
			"last_run_at":           st.LastRunAt,
			"last_run_status":       st.LastRunStatus,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"engines": out})
}

func (s *Server) handleEngineInstall(w http.ResponseWriter, req *http.Request) {
	slug := req.PathValue("slug")
	a, ok := s.registry.Get(slug)
	if !ok {
		writeErr(w, http.StatusNotFound, "engine %q does not exist in this binary", slug)
		return
	}

	env := adapter.Environment{
		DataDir:    s.config().General.DataDir,
		BinaryPath: s.config().Engines[slug].Path,
		ExtraArgs:  s.config().Engines[slug].ExtraArgs,
	}
	if err := adapter.SafeInstall(req.Context(), a, env); err != nil {
		if errors.Is(err, adapter.ErrNotInstallable) {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.logAction(req, "engine installed from the panel: "+slug, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Configuration ----------------------------------------------------------------

func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	// Secrets never leave through the API. The panel shows "set"/"not set" instead
	// of the value: whoever has access to the panel can already act, but does not
	// need to be able to READ the SMTP password to paste it somewhere else.
	c := *s.config()
	c.Alerts.Email.Password = mask(c.Alerts.Email.Password)
	hooks := make([]config.Webhook, len(c.Alerts.Webhooks))
	copy(hooks, c.Alerts.Webhooks)
	for i := range hooks {
		hooks[i].Secret = mask(hooks[i].Secret)
	}
	c.Alerts.Webhooks = hooks

	writeJSON(w, http.StatusOK, map[string]any{
		"config": map[string]any{
			"general":    c.General,
			"limits":     c.Limits,
			"schedule":   c.Schedule,
			"verdict":    c.Verdict,
			"quarantine": c.Quarantine,
			"engines":    c.Engines,
			"alerts":     c.Alerts,
			"web":        c.Web,
			"logging":    c.Logging,
		},
		"path": s.config().Path(),
	})
}

func mask(v string) string {
	if v == "" {
		return ""
	}
	return "********"
}

// handleConfigPut writes changes coming from the panel.
//
// FR-014: the panel writes to the SAME TOML the CLI reads. There is no
// configuration state living only in the panel.
func (s *Server) handleConfigPut(w http.ResponseWriter, req *http.Request) {
	var patch configPatch
	if err := decodeBody(req, &patch); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	var validationWarnings []config.Problem
	err := s.mutateConfig(func(c *config.Config) error {
		patch.apply(c)

		res := c.Validate()
		if res.HasErrors() {
			// An invalid configuration never gets to touch the published copy nor
			// the file: better to refuse the edit than to leave the tool unable to
			// start afterwards.
			return res.Err()
		}
		validationWarnings = res.Warnings()
		return c.Save()
	})
	switch {
	case errors.Is(err, ErrBusy):
		writeErr(w, http.StatusConflict, "%v", err)
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	s.logAction(req, "configuration changed from the panel", map[string]any{"fields": patch.fields()})

	warnings := make([]string, 0, len(validationWarnings))
	for _, p := range validationWarnings {
		warnings = append(warnings, p.Field+": "+p.Message)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warnings": warnings})
}

// Alerts -----------------------------------------------------------------------

func (s *Server) handleAlertTest(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Channel string `json:"channel"` // email | webhook
		ID      string `json:"id"`
	}
	if err := decodeBody(req, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	var res alert.TestResult
	switch body.Channel {
	case "email":
		res = s.alerts.TestEmail(req.Context())
	case "webhook":
		res = s.alerts.TestWebhook(req.Context(), body.ID)
	default:
		writeErr(w, http.StatusBadRequest, "unknown channel %q (use email or webhook)", body.Channel)
		return
	}

	// The REAL result goes to the screen, error included. That is the whole point
	// of the test button (FR-012).
	out := map[string]any{
		"ok":          res.OK,
		"channel":     res.Channel,
		"target":      res.Target,
		"http_status": res.HTTPStatus,
		"duration_ms": res.Duration.Milliseconds(),
		"message":     res.String(),
	}
	if res.Err != nil {
		out["error"] = res.Err.Error()
	}
	if res.Body != "" {
		out["response_body"] = res.Body
	}
	writeJSON(w, http.StatusOK, out)
}

// On-demand scan ---------------------------------------------------------------

func (s *Server) handleScanNow(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Full bool `json:"full"`
	}
	_ = decodeBody(req, &body)

	mode := schema.ModeIncremental
	if body.Full {
		mode = schema.ModeFull
	}

	// The cycle reads the configuration from beginning to end. Holding the read
	// lock for the whole execution is what keeps the panel from swapping thresholds
	// or exclusions in the middle of a scan.
	var sum cycle.Summary
	err := s.withConfigRead(func(cfg *config.Config) error {
		// The periodic maintenance travels with the cycle on all THREE paths that
		// trigger a scan: cron, daemon and panel. Leaving the panel out would mean
		// that whoever only uses the interface never gets a webhook retry nor disk
		// pruning.
		if _, err := housekeeping.Run(req.Context(), housekeeping.Deps{
			Cfg: cfg, Store: s.store, Vault: s.vault, Alerts: s.alerts, Now: s.now,
		}); err != nil {
			// Maintenance that fails never blocks the scan.
			_ = s.store.Log(req.Context(), store.Event{
				Level: "warn", Category: store.CatSystem,
				Message: "periodic maintenance: " + err.Error(),
			})
		}

		var err error
		sum, err = s.runner.Run(req.Context(), cycle.Options{Mode: mode})
		return err
	})
	if err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, sum.Event())
}

// Structured log (FR-015) ------------------------------------------------------

func (s *Server) handleEvents(w http.ResponseWriter, req *http.Request) {
	f := store.EventFilter{
		Category: req.URL.Query().Get("category"),
		Level:    req.URL.Query().Get("level"),
		Limit:    200,
	}
	if d := req.URL.Query().Get("since_hours"); d != "" {
		var h int
		if _, err := fmt.Sscanf(d, "%d", &h); err == nil && h > 0 {
			f.Since = s.now().Add(-time.Duration(h) * time.Hour)
		}
	}
	events, err := s.store.ListEvents(req.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleCronLine(w http.ResponseWriter, _ *http.Request) {
	cfg := s.config()
	writeJSON(w, http.StatusOK, map[string]any{
		"incremental": cfg.Schedule.Incremental.Duration.String(),
		"full_cron":   cfg.Schedule.FullCron,
		"config_path": cfg.Path(),
		"hint":        "run `sentinelhost cron-line` on the server for the complete line, with the binary's path",
	})
}

func (s *Server) logAction(req *http.Request, msg string, fields map[string]any) {
	// Logging must never be the thing that takes the panel down.
	//
	// This is called on failure paths — including the one that runs when somebody served a
	// binary the release key did not sign. Panicking there would turn "we refused a forged
	// update" into "the panel crashed", which is a strictly worse outcome and a confusing
	// one to debug.
	if s == nil || s.store == nil {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["ip"] = clientIP(req)
	_ = s.store.Log(req.Context(), store.Event{
		Level: "info", Category: store.CatConfig, Message: msg, Fields: fields,
	})
}
