package web

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/alert"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Autenticacao ----------------------------------------------------------------

func (s *Server) handleSession(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": s.authenticated(req),
		"password_set":  s.passwordSet(req.Context()),
	})
}

// handleSetup define a senha no primeiro acesso.
func (s *Server) handleSetup(w http.ResponseWriter, req *http.Request) {
	if s.passwordSet(req.Context()) {
		// Sem esta checagem, qualquer um que alcancasse a porta poderia
		// redefinir a senha do painel a qualquer momento.
		writeErr(w, http.StatusConflict, "a senha ja foi definida; use o login")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(req, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(body.Password) < 10 {
		writeErr(w, http.StatusBadRequest,
			"a senha precisa de pelo menos 10 caracteres: ela e a unica coisa entre a internet e um botao que move arquivos do seu site")
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
	_ = s.store.Log(req.Context(), store.Event{
		Level: "info", Category: store.CatAuth,
		Message: "senha do painel definida no primeiro acesso",
	})

	s.startSession(w, req)
}

func (s *Server) handleLogin(w http.ResponseWriter, req *http.Request) {
	ip := clientIP(req)
	if !s.limiter.allow(ip, s.now()) {
		writeErr(w, http.StatusTooManyRequests,
			"muitas tentativas de login; espere um minuto")
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
		writeErr(w, http.StatusPreconditionRequired, "a senha ainda nao foi definida")
		return
	}
	if !verifyPassword(body.Password, hash) {
		_ = s.store.Log(req.Context(), store.Event{
			Level: "warn", Category: store.CatAuth,
			Message: "tentativa de login com senha incorreta",
			Fields:  map[string]any{"ip": ip},
		})
		// Mensagem generica de proposito: dizer "senha errada" versus
		// "usuario nao existe" e o que permite enumerar contas. Aqui so ha
		// uma senha, mas o habito e o mesmo.
		writeErr(w, http.StatusUnauthorized, "credenciais invalidas")
		return
	}

	s.limiter.reset(ip)
	s.startSession(w, req)
}

func (s *Server) startSession(w http.ResponseWriter, req *http.Request) {
	token, err := newToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gerando sessao: %v", err)
		return
	}
	expira := s.now().Add(s.config().Web.SessionTTL.Duration)
	if err := s.store.CreateSession(req.Context(), token, expira,
		req.UserAgent(), clientIP(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, "gravando sessao: %v", err)
		return
	}
	s.setCookie(w, token, expira, isSecureRequest(req))
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "expires_at": expira})
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) {
	if c, err := req.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(req.Context(), c.Value)
	}
	s.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// Visao geral -----------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	ultimo, _ := s.store.LastScan(ctx)
	niveis, _ := s.store.CountByLevel(ctx, "")
	cofre, _ := s.store.CountQuarantine(ctx)
	engines, _ := s.store.ListEngineStates(ctx)

	pendentes, _ := s.store.ListVerdicts(ctx, store.VerdictFilter{PendingOnly: true, Limit: 200})

	cfg := s.config()
	permitido, motivo := cfg.AutomaticActionAllowed(s.now())

	// A cobertura vem junto do resumo, sempre. Um painel que mostra "0
	// ameacas" sem dizer que metade dos engines esta fora esconde exatamente
	// a informacao que o usuario precisa para confiar no numero.
	disponiveis, indisponiveis := 0, 0
	for _, e := range engines {
		if e.Available {
			disponiveis++
		} else {
			indisponiveis++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"roots": cfg.General.Roots,
		"last_scan": map[string]any{
			"scan_id":          ultimo.ScanID,
			"mode":             ultimo.Mode,
			"started_at":       ultimo.StartedAt,
			"finished_at":      ultimo.FinishedAt,
			"status":           ultimo.Status,
			"files_considered": ultimo.FilesConsidered,
			"files_scanned":    ultimo.FilesScanned,
		},
		"verdicts": map[string]int{
			"confirmed":  niveis[schema.LevelConfirmed],
			"likely":     niveis[schema.LevelLikely],
			"suspicious": niveis[schema.LevelSuspicious],
			"clean":      niveis[schema.LevelClean],
		},
		"pending_count": len(pendentes),
		"quarantine": map[string]int{
			"active":   cofre[store.QuarantineActive],
			"restored": cofre[store.QuarantineRestored],
			"purged":   cofre[store.QuarantinePurged],
		},
		"engines": map[string]int{
			"available":   disponiveis,
			"unavailable": indisponiveis,
		},
		"automatic_action": map[string]any{
			"allowed":          permitido,
			"reason":           motivo,
			"observation_mode": cfg.General.ObservationMode,
			"grace_ends_at":    cfg.GracePeriodEndsAt(),
		},
	})
}

// Achados ---------------------------------------------------------------------

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
	// Os achados brutos de cada engine acompanham o veredito: e o que
	// responde "por que este arquivo foi apontado?" com detalhe.
	findings, _ := s.store.FindingsForHash(req.Context(), v.FileSHA256)
	writeJSON(w, http.StatusOK, map[string]any{"verdict": v, "findings": findings})
}

// handleDecide aplica a decisao do usuario sobre um achado.
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
			// O erro real vai para a tela. "Falha ao quarentenar" nao ajuda
			// ninguem a descobrir que o arquivo mudou desde o scan.
			writeErr(w, http.StatusConflict, "%v", err)
			return
		}
		_ = s.store.UpdateVerdictAction(req.Context(), id, schema.ActionQuarantined, item.Ref, "")
		_ = s.store.AcknowledgeVerdict(req.Context(), id)
		s.logAction(req, "arquivo quarentenado pelo painel: "+v.FilePath, map[string]any{"ref": item.Ref})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "quarantine_ref": item.Ref})

	case "ignore":
		_ = s.store.UpdateVerdictAction(req.Context(), id, schema.ActionIgnored, "", "ignorado pelo usuario")
		_ = s.store.AcknowledgeVerdict(req.Context(), id)
		s.logAction(req, "achado ignorado pelo usuario: "+v.FilePath, nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case "whitelist":
		// A whitelist e permanente e vive no TOML, que e a fonte da verdade
		// compartilhada com a CLI (FR-014). E uma ESCRITA de configuracao como
		// qualquer outra, e passa pelo mesmo lock.
		err := s.mutateConfig(func(c *config.Config) error {
			c.Verdict.Whitelist = append(c.Verdict.Whitelist, v.FilePath)
			return c.Save()
		})
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, ErrBusy) {
				status = http.StatusConflict
			}
			writeErr(w, status, "gravando whitelist: %v", err)
			return
		}
		_ = s.store.UpdateVerdictAction(req.Context(), id, schema.ActionSkippedWhitelist, "",
			"adicionado a whitelist pelo usuario")
		_ = s.store.AcknowledgeVerdict(req.Context(), id)
		s.logAction(req, "arquivo adicionado a whitelist: "+v.FilePath, nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeErr(w, http.StatusBadRequest, "acao %q desconhecida (use quarantine, ignore ou whitelist)", body.Action)
	}
}

// Quarentena -------------------------------------------------------------------

func (s *Server) handleQuarantineList(w http.ResponseWriter, req *http.Request) {
	status := store.QuarantineActive
	if req.URL.Query().Get("all") == "1" {
		status = ""
	}
	itens, err := s.store.ListQuarantineItems(req.Context(), status, 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": itens})
}

func (s *Server) handleRestore(w http.ResponseWriter, req *http.Request) {
	ref := req.PathValue("ref")
	item, err := s.vault.Restore(req.Context(), ref)
	if err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	s.logAction(req, "arquivo restaurado pelo painel: "+item.OriginalPath, map[string]any{"ref": ref})
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
	// Confirmacao explicita por texto: esta e a UNICA operacao irreversivel
	// do projeto, e um clique acidental nao pode bastar.
	if body.Confirm != "purgar" {
		writeErr(w, http.StatusBadRequest,
			`a purga e irreversivel; envie {"confirm":"purgar"} para confirmar`)
		return
	}

	if err := s.vault.Purge(req.Context(), ref, true); err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	s.logAction(req, "item purgado definitivamente pelo painel", map[string]any{"ref": ref})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Engines -----------------------------------------------------------------------

func (s *Server) handleEngines(w http.ResponseWriter, req *http.Request) {
	cfgEngines := s.config()
	estados, _ := s.store.ListEngineStates(req.Context())
	porSlug := map[string]store.EngineState{}
	for _, e := range estados {
		porSlug[e.Slug] = e
	}

	var out []map[string]any
	for _, slug := range s.registry.Slugs() {
		a, _ := s.registry.Get(slug)
		info := a.Info()
		st := porSlug[slug]
		out = append(out, map[string]any{
			"slug":                  slug,
			"name":                  info.Name,
			"license":               info.License,
			"homepage":              info.Homepage,
			"cost":                  info.Cost,
			"enabled":               cfgEngines.EngineEnabled(slug),
			"weight":                cfgEngines.WeightFor(slug),
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
		writeErr(w, http.StatusNotFound, "engine %q nao existe neste binario", slug)
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
	s.logAction(req, "engine instalado pelo painel: "+slug, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Configuracao --------------------------------------------------------------------

func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	// Segredos nunca saem pela API. O painel mostra "definido"/"nao definido"
	// em vez do valor: quem tem acesso ao painel ja pode agir, mas nao
	// precisa poder LER a senha do SMTP para colar em outro lugar.
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

// handleConfigPut grava alteracoes vindas do painel.
//
// FR-014: o painel escreve no MESMO TOML que a CLI le. Nao existe estado de
// configuracao vivendo so no painel.
func (s *Server) handleConfigPut(w http.ResponseWriter, req *http.Request) {
	var patch configPatch
	if err := decodeBody(req, &patch); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	var avisosValidacao []config.Problem
	err := s.mutateConfig(func(c *config.Config) error {
		patch.apply(c)

		res := c.Validate()
		if res.HasErrors() {
			// Configuracao invalida nao chega a tocar nem a copia publicada
			// nem o arquivo: melhor recusar a edicao do que deixar a
			// ferramenta sem conseguir subir depois.
			return res.Err()
		}
		avisosValidacao = res.Warnings()
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
	s.logAction(req, "configuracao alterada pelo painel", map[string]any{"campos": patch.fields()})

	avisos := make([]string, 0, len(avisosValidacao))
	for _, p := range avisosValidacao {
		avisos = append(avisos, p.Field+": "+p.Message)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warnings": avisos})
}

// Alertas ---------------------------------------------------------------------------

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
		writeErr(w, http.StatusBadRequest, "canal %q desconhecido (use email ou webhook)", body.Channel)
		return
	}

	// O resultado REAL vai para a tela, inclusive o erro. E o proposito do
	// botao de teste (FR-012).
	saida := map[string]any{
		"ok":          res.OK,
		"channel":     res.Channel,
		"target":      res.Target,
		"http_status": res.HTTPStatus,
		"duration_ms": res.Duration.Milliseconds(),
		"message":     res.String(),
	}
	if res.Err != nil {
		saida["error"] = res.Err.Error()
	}
	if res.Body != "" {
		saida["response_body"] = res.Body
	}
	writeJSON(w, http.StatusOK, saida)
}

// Scan sob demanda ---------------------------------------------------------------------

func (s *Server) handleScanNow(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Full bool `json:"full"`
	}
	_ = decodeBody(req, &body)

	modo := schema.ModeIncremental
	if body.Full {
		modo = schema.ModeFull
	}

	// O ciclo le a configuracao do comeco ao fim. Segurar o lock de leitura
	// durante toda a execucao e o que impede o painel de trocar limiares ou
	// exclusoes no meio de um scan.
	var sum cycle.Summary
	err := s.withConfigRead(func(*config.Config) error {
		var err error
		sum, err = s.runner.Run(req.Context(), cycle.Options{Mode: modo})
		return err
	})
	if err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, sum.Event())
}

// Log estruturado (FR-015) --------------------------------------------------------------

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
	eventos, err := s.store.ListEvents(req.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": eventos})
}

func (s *Server) handleCronLine(w http.ResponseWriter, _ *http.Request) {
	cfg := s.config()
	writeJSON(w, http.StatusOK, map[string]any{
		"incremental": cfg.Schedule.Incremental.Duration.String(),
		"full_cron":   cfg.Schedule.FullCron,
		"config_path": cfg.Path(),
		"hint":        "rode `sentinelhost cron-line` no servidor para a linha completa com o caminho do binario",
	})
}

func (s *Server) logAction(req *http.Request, msg string, campos map[string]any) {
	if campos == nil {
		campos = map[string]any{}
	}
	campos["ip"] = clientIP(req)
	_ = s.store.Log(req.Context(), store.Event{
		Level: "info", Category: store.CatConfig, Message: msg, Fields: campos,
	})
}
