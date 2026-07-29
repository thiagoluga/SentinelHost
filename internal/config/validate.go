package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Problem e um achado da validacao da configuracao.
type Problem struct {
	Field   string
	Message string
	// Fatal separa "isto impede o programa de rodar" de "isto merece um aviso
	// na tela". Um aviso nunca deve impedir o scan de acontecer: a ferramenta
	// que se recusa a rodar protege menos que a que roda avisando.
	Fatal bool
}

func (p Problem) String() string {
	prefix := "aviso"
	if p.Fatal {
		prefix = "erro"
	}
	return fmt.Sprintf("%s: %s: %s", prefix, p.Field, p.Message)
}

// ValidationResult reune erros e avisos.
type ValidationResult struct {
	Problems []Problem
}

// HasErrors responde se ha algo que impeca a execucao.
func (r ValidationResult) HasErrors() bool {
	for _, p := range r.Problems {
		if p.Fatal {
			return true
		}
	}
	return false
}

// Errors devolve so os fatais.
func (r ValidationResult) Errors() []Problem {
	var out []Problem
	for _, p := range r.Problems {
		if p.Fatal {
			out = append(out, p)
		}
	}
	return out
}

// Warnings devolve so os avisos.
func (r ValidationResult) Warnings() []Problem {
	var out []Problem
	for _, p := range r.Problems {
		if !p.Fatal {
			out = append(out, p)
		}
	}
	return out
}

// Err transforma os fatais num error unico, ou nil.
func (r ValidationResult) Err() error {
	errs := r.Errors()
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, p := range errs {
		msgs = append(msgs, p.Field+": "+p.Message)
	}
	return fmt.Errorf("configuracao invalida: %s", strings.Join(msgs, "; "))
}

func (r *ValidationResult) fatal(field, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{field, fmt.Sprintf(format, args...), true})
}

func (r *ValidationResult) warn(field, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{field, fmt.Sprintf(format, args...), false})
}

// Validate checa a configuracao inteira.
func (c *Config) Validate() ValidationResult {
	var r ValidationResult

	c.validateGeneral(&r)
	c.validateLimits(&r)
	c.validateVerdict(&r)
	c.validateQuarantine(&r)
	c.validateEngines(&r)
	c.validateAlerts(&r)
	c.validateWeb(&r)

	return r
}

func (c *Config) validateGeneral(r *ValidationResult) {
	if len(c.General.Roots) == 0 {
		r.fatal("general.roots", "nenhuma raiz configurada: o scan nao tem o que varrer")
	}
	for i, root := range c.General.Roots {
		if root == "" {
			r.fatal(fmt.Sprintf("general.roots[%d]", i), "raiz vazia")
			continue
		}
		if root == "/" {
			r.fatal(fmt.Sprintf("general.roots[%d]", i),
				"varrer / nao e o proposito da ferramenta e derrubaria a conta por uso de recursos")
		}
	}
	if c.General.DataDir == "" {
		r.fatal("general.data_dir", "vazio")
	}
	if c.General.GracePeriodDays < 0 {
		r.fatal("general.grace_period_days", "nao pode ser negativo")
	}
	if !c.General.ObservationMode && c.General.GracePeriodDays == 0 {
		r.warn("general.observation_mode",
			"acao automatica ligada sem periodo de graca: a ferramenta pode quarentenar ja no primeiro ciclo, antes de voce calibrar a whitelist")
	}
}

func (c *Config) validateLimits(r *ValidationResult) {
	if c.Limits.Nice < 0 || c.Limits.Nice > 19 {
		r.fatal("limits.nice", "deve estar entre 0 e 19, veio %d", c.Limits.Nice)
	}
	if c.Limits.Nice < 10 {
		// Sem root nao da para BAIXAR o nice depois; subir prioridade e
		// exatamente o que faz a hospedagem suspender a conta.
		r.warn("limits.nice", "valor %d da prioridade alta ao scanner e pode fazer a hospedagem suspender a conta (recomendado: 19)", c.Limits.Nice)
	}
	if c.Limits.MaxFileSizeMB <= 0 {
		r.fatal("limits.max_file_size_mb", "deve ser positivo")
	}
	if c.Limits.EngineTimeout.Duration <= 0 {
		r.fatal("limits.engine_timeout", "deve ser positivo: sem timeout um engine travado paralisa o ciclo para sempre")
	}
	if c.Limits.CycleTimeout.Duration > 0 && c.Limits.CycleTimeout.Duration < c.Limits.EngineTimeout.Duration {
		r.warn("limits.cycle_timeout", "menor que engine_timeout: nenhum engine conseguira terminar")
	}
	if c.Limits.BatchSize <= 0 {
		r.fatal("limits.batch_size", "deve ser positivo")
	}
	if c.Limits.MaxDepth <= 0 {
		r.fatal("limits.max_depth", "deve ser positivo")
	}
	if c.Limits.MemoryLimitMB > 0 && c.Limits.MemoryLimitMB < 32 {
		r.warn("limits.memory_limit_mb", "abaixo de 32 MB o proprio orquestrador pode nao caber")
	}
}

func (c *Config) validateVerdict(r *ValidationResult) {
	v := c.Verdict
	if v.Saturation <= 0 {
		r.fatal("verdict.saturation", "deve ser positivo (e o divisor do score)")
	}
	for name, val := range map[string]float64{
		"verdict.confirmed_at":  v.ConfirmedAt,
		"verdict.likely_at":     v.LikelyAt,
		"verdict.suspicious_at": v.SuspiciousAt,
	} {
		if val < 0 || val > 1 {
			r.fatal(name, "deve estar entre 0 e 1, veio %v", val)
		}
	}
	// Limiares fora de ordem produziriam niveis inalcancaveis — um confirmed
	// abaixo do likely faria todo achado grave virar likely.
	if !(v.ConfirmedAt > v.LikelyAt && v.LikelyAt > v.SuspiciousAt) {
		r.fatal("verdict",
			"limiares fora de ordem: confirmed_at (%v) > likely_at (%v) > suspicious_at (%v) e obrigatorio",
			v.ConfirmedAt, v.LikelyAt, v.SuspiciousAt)
	}
	for name, val := range map[string]float64{
		"verdict.signature_multiplier": v.SignatureMultiplier,
		"verdict.heuristic_multiplier": v.HeuristicMultiplier,
		"verdict.anomaly_multiplier":   v.AnomalyMultiplier,
	} {
		if val < 0 || val > 1 {
			r.fatal(name, "deve estar entre 0 e 1, veio %v", val)
		}
	}
	if v.SignatureMultiplier < v.HeuristicMultiplier || v.HeuristicMultiplier < v.AnomalyMultiplier {
		r.warn("verdict",
			"multiplicadores invertidos: uma anomalia passaria a pesar mais que uma assinatura exata")
	}
	if v.ConfirmedAt < 0.5 {
		r.warn("verdict.confirmed_at",
			"limiar baixo (%v) para o nivel que autoriza quarentena automatica", v.ConfirmedAt)
	}
}

func (c *Config) validateQuarantine(r *ValidationResult) {
	if c.Quarantine.RetentionDays < 0 {
		r.fatal("quarantine.retention_days", "nao pode ser negativo")
	}
	if c.Quarantine.AutoPurge && c.Quarantine.RetentionDays == 0 {
		r.fatal("quarantine.auto_purge",
			"purga automatica com retencao 0 apagaria o arquivo no mesmo instante em que ele fosse quarentenado, tornando a acao irreversivel")
	}
	if c.Quarantine.AutoPurge && c.Quarantine.RetentionDays < 7 {
		r.warn("quarantine.retention_days",
			"%d dias e pouco para perceber um falso positivo antes da purga", c.Quarantine.RetentionDays)
	}
	if c.Quarantine.NeutralizedExtension == "" {
		r.fatal("quarantine.neutralized_extension",
			"vazio: o arquivo ficaria no cofre com a extensao original e ainda executavel se o cofre for servido pela web")
	}
}

func (c *Config) validateEngines(r *ValidationResult) {
	enabled := 0
	for slug, e := range c.Engines {
		if e.Weight < 0 {
			r.fatal("engines."+slug+".weight", "nao pode ser negativo")
		}
		if e.Weight > 3 {
			r.warn("engines."+slug+".weight",
				"peso %v faz este engine sozinho decidir qualquer veredito", e.Weight)
		}
		if e.Enabled {
			enabled++
			if e.Weight == 0 {
				r.warn("engines."+slug,
					"habilitado com peso 0: vai gastar CPU e nunca influenciar veredito")
			}
		}
	}
	if enabled == 0 {
		r.fatal("engines", "nenhum engine habilitado")
	}
	if enabled == 1 {
		r.warn("engines",
			"apenas 1 engine habilitado: nao existe consenso com um voto so, e a cobertura fica reduzida")
	}
}

func (c *Config) validateAlerts(r *ValidationResult) {
	e := c.Alerts.Email
	if e.Enabled {
		if e.Host == "" {
			r.fatal("alerts.email.host", "vazio com e-mail habilitado")
		}
		if e.Port <= 0 || e.Port > 65535 {
			r.fatal("alerts.email.port", "porta invalida: %d", e.Port)
		}
		if e.From == "" {
			r.fatal("alerts.email.from", "vazio com e-mail habilitado")
		}
		if len(e.To) == 0 {
			r.fatal("alerts.email.to", "nenhum destinatario com e-mail habilitado")
		}
		switch e.TLS {
		case "starttls", "tls", "none":
		default:
			r.fatal("alerts.email.tls", "valor %q invalido (use starttls, tls ou none)", e.TLS)
		}
		if e.TLS == "none" && e.Password != "" {
			r.warn("alerts.email.tls",
				"senha SMTP seria enviada em texto claro pela rede")
		}
		for _, lv := range e.Levels {
			switch lv {
			case "confirmed", "likely", "suspicious":
			default:
				r.fatal("alerts.email.levels", "nivel %q desconhecido", lv)
			}
		}
		if len(e.Levels) == 0 {
			r.warn("alerts.email.levels",
				"nenhum nivel selecionado: o e-mail esta ligado mas nunca vai disparar")
		}
	}

	seen := map[string]bool{}
	for i, w := range c.Alerts.Webhooks {
		field := fmt.Sprintf("alerts.webhooks[%d]", i)
		if w.ID == "" {
			r.fatal(field+".id", "vazio")
		} else if seen[w.ID] {
			r.fatal(field+".id", "id %q duplicado", w.ID)
		} else {
			seen[w.ID] = true
		}

		u, err := url.Parse(w.URL)
		switch {
		case w.URL == "":
			r.fatal(field+".url", "vazio")
		case err != nil:
			r.fatal(field+".url", "invalida: %v", err)
		case u.Scheme != "http" && u.Scheme != "https":
			r.fatal(field+".url", "esquema %q nao suportado (use http ou https)", u.Scheme)
		case u.Scheme == "http" && w.Enabled:
			r.warn(field+".url",
				"http sem TLS: o payload com caminhos dos seus arquivos trafega em claro")
		}

		if w.Enabled && w.Secret == "" {
			r.warn(field+".secret",
				"sem segredo o destino nao consegue verificar que a entrega veio daqui")
		}
		if w.Enabled && len(w.Events) == 0 {
			r.warn(field+".events", "sem eventos assinados: nunca havera entrega")
		}
		for _, ev := range w.Events {
			if !validEvent(ev) {
				r.fatal(field+".events", "evento %q desconhecido", ev)
			}
		}
	}
}

// KnownEvents sao os eventos de webhook do contrato
// (specs/001-orquestrador-mvp/contracts/webhooks.md).
var KnownEvents = []string{
	"verdict.confirmed",
	"verdict.likely",
	"verdict.suspicious",
	"quarantine.action",
	"scan.completed",
	"engine.failed",
}

func validEvent(e string) bool {
	for _, k := range KnownEvents {
		if k == e {
			return true
		}
	}
	return false
}

func (c *Config) validateWeb(r *ValidationResult) {
	if !c.Web.Enabled {
		return
	}
	if c.Web.Listen == "" {
		r.fatal("web.listen", "vazio com painel habilitado")
	}
	host, _, found := strings.Cut(c.Web.Listen, ":")
	if !found {
		r.fatal("web.listen", "formato invalido: use host:porta")
		return
	}
	// A constituicao manda escutar em localhost por padrao. Expor e uma
	// escolha legitima do usuario — mas tem que ser consciente, com aviso.
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		r.warn("web.listen",
			"o painel vai aceitar conexoes de fora de %q; prefira tunel SSH ou garanta que a porta esta protegida", host)
	}
	if c.Web.SessionTTL.Duration <= 0 {
		r.fatal("web.session_ttl", "deve ser positivo")
	}
	if c.Web.LoginRateLimit <= 0 {
		r.fatal("web.login_rate_limit", "deve ser positivo: sem limite o painel fica aberto a forca bruta")
	}
}
