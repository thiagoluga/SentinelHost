// Package config carrega, valida e grava o arquivo TOML unico do SentinelHost.
//
// O TOML e a fonte da verdade compartilhada entre CLI e painel (FR-014):
// tudo que o painel edita esta aqui, e tudo que e editado a mao aparece no
// painel. Nao existe segundo arquivo de configuracao (Principio VII).
package config

import (
	"time"
)

// Config e o arquivo inteiro.
type Config struct {
	General    General           `toml:"general"`
	Limits     Limits            `toml:"limits"`
	Schedule   Schedule          `toml:"schedule"`
	Verdict    VerdictConfig     `toml:"verdict"`
	Quarantine QuarantineConfig  `toml:"quarantine"`
	Engines    map[string]Engine `toml:"engines"`
	Alerts     Alerts            `toml:"alerts"`
	Web        Web               `toml:"web"`
	Logging    Logging           `toml:"logging"`

	// path guarda de onde este Config foi lido, para que Save() volte ao
	// mesmo lugar sem o chamador precisar lembrar.
	path string `toml:"-"`
}

// General reune o que define a instalacao.
type General struct {
	// Roots sao os diretorios raiz vigiados. Nada fora deles e varrido,
	// nunca — nem por symlink.
	Roots []string `toml:"roots"`
	// DataDir guarda baseline, cofre de quarentena, saidas brutas e o SQLite.
	DataDir string `toml:"data_dir"`
	// ObservationMode desliga toda acao automatica: os vereditos continuam
	// saindo e os alertas viram "acao recomendada".
	ObservationMode bool `toml:"observation_mode"`
	// GracePeriodDays e o periodo apos a primeira execucao em que nenhuma
	// quarentena automatica acontece, mesmo com observation_mode=false.
	// Existe para o usuario calibrar pesos e whitelist antes de a ferramenta
	// mexer nos arquivos dele (DECISIONS.md D-007).
	GracePeriodDays int `toml:"grace_period_days"`
	// FirstRunAt e gravado pelo primeiro ciclo. Zero significa "ainda nao
	// rodou".
	FirstRunAt time.Time `toml:"first_run_at"`
	// Locale do painel e dos e-mails.
	Locale string `toml:"locale"`
}

// Limits e o Principio IV em forma de struct: o scanner nunca pode causar a
// suspensao da conta do usuario por abuso de recursos. Todos estes limites sao
// obrigatorios e ativos por padrao.
type Limits struct {
	// Nice de 0 a 19. O padrao e 19 (a menor prioridade possivel).
	Nice int `toml:"nice"`
	// IonoceClass 3 = idle. Aplicado quando ionice existe.
	IoniceClass int `toml:"ionice_class"`
	// MaxFileSizeMB: arquivos maiores sao pulados e contabilizados como
	// "too_large" no relatorio, nunca ignorados em silencio.
	MaxFileSizeMB int `toml:"max_file_size_mb"`
	// EngineTimeout: tempo maximo de UMA execucao de engine.
	EngineTimeout Duration `toml:"engine_timeout"`
	// CycleTimeout: tempo maximo do ciclo inteiro.
	CycleTimeout Duration `toml:"cycle_timeout"`
	// BatchSize e BatchPause implementam a pausa entre lotes.
	BatchSize  int      `toml:"batch_size"`
	BatchPause Duration `toml:"batch_pause"`
	// MaxDepth limita a profundidade do walker (sites com cache descontrolado).
	MaxDepth int `toml:"max_depth"`
	// MaxFilesPerCycle corta o ciclo com status partial em vez de varrer
	// milhoes de inodes de uma vez.
	MaxFilesPerCycle int `toml:"max_files_per_cycle"`
	// Exclude sao globs relativos a cada raiz.
	Exclude []string `toml:"exclude"`
	// MemoryLimitMB do proprio orquestrador (engines tem os seus).
	MemoryLimitMB int `toml:"memory_limit_mb"`
}

// Schedule define o ritmo dos ciclos.
type Schedule struct {
	// Mode: "daemon" ou "cron". Em "cron" o binario roda um ciclo e sai.
	Mode string `toml:"mode"`
	// Incremental e o intervalo entre ciclos incrementais.
	Incremental Duration `toml:"incremental"`
	// FullCron e a agenda do scan completo (formato cron de 5 campos).
	FullCron string `toml:"full_cron"`
	// SignaturesCron e a agenda de atualizacao de assinaturas dos engines.
	SignaturesCron string `toml:"signatures_cron"`
	// QuietHours suspende scans num intervalo do dia ("02:00-06:00" vazio
	// significa sem restricao). Serve para quem tem pico de trafego conhecido.
	QuietHours string `toml:"quiet_hours"`
}

// VerdictConfig parametriza o motor de consenso. Os limiares e pesos sao
// configuraveis (FR-017); as regras de seguranca (whitelist e checksum
// oficial) nao sao.
type VerdictConfig struct {
	// Saturation e o teto da soma de pesos: score = min(1, soma/saturation).
	// Ver DECISIONS.md D-003.
	Saturation float64 `toml:"saturation"`
	// Thresholds: score minimo de cada nivel.
	ConfirmedAt  float64 `toml:"confirmed_at"`
	LikelyAt     float64 `toml:"likely_at"`
	SuspiciousAt float64 `toml:"suspicious_at"`
	// Multiplicadores por confianca do achado.
	SignatureMultiplier float64 `toml:"signature_multiplier"`
	HeuristicMultiplier float64 `toml:"heuristic_multiplier"`
	AnomalyMultiplier   float64 `toml:"anomaly_multiplier"`
	// Whitelist de caminhos (globs) que nunca sao quarentenados. Continuam
	// visiveis no relatorio (DECISIONS.md D-006).
	Whitelist []string `toml:"whitelist"`
}

// QuarantineConfig governa o cofre.
type QuarantineConfig struct {
	// Dir vazio = <data_dir>/quarantine.
	Dir string `toml:"dir"`
	// RetentionDays antes de um item ficar elegivel a purga. A purga nunca e
	// automatica sem que o item tenha passado deste prazo (Principio I).
	RetentionDays int `toml:"retention_days"`
	// AutoPurge liga a rotina periodica de purga dos expirados. Desligado
	// por padrao: apagar arquivo do usuario e sempre decisao dele.
	AutoPurge bool `toml:"auto_purge"`
	// NeutralizedExtension e o sufixo aplicado no cofre.
	NeutralizedExtension string `toml:"neutralized_extension"`
}

// Engine e a configuracao de um adaptador.
type Engine struct {
	Enabled bool `toml:"enabled"`
	// Weight e o peso do voto deste engine no consenso.
	Weight float64 `toml:"weight"`
	// Path forca o caminho do binario/phar quando o probe automatico nao
	// acha (hospedagens com PHP em lugar exotico).
	Path string `toml:"path"`
	// ExtraArgs sao repassados ao subprocesso.
	ExtraArgs []string `toml:"extra_args"`
	// Timeout sobrepoe limits.engine_timeout so para este engine.
	Timeout Duration `toml:"timeout"`
}

// Alerts reune os canais de notificacao.
type Alerts struct {
	Email    EmailConfig `toml:"email"`
	Webhooks []Webhook   `toml:"webhooks"`
}

// EmailConfig e o SMTP.
type EmailConfig struct {
	Enabled  bool   `toml:"enabled"`
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	// TLS: "starttls", "tls" ou "none".
	TLS  string   `toml:"tls"`
	From string   `toml:"from"`
	To   []string `toml:"to"`
	// Levels que disparam alerta imediato.
	Levels []string `toml:"levels"`
	// Digest diario.
	DigestEnabled bool   `toml:"digest_enabled"`
	DigestAt      string `toml:"digest_at"`
	// PanelURL entra no corpo do e-mail para o usuario chegar no achado.
	PanelURL string `toml:"panel_url"`
}

// Webhook e um endpoint assinado.
type Webhook struct {
	ID      string `toml:"id"`
	Enabled bool   `toml:"enabled"`
	URL     string `toml:"url"`
	// Secret e a chave do HMAC-SHA256.
	Secret string `toml:"secret"`
	// Events assinados. Sem inscricao, sem entrega.
	Events []string `toml:"events"`
}

// Web e o painel embutido.
type Web struct {
	Enabled bool `toml:"enabled"`
	// Listen e 127.0.0.1 por padrao. Expor em 0.0.0.0 exige acao consciente
	// do usuario e dispara aviso na validacao.
	Listen string `toml:"listen"`
	// SessionTTL da sessao autenticada.
	SessionTTL Duration `toml:"session_ttl"`
	// LoginRateLimit: tentativas por minuto por IP.
	LoginRateLimit int `toml:"login_rate_limit"`
}

// Logging do log estruturado.
type Logging struct {
	// Level: debug, info, warn, error.
	Level string `toml:"level"`
	// RetentionDays do log e das saidas brutas arquivadas.
	RetentionDays int `toml:"retention_days"`
	// RawOutputRetentionDays das saidas brutas de engine (auditoria e
	// reprocessamento por Parse).
	RawOutputRetentionDays int `toml:"raw_output_retention_days"`
}

// Path devolve o arquivo de onde este Config foi lido.
func (c *Config) Path() string { return c.path }

// SetPath define o destino de Save().
func (c *Config) SetPath(p string) { c.path = p }
