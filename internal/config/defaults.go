package config

import (
	"os"
	"path/filepath"
	"time"
)

// Pesos padrao por engine, de docs/esquema-e-adaptadores.md secao 2.1.
const (
	WeightWPChecksums = 1.5 // core adulterado = quase certeza
	WeightMaldet      = 1.0
	WeightAMWScan     = 0.8
	WeightPMF         = 0.8
	WeightWordfence   = 1.0 // pos-MVP
	WeightClamAV      = 0.6 // pos-MVP
)

// DefaultDataDir e ~/.sentinelhost. Fica no espaco do usuario porque nao ha
// root (Principio III).
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Sem HOME (cron minimalista de algumas hospedagens), cai no diretorio
		// atual em vez de falhar: e melhor rodar num lugar previsivel do que
		// nao rodar.
		return ".sentinelhost"
	}
	return filepath.Join(home, ".sentinelhost")
}

// DefaultConfigPath e <data_dir>/config.toml.
func DefaultConfigPath() string {
	return filepath.Join(DefaultDataDir(), "config.toml")
}

// Default devolve a configuracao inicial.
//
// Os padroes sao deliberadamente conservadores: observacao ligada, nice 19,
// incremental de 1h, sem purga automatica, painel so em localhost. A primeira
// experiencia do usuario tem que ser "nao quebrou nada", nao "que bom que fiz
// backup".
func Default() *Config {
	data := DefaultDataDir()
	return &Config{
		General: General{
			Roots:   nil, // sem raiz definida, o scan recusa rodar
			DataDir: data,
			// Observacao ligada de saida. Junto com o periodo de graca de 7
			// dias, garante que a ferramenta so passe a mexer em arquivo
			// depois que o usuario tiver visto o que ela acha.
			ObservationMode: true,
			GracePeriodDays: 7,
			Locale:          "pt-BR",
		},
		Limits: Limits{
			Nice:             19,
			IoniceClass:      3, // idle
			MaxFileSizeMB:    16,
			EngineTimeout:    D(5 * time.Minute),
			CycleTimeout:     D(30 * time.Minute),
			BatchSize:        200,
			BatchPause:       D(500 * time.Millisecond),
			MaxDepth:         20,
			MaxFilesPerCycle: 200000,
			MemoryLimitMB:    128,
			Exclude: []string{
				// Cache e uploads binarios: volume enorme, risco baixo.
				"**/wp-content/cache/**",
				"**/wp-content/uploads/**/*.jpg",
				"**/wp-content/uploads/**/*.jpeg",
				"**/wp-content/uploads/**/*.png",
				"**/wp-content/uploads/**/*.gif",
				"**/wp-content/uploads/**/*.webp",
				"**/wp-content/uploads/**/*.svg",
				"**/wp-content/uploads/**/*.mp4",
				"**/wp-content/uploads/**/*.pdf",
				"**/node_modules/**",
				"**/vendor/**/tests/**",
				"**/.git/**",
				"**/.svn/**",
				// O proprio diretorio de dados: escanear o cofre de quarentena
				// re-detectaria o que ja foi neutralizado, em loop.
				"**/.sentinelhost/**",
			},
		},
		Schedule: Schedule{
			Mode:           "cron", // hospedagem compartilhada raramente mantem daemon vivo
			Incremental:    D(time.Hour),
			FullCron:       "0 3 * * 0", // domingo 03:00
			SignaturesCron: "0 2 * * *", // todo dia 02:00
		},
		Verdict: VerdictConfig{
			// Ver DECISIONS.md D-003 para a razao do teto 2.0.
			Saturation:          2.0,
			ConfirmedAt:         0.9,
			LikelyAt:            0.6,
			SuspiciousAt:        0.3,
			SignatureMultiplier: 1.0,
			HeuristicMultiplier: 0.8,
			AnomalyMultiplier:   0.55,
			Whitelist:           []string{},
		},
		Quarantine: QuarantineConfig{
			Dir:           "", // <data_dir>/quarantine
			RetentionDays: 30,
			// Desligado: apagar arquivo do usuario e sempre decisao dele.
			AutoPurge:            false,
			NeutralizedExtension: ".quarantined",
		},
		Engines: map[string]Engine{
			"wp-checksums":       {Enabled: true, Weight: WeightWPChecksums},
			"amwscan":            {Enabled: true, Weight: WeightAMWScan},
			"php-malware-finder": {Enabled: true, Weight: WeightPMF},
			"maldet":             {Enabled: true, Weight: WeightMaldet},
		},
		Alerts: Alerts{
			Email: EmailConfig{
				Enabled: false,
				Port:    587,
				TLS:     "starttls",
				// So confirmed e likely por padrao: alertar em suspicious de
				// saida treina o usuario a ignorar os e-mails.
				Levels:        []string{"confirmed", "likely"},
				DigestEnabled: false,
				DigestAt:      "08:00",
			},
			Webhooks: []Webhook{},
		},
		Web: Web{
			Enabled: true,
			// 127.0.0.1 por padrao. Acesso via tunel SSH ou porta liberada
			// conscientemente (restricao explicita da constituicao).
			Listen:         "127.0.0.1:8787",
			SessionTTL:     D(12 * time.Hour),
			LoginRateLimit: 10,
		},
		Logging: Logging{
			Level:                  "info",
			RetentionDays:          90,
			RawOutputRetentionDays: 14,
		},
	}
}

// QuarantineDir resolve o diretorio efetivo do cofre.
func (c *Config) QuarantineDir() string {
	if c.Quarantine.Dir != "" {
		return c.Quarantine.Dir
	}
	return filepath.Join(c.General.DataDir, "quarantine")
}

// DatabasePath e o SQLite de estado.
func (c *Config) DatabasePath() string {
	return filepath.Join(c.General.DataDir, "sentinelhost.db")
}

// RawOutputDir guarda as saidas brutas arquivadas dos engines.
func (c *Config) RawOutputDir() string {
	return filepath.Join(c.General.DataDir, "raw")
}

// BaselinePath e o arquivo de baseline de hashes.
func (c *Config) BaselinePath() string {
	return filepath.Join(c.General.DataDir, "baseline.json")
}

// LockPath e o lock de instancia unica.
func (c *Config) LockPath() string {
	return filepath.Join(c.General.DataDir, "sentinelhost.lock")
}

// EngineTimeoutFor devolve o timeout efetivo de um engine.
func (c *Config) EngineTimeoutFor(slug string) time.Duration {
	if e, ok := c.Engines[slug]; ok && e.Timeout.Duration > 0 {
		return e.Timeout.Duration
	}
	return c.Limits.EngineTimeout.Duration
}

// WeightFor devolve o peso configurado de um engine. Engine desconhecido pesa
// zero: um adaptador nao registrado nao pode influenciar veredito.
func (c *Config) WeightFor(slug string) float64 {
	if e, ok := c.Engines[slug]; ok {
		return e.Weight
	}
	return 0
}

// EngineEnabled responde se o engine esta ligado na configuracao.
func (c *Config) EngineEnabled(slug string) bool {
	e, ok := c.Engines[slug]
	return ok && e.Enabled
}

// InGracePeriod responde se a instalacao ainda esta no periodo em que nenhuma
// acao automatica acontece (DECISIONS.md D-007).
func (c *Config) InGracePeriod(now time.Time) bool {
	if c.General.GracePeriodDays <= 0 {
		return false
	}
	if c.General.FirstRunAt.IsZero() {
		// Ainda nao houve primeiro ciclo: estamos no inicio do periodo, nao
		// fora dele. Tratar "nunca rodou" como "graca expirada" deixaria a
		// primeira execucao ja podendo quarentenar.
		return true
	}
	return now.Before(c.General.FirstRunAt.AddDate(0, 0, c.General.GracePeriodDays))
}

// GracePeriodEndsAt devolve quando o periodo de graca expira. Zero se nao ha
// periodo de graca ou se a ferramenta ainda nao rodou.
func (c *Config) GracePeriodEndsAt() time.Time {
	if c.General.GracePeriodDays <= 0 || c.General.FirstRunAt.IsZero() {
		return time.Time{}
	}
	return c.General.FirstRunAt.AddDate(0, 0, c.General.GracePeriodDays)
}

// AutomaticActionAllowed e a porta unica pela qual a quarentena automatica
// pode passar. Concentrada aqui para que nenhum caminho de codigo consiga
// agir automaticamente por engano (DECISIONS.md D-008).
func (c *Config) AutomaticActionAllowed(now time.Time) (bool, string) {
	if c.General.ObservationMode {
		return false, "modo observacao ativo"
	}
	if c.InGracePeriod(now) {
		end := c.GracePeriodEndsAt()
		if end.IsZero() {
			return false, "periodo de graca ativo (primeiro ciclo ainda nao registrado)"
		}
		return false, "periodo de graca ativo ate " + end.Format("2006-01-02")
	}
	return true, ""
}
