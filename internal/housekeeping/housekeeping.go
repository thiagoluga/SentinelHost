// Package housekeeping reúne a manutenção periódica do SentinelHost.
//
// Existe porque essas rotinas viviam só no daemon, e o modo PADRÃO do projeto
// é `cron` (Princípio III: tudo essencial precisa funcionar só com o cron do
// cPanel). O efeito prático era que, no caminho recomendado da documentação:
//
//   - webhook que falhava nunca era retentado — o backoff de 5 tentativas
//     existia no código e nunca acontecia;
//   - o resumo periódico nunca saía;
//   - ciclos mortos pela hospedagem ficavam `running` para sempre;
//   - a retenção configurada de log e de saída bruta nunca era aplicada, e os
//     dois cresciam até estourar a cota de disco da conta — o oposto exato do
//     Princípio IV, causado pela própria ferramenta.
//
// Agora `scan` e `daemon` chamam as mesmas rotinas.
package housekeeping

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Alerter é o que a manutenção precisa dos alertas. Interface local para que
// este pacote não dependa do pacote de alertas — uma entrega travada não pode
// ter como segurar a limpeza de disco.
type Alerter interface {
	RetryPending(ctx context.Context) (int, error)
	SendDigestIfDue(ctx context.Context) (bool, error)
}

// Result descreve o que a manutenção fez, para o log e para a CLI.
type Result struct {
	RetriedDeliveries int
	DigestSent        bool
	PurgedQuarantine  int
	PrunedEvents      int64
	PrunedRawDirs     int
	RecoveredScans    int
}

// Empty responde se não houve nada a fazer.
func (r Result) Empty() bool {
	return r.RetriedDeliveries == 0 && !r.DigestSent && r.PurgedQuarantine == 0 &&
		r.PrunedEvents == 0 && r.PrunedRawDirs == 0 && r.RecoveredScans == 0
}

// Deps são as peças que a manutenção usa. Vault e Alerts podem ser nil.
type Deps struct {
	Cfg    *config.Config
	Store  *store.Store
	Vault  *quarantine.Vault
	Alerts Alerter
	Now    func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Run executa todas as rotinas.
//
// Nenhuma falha interrompe as demais: se o webhook está fora do ar, a poda de
// disco ainda precisa acontecer. Os erros são agregados e devolvidos para
// registro, nunca propagados como falha do ciclo.
func Run(ctx context.Context, d Deps) (Result, error) {
	var res Result
	var erros []error

	res.RecoveredScans = recuperarCiclos(ctx, d, &erros)

	if d.Alerts != nil {
		if n, err := d.Alerts.RetryPending(ctx); err != nil {
			erros = append(erros, fmt.Errorf("retentativas de entrega: %w", err))
		} else {
			res.RetriedDeliveries = n
		}

		if enviado, err := d.Alerts.SendDigestIfDue(ctx); err != nil {
			erros = append(erros, fmt.Errorf("resumo periódico: %w", err))
		} else {
			res.DigestSent = enviado
		}
	}

	// A purga automática só age se o usuário a ligou, e o cofre continua
	// recusando qualquer item dentro da retenção — a manutenção não tem como
	// contornar essa barreira nem por engano.
	if d.Vault != nil && d.Cfg.Quarantine.AutoPurge {
		if n, err := d.Vault.PurgeExpired(ctx); err != nil {
			erros = append(erros, fmt.Errorf("purga de quarentena: %w", err))
		} else if n > 0 {
			res.PurgedQuarantine = n
			// Remoção definitiva de arquivo do usuário sempre vira registro,
			// mesmo tendo sido autorizada de antemão pela configuração.
			log(ctx, d, "warn", store.CatQuarantine,
				fmt.Sprintf("%d item(ns) expirado(s) purgado(s) definitivamente pela rotina automática", n))
		}
	}

	res.PrunedEvents = podarLog(ctx, d, &erros)
	res.PrunedRawDirs = podarSaidaBruta(ctx, d, &erros)

	if _, err := d.Store.PurgeExpiredSessions(ctx); err != nil {
		erros = append(erros, fmt.Errorf("sessões vencidas: %w", err))
	}

	return res, errors.Join(erros...)
}

// recuperarCiclos fecha ciclos que começaram e nunca terminaram.
//
// A hospedagem mata processos longos. Um ciclo interrompido fica `running` sem
// `finished_at`; deixá-lo assim para sempre faria o histórico mentir por
// omissão — e o registro como `killed` é o que deixa visível que houve perda
// de cobertura naquele período.
func recuperarCiclos(ctx context.Context, d Deps, erros *[]error) int {
	ids, err := d.Store.InterruptedScans(ctx)
	if err != nil {
		*erros = append(*erros, fmt.Errorf("buscando ciclos interrompidos: %w", err))
		return 0
	}

	n := 0
	for _, id := range ids {
		if err := d.Store.FinishScan(ctx, store.ScanRecord{
			ScanID: id, FinishedAt: d.now(), Status: schema.StatusKilled,
		}); err != nil {
			*erros = append(*erros, err)
			continue
		}
		n++
		log(ctx, d, "warn", store.CatScan,
			fmt.Sprintf("ciclo %s foi interrompido antes de terminar (processo morto?); registrado como killed", id))
	}
	return n
}

// podarLog aplica a retenção do log estruturado.
func podarLog(ctx context.Context, d Deps, erros *[]error) int64 {
	dias := d.Cfg.Logging.RetentionDays
	if dias <= 0 {
		return 0
	}
	corte := d.now().AddDate(0, 0, -dias)
	n, err := d.Store.PruneEvents(ctx, corte)
	if err != nil {
		*erros = append(*erros, fmt.Errorf("podando log: %w", err))
		return 0
	}
	return n
}

// podarSaidaBruta apaga as saídas brutas de engine além da retenção.
//
// A saída bruta é arquivada para auditoria e reprocessamento, mas ela é o que
// mais cresce: cada ciclo grava o stdout completo de cada engine. Numa conta
// com cota, sem poda isso enche o disco em semanas.
//
// Só diretórios de ciclo inteiros são removidos, e só pela data de
// modificação — nunca por nome, que é palpite sobre formato de id.
func podarSaidaBruta(ctx context.Context, d Deps, erros *[]error) int {
	dias := d.Cfg.Logging.RawOutputRetentionDays
	if dias <= 0 {
		return 0
	}
	raiz := d.Cfg.RawOutputDir()
	corte := d.now().AddDate(0, 0, -dias)

	entradas, err := os.ReadDir(raiz)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			*erros = append(*erros, fmt.Errorf("lendo %s: %w", raiz, err))
		}
		return 0
	}

	n := 0
	for _, e := range entradas {
		if ctx.Err() != nil {
			break
		}
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(corte) {
			continue
		}
		alvo := filepath.Join(raiz, e.Name())
		// Confere que o alvo continua dentro da área de dados antes de
		// remover recursivamente. Um nome inesperado nunca deve virar um
		// RemoveAll fora de onde a ferramenta manda.
		if !dentroDe(raiz, alvo) {
			continue
		}
		if err := os.RemoveAll(alvo); err != nil {
			*erros = append(*erros, fmt.Errorf("removendo %s: %w", alvo, err))
			continue
		}
		n++
	}
	if n > 0 {
		log(ctx, d, "info", store.CatSystem,
			fmt.Sprintf("%d diretório(s) de saída bruta removido(s) por retenção (%d dias)", n, dias))
	}
	return n
}

func dentroDe(raiz, alvo string) bool {
	r, err1 := filepath.Abs(raiz)
	a, err2 := filepath.Abs(alvo)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(r, a)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.IsAbs(rel) &&
		!(len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator))
}

func log(ctx context.Context, d Deps, nivel, cat, msg string) {
	_ = d.Store.Log(ctx, store.Event{TS: d.now(), Level: nivel, Category: cat, Message: msg})
}
