package adapter

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Este arquivo implementa a obrigacao 5 do contrato de adaptadores: panico ou
// timeout de UM adaptador nao derruba o ciclo — vira ScanReport{status:
// failed} e abstencao no consenso.
//
// A blindagem fica aqui, no orquestrador, e nao na boa vontade de cada
// adaptador. Um adaptador de terceiro com um bug de indice nao pode ser capaz
// de derrubar a protecao do site inteiro.

// SafeProbe executa Probe sem deixar panico escapar.
func SafeProbe(ctx context.Context, a Adapter, env Environment) (res ProbeResult) {
	slug := safeSlug(a)
	defer func() {
		if p := recover(); p != nil {
			res = Unavailable(fmt.Sprintf(
				"o adaptador %s entrou em panico durante o probe: %v", slug, p))
		}
	}()
	res = a.Probe(ctx, env)
	// Motivo vazio numa indisponibilidade e um bug do adaptador que penaliza
	// o usuario: ele fica sem saber o que fazer para habilitar o engine.
	if !res.Available && res.Reason == "" {
		res.Reason = "indisponivel (o adaptador nao informou o motivo)"
	}
	return res
}

// SafeScanAndParse executa Scan e Parse de um adaptador com blindagem total.
//
// Qualquer desfecho ruim — panico, erro, timeout, saida ilegivel, relatorio
// que nao passa na validacao do esquema — vira um ScanReport de falha, que o
// motor de veredito trata como abstencao. Em nenhuma hipotese vira "o engine
// nao achou nada".
func SafeScanAndParse(ctx context.Context, a Adapter, env Environment, req ScanRequest) (report schema.ScanReport) {
	slug := safeSlug(a)
	started := time.Now()

	defer func() {
		if p := recover(); p != nil {
			report = schema.FailedReport(req.ScanID, slug, schema.StatusFailed,
				fmt.Errorf("panico no adaptador %s: %v\n%s", slug, p, debug.Stack()),
				started)
		}
	}()

	raw, err := a.Scan(ctx, env, req)
	if err != nil {
		return schema.FailedReport(req.ScanID, slug, statusOr(raw.Status, schema.StatusFailed), err, started)
	}
	// Um Scan que "deu certo" mas devolveu status de falha ainda e falha: o
	// executor ja traduziu timeout e kill para o vocabulario do esquema.
	if raw.Status != "" && !raw.Status.CountsAsVote() {
		return schema.FailedReport(req.ScanID, slug, raw.Status, orErr(raw.Err, "engine nao completou"), started)
	}

	report, err = a.Parse(raw)
	if err != nil {
		return schema.FailedReport(req.ScanID, slug, schema.StatusFailed,
			fmt.Errorf("saida do engine %s nao pode ser interpretada: %w", slug, err), started)
	}

	// Preenche o que o adaptador pode ter esquecido, antes de validar.
	if report.SchemaVersion == "" {
		report.SchemaVersion = schema.Version
	}
	if report.ScanID == "" {
		report.ScanID = req.ScanID
	}
	if report.Engine == "" {
		report.Engine = slug
	}
	if report.Status == "" {
		report.Status = schema.StatusCompleted
	}
	if report.StartedAt.IsZero() {
		report.StartedAt = started
	}
	if report.FinishedAt.IsZero() {
		report.FinishedAt = time.Now()
	}
	if report.RawRef == "" {
		report.RawRef = raw.RawRef
	}
	if report.Scope.Root == "" {
		report.Scope.Root = req.Root
	}
	if report.Scope.Mode == "" {
		report.Scope.Mode = req.Mode
	}

	// Um relatorio invalido e pior que nenhum relatorio: ele entraria no
	// consenso carregando dados que o resto do sistema nao sabe interpretar.
	if err := report.Validate(); err != nil {
		return schema.FailedReport(req.ScanID, slug, schema.StatusFailed,
			fmt.Errorf("relatorio do engine %s nao cumpre o esquema: %w", slug, err), started)
	}

	return report
}

// SafeUpdateSignatures blinda a atualizacao de assinaturas.
func SafeUpdateSignatures(ctx context.Context, a Adapter, env Environment) (t time.Time, err error) {
	slug := safeSlug(a)
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panico ao atualizar assinaturas de %s: %v", slug, p)
		}
	}()
	return a.UpdateSignatures(ctx, env)
}

// SafeInstall blinda a instalacao.
func SafeInstall(ctx context.Context, a Adapter, env Environment) (err error) {
	slug := safeSlug(a)
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panico ao instalar %s: %v", slug, p)
		}
	}()
	return a.Install(ctx, env)
}

func safeSlug(a Adapter) (slug string) {
	defer func() {
		if recover() != nil {
			slug = "desconhecido"
		}
	}()
	if s := a.Info().Slug; s != "" {
		return s
	}
	return "desconhecido"
}

func statusOr(s, fallback schema.ScanStatus) schema.ScanStatus {
	if s == "" {
		return fallback
	}
	return s
}

func orErr(err error, msg string) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("%s", msg)
}
