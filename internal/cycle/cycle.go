// Package cycle orquestra um ciclo completo: varrer, escanear com os engines
// disponiveis, consolidar vereditos e agir.
//
// E o unico lugar que conhece todas as pecas. Cada uma delas continua sem
// conhecer as outras: os adaptadores nao sabem do veredito, o veredito nao
// sabe da quarentena, e a quarentena nao sabe dos alertas.
package cycle

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/lock"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

// Dispatcher entrega eventos aos canais de alerta.
//
// E uma interface para que o ciclo nao dependa do pacote de alertas: um
// webhook fora do ar nao pode ter como derrubar um scan.
type Dispatcher interface {
	Dispatch(ctx context.Context, event string, data any) error
}

// Runner executa ciclos.
type Runner struct {
	cfg      *config.Config
	store    *store.Store
	registry *adapter.Registry
	exec     *sexec.Runner
	verdict  *verdict.Engine
	vault    *quarantine.Vault
	dispatch Dispatcher
	now      func() time.Time
}

// New monta o runner.
func New(cfg *config.Config, st *store.Store, reg *adapter.Registry, vault *quarantine.Vault) *Runner {
	return &Runner{
		cfg:      cfg,
		store:    st,
		registry: reg,
		exec: sexec.New(sexec.Limits{
			Nice:        cfg.Limits.Nice,
			IoniceClass: cfg.Limits.IoniceClass,
			Timeout:     cfg.Limits.EngineTimeout.Duration,
		}, cfg.RawOutputDir()),
		verdict: verdict.New(cfg.Verdict, cfg.Engines),
		vault:   vault,
		now:     time.Now,
	}
}

// WithDispatcher liga os alertas.
func (r *Runner) WithDispatcher(d Dispatcher) *Runner {
	r.dispatch = d
	return r
}

// WithClock troca o relogio. Uso restrito a testes.
func (r *Runner) WithClock(fn func() time.Time) *Runner {
	r.now = fn
	return r
}

// Options parametriza o ciclo.
type Options struct {
	// Mode: incremental, full ou targeted.
	Mode schema.ScanMode
	// Paths so e usado em modo targeted.
	Paths []string
	// DryRun calcula tudo e nao age, mesmo com acao automatica liberada.
	DryRun bool
	// SkipLock desliga o lock de instancia unica. So para teste.
	SkipLock bool
}

// EngineOutcome resume o que aconteceu com um engine.
type EngineOutcome struct {
	Slug      string
	Available bool
	Reason    string
	Status    schema.ScanStatus
	Findings  int
	Duration  time.Duration
	// Skipped e o que o engine pulou e por que, vindo do proprio relatorio.
	//
	// Sobe do ScanReport ate aqui porque o relatorio em texto precisa mostrar
	// isso: o wp-checksums registra quantos plugins NAO conseguiu verificar, e
	// esse numero nao pode ficar so no banco. Plugin nao verificado que nao
	// aparece em lugar nenhum se parece com plugin verificado e limpo — a
	// mesma falha silenciosa que o projeto combate em todo lugar.
	Skipped map[string]int
}

// Summary e o resultado do ciclo.
type Summary struct {
	ScanID          string
	Mode            schema.ScanMode
	Roots           []string
	StartedAt       time.Time
	FinishedAt      time.Time
	Status          schema.ScanStatus
	FilesConsidered int
	FilesScanned    int
	SkippedCounts   map[string]int

	Engines     []EngineOutcome
	Abstentions map[string]string

	Verdicts    []schema.Verdict
	LevelCounts map[schema.Level]int
	ActionCts   map[schema.ActionTaken]int

	// ObservationReason explica por que nenhuma acao automatica ocorreu.
	ObservationReason string
}

// Run executa um ciclo completo.
func (r *Runner) Run(ctx context.Context, opts Options) (Summary, error) {
	started := r.now()
	sum := Summary{
		Mode:          orMode(opts.Mode),
		Roots:         r.cfg.General.Roots,
		StartedAt:     started,
		Status:        schema.StatusCompleted,
		SkippedCounts: map[string]int{},
		LevelCounts:   map[schema.Level]int{},
		ActionCts:     map[schema.ActionTaken]int{},
	}
	sum.ScanID = scanID(started, sum.Mode)

	if len(r.cfg.General.Roots) == 0 {
		return sum, fmt.Errorf("nenhuma raiz configurada: nao ha o que escanear")
	}

	if !opts.SkipLock {
		l, err := lock.Acquire(r.cfg.LockPath())
		if err != nil {
			return sum, err
		}
		defer func() { _ = l.Release() }()
	}

	if err := r.cfg.EnsureDataDirs(); err != nil {
		return sum, err
	}

	// Ciclo com timeout proprio: a hospedagem mata processos longos, e e
	// melhor terminar por decisao propria (com relatorio parcial gravado) do
	// que ser morto no meio sem deixar rastro.
	if d := r.cfg.Limits.CycleTimeout.Duration; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	if err := r.store.StartScan(ctx, store.ScanRecord{
		ScanID: sum.ScanID, Mode: sum.Mode, Roots: sum.Roots, StartedAt: started,
	}); err != nil {
		return sum, err
	}
	r.log(ctx, "info", store.CatScan, "ciclo iniciado", sum.ScanID, map[string]any{
		"mode": string(sum.Mode), "roots": sum.Roots,
	})

	// 1. Descobrir o que escanear.
	alvos, bl, err := r.collectTargets(ctx, opts, &sum)
	if err != nil {
		r.finish(ctx, &sum, schema.StatusFailed)
		return sum, err
	}

	// 2. Rodar os engines disponiveis.
	reports := r.runEngines(ctx, opts, alvos, &sum)

	// 3. Consolidar.
	consolidado := r.verdict.Consolidate(verdict.Input{
		ScanID:          sum.ScanID,
		Reports:         reports,
		ExpectedEngines: r.enabledSlugs(),
		Whitelist:       r.cfg.Verdict.Whitelist,
		Now:             r.now(),
	})
	sum.Abstentions = consolidado.Abstentions
	sum.Verdicts = consolidado.Verdicts

	// 4. Persistir achados e vereditos.
	if err := r.persist(ctx, reports, consolidado.Verdicts); err != nil {
		r.finish(ctx, &sum, schema.StatusPartial)
		return sum, err
	}

	// 5. Agir.
	r.act(ctx, opts, &sum)

	// 6. Atualizar baseline e fechar.
	if bl != nil {
		if err := bl.Save(r.cfg.BaselinePath()); err != nil {
			// Baseline nao salvo custa um ciclo mais caro depois, nao a
			// protecao. Registra e segue.
			r.log(ctx, "warn", store.CatSystem, "nao foi possivel salvar o baseline: "+err.Error(), sum.ScanID, nil)
		}
	}

	for _, v := range sum.Verdicts {
		sum.LevelCounts[v.Level]++
		sum.ActionCts[v.ActionTaken]++
	}

	status := schema.StatusCompleted
	if sum.SkippedCounts["truncated"] > 0 {
		status = schema.StatusPartial
	}
	r.finish(ctx, &sum, status)
	r.emit(ctx, "scan.completed", sum.Event())
	return sum, nil
}

// collectTargets varre as raizes e decide a lista de arquivos do ciclo.
func (r *Runner) collectTargets(ctx context.Context, opts Options, sum *Summary) ([]string, *baseline.Baseline, error) {
	if sum.Mode == schema.ModeTargeted {
		sum.FilesConsidered = len(opts.Paths)
		sum.FilesScanned = len(opts.Paths)
		return opts.Paths, nil, nil
	}

	bl, err := baseline.Load(r.cfg.BaselinePath(), r.cfg.General.Roots)
	if err != nil {
		// Baseline corrompido ja devolveu um vazio utilizavel; so registra.
		r.log(ctx, "warn", store.CatSystem, err.Error(), sum.ScanID, nil)
	}

	var todas []baseline.Entry
	for _, root := range r.cfg.General.Roots {
		res, err := baseline.Walk(ctx, baseline.WalkOptions{
			Root:             root,
			Exclude:          r.cfg.Limits.Exclude,
			MaxDepth:         r.cfg.Limits.MaxDepth,
			MaxFileSizeBytes: int64(r.cfg.Limits.MaxFileSizeMB) << 20,
			MaxFiles:         r.cfg.Limits.MaxFilesPerCycle,
		})
		if err != nil {
			// Raiz inacessivel nao derruba as outras raizes.
			r.log(ctx, "error", store.CatScan,
				fmt.Sprintf("raiz %s inacessivel: %v", root, err), sum.ScanID, nil)
			sum.SkippedCounts["root_unreadable"]++
			continue
		}
		for k, v := range res.SkippedCounts {
			sum.SkippedCounts[k] += v
		}
		if res.Truncated {
			sum.SkippedCounts["truncated"]++
		}
		sum.FilesConsidered += res.Considered
		todas = append(todas, res.Entries...)
	}

	// Hash so do que mudou no par tamanho+mtime: e o que torna o ciclo
	// incremental barato o bastante para rodar de hora em hora.
	var paraHashear []baseline.Entry
	if sum.Mode == schema.ModeFull {
		paraHashear = todas
	} else {
		paraHashear = bl.NeedsHash(todas)
	}
	hasheadas := baseline.HashEntries(ctx, paraHashear, sum.SkippedCounts)

	// Reune o estado atual: o que foi hasheado agora + o que o baseline ja
	// conhecia e nao mudou.
	novosHashes := make(map[string]baseline.Entry, len(hasheadas))
	for _, e := range hasheadas {
		novosHashes[e.Path] = e
	}
	atual := make([]baseline.Entry, 0, len(todas))
	for _, e := range todas {
		if h, ok := novosHashes[e.Path]; ok {
			atual = append(atual, h)
			continue
		}
		if anterior, ok := bl.Get(e.Path); ok {
			e.SHA256 = anterior.SHA256
		}
		atual = append(atual, e)
	}

	var alvos []string
	if sum.Mode == schema.ModeFull {
		for _, e := range atual {
			if e.SHA256 != "" {
				alvos = append(alvos, e.Path)
			}
		}
	} else {
		d := bl.Compare(atual)
		alvos = d.Targets()
		sum.SkippedCounts["unchanged"] += d.Unchanged
		bl.Update(atual, d.Removed)
	}
	if sum.Mode == schema.ModeFull {
		bl.Update(atual, nil)
	}

	sum.FilesScanned = len(alvos)
	return alvos, bl, nil
}

// runEngines sonda e executa cada engine habilitado.
func (r *Runner) runEngines(ctx context.Context, opts Options, alvos []string, sum *Summary) []schema.ScanReport {
	var reports []schema.ScanReport
	batcher := sexec.NewBatcher(r.cfg.Limits.BatchSize, r.cfg.Limits.BatchPause.Duration)

	for _, slug := range r.registry.Slugs() {
		if !r.cfg.EngineEnabled(slug) {
			continue
		}
		a, _ := r.registry.Get(slug)
		env := r.envFor(slug)

		probe := adapter.SafeProbe(ctx, a, env)
		_ = r.store.SaveEngineState(ctx, store.EngineState{
			Slug:                slug,
			Available:           probe.Available,
			UnavailableReason:   probe.Reason,
			Version:             probe.Version,
			BinaryPath:          probe.BinaryPath,
			SignaturesUpdatedAt: probe.SignaturesUpdatedAt,
			LastProbeAt:         r.now(),
		})

		if !probe.Available {
			// Engine indisponivel e informacao, nao silencio. O usuario tem
			// que ver o motivo (FR-001).
			sum.Engines = append(sum.Engines, EngineOutcome{Slug: slug, Reason: probe.Reason})
			r.log(ctx, "warn", store.CatEngine,
				fmt.Sprintf("engine %s indisponivel: %s", slug, probe.Reason), sum.ScanID, nil)
			continue
		}

		if len(alvos) == 0 {
			// Nada mudou: o engine nao roda, mas isso NAO e abstencao —
			// e um ciclo sem alvos. Registrar como relatorio completo com
			// zero achados mantem a contabilidade honesta.
			reports = append(reports, schema.ScanReport{
				SchemaVersion: schema.Version, ScanID: sum.ScanID, Engine: slug,
				EngineVersion: probe.Version, Status: schema.StatusCompleted,
				StartedAt: r.now(), FinishedAt: r.now(),
				Scope:    schema.Scope{Root: firstRoot(r.cfg), Mode: sum.Mode},
				Findings: []schema.Finding{},
			})
			sum.Engines = append(sum.Engines, EngineOutcome{Slug: slug, Available: true, Status: schema.StatusCompleted})
			continue
		}

		inicio := r.now()
		parciais := r.runEngineBatches(ctx, a, env, slug, alvos, sum, batcher, probe.Version)
		merged := mergeReports(sum.ScanID, slug, probe.Version, parciais, firstRoot(r.cfg), sum.Mode)
		reports = append(reports, merged)

		outcome := EngineOutcome{
			Slug: slug, Available: true, Status: merged.Status,
			Findings: len(merged.Findings), Duration: r.now().Sub(inicio),
			Skipped: merged.Scope.SkippedReasonCounts,
		}
		if merged.Abstains() {
			outcome.Reason = merged.Error
			r.emit(ctx, "engine.failed", merged)
		}
		sum.Engines = append(sum.Engines, outcome)

		_ = r.store.SaveScanReport(ctx, merged)
		_ = r.store.SaveEngineState(ctx, store.EngineState{
			Slug: slug, Available: true, Version: probe.Version,
			LastProbeAt: r.now(), LastRunAt: r.now(), LastRunStatus: string(merged.Status),
		})
	}

	_ = opts
	return reports
}

// runEngineBatches executa o engine em lotes, com pausa entre eles.
//
// Engines que NAO sabem limitar a varredura a uma lista de arquivos
// (Info().ScopeAware == false) sao executados UMA vez, com a lista inteira.
// Executa-los por lote multiplicaria o trabalho pelo numero de lotes, porque
// cada invocacao varre a raiz completa de novo — medido no container de
// validacao: num WordPress de 3 mil arquivos, o AMWScan levou 13m54s e o
// wp-checksums 7m02s num ciclo que deveria custar minutos.
func (r *Runner) runEngineBatches(
	ctx context.Context,
	a adapter.Adapter,
	env adapter.Environment,
	slug string,
	alvos []string,
	sum *Summary,
	batcher *sexec.Batcher,
	engineVersion string,
) []schema.ScanReport {
	var parciais []schema.ScanReport

	executar := func(ctx context.Context, lote []string) error {
		rep := adapter.SafeScanAndParse(ctx, a, env, adapter.ScanRequest{
			ScanID:           sum.ScanID,
			Root:             firstRoot(r.cfg),
			Paths:            lote,
			Mode:             sum.Mode,
			Timeout:          r.cfg.EngineTimeoutFor(slug),
			MaxFileSizeBytes: int64(r.cfg.Limits.MaxFileSizeMB) << 20,
		})
		if rep.EngineVersion == "" {
			rep.EngineVersion = engineVersion
		}
		parciais = append(parciais, rep)
		return nil
	}

	if !safeInfo(a).ScopeAware {
		// Uma execucao so. A pausa entre lotes nao se aplica aqui — o que
		// segura o consumo e o nice/ionice do executor.
		if err := executar(ctx, alvos); err != nil {
			parciais = append(parciais, schema.FailedReport(sum.ScanID, slug, schema.StatusKilled, err, r.now()))
		}
		return parciais
	}

	err := batcher.Each(ctx, alvos, func(ctx context.Context, lote []string) error {
		rep := adapter.SafeScanAndParse(ctx, a, env, adapter.ScanRequest{
			ScanID:           sum.ScanID,
			Root:             firstRoot(r.cfg),
			Paths:            lote,
			Mode:             sum.Mode,
			Timeout:          r.cfg.EngineTimeoutFor(slug),
			MaxFileSizeBytes: int64(r.cfg.Limits.MaxFileSizeMB) << 20,
		})
		if rep.EngineVersion == "" {
			rep.EngineVersion = engineVersion
		}
		parciais = append(parciais, rep)
		return nil
	})
	if err != nil {
		// Cancelamento do ciclo inteiro. O que ja rodou continua valendo.
		parciais = append(parciais, schema.FailedReport(sum.ScanID, slug, schema.StatusKilled, err, r.now()))
	}
	return parciais
}

// envFor monta o ambiente do adaptador.
func (r *Runner) envFor(slug string) adapter.Environment {
	e := r.cfg.Engines[slug]
	binPath := e.Path
	if slug == "wp-checksums" && binPath == "" {
		// Adaptador nativo: o que ele precisa saber e onde procurar, nao
		// qual binario rodar.
		binPath = firstRoot(r.cfg)
	}
	return adapter.Environment{
		DataDir:    r.cfg.General.DataDir,
		Runner:     r.exec,
		BinaryPath: binPath,
		ExtraArgs:  e.ExtraArgs,
	}
}

func (r *Runner) enabledSlugs() []string {
	var out []string
	for slug := range r.cfg.Engines {
		if r.cfg.EngineEnabled(slug) {
			out = append(out, slug)
		}
	}
	sort.Strings(out)
	return out
}

// safeInfo le o Info do adaptador sem deixar um panico derrubar o ciclo.
//
// Um adaptador de terceiro nao pode decidir o destino do ciclo nem no metodo
// mais trivial que ele expoe.
func safeInfo(a adapter.Adapter) (info adapter.Info) {
	defer func() {
		if recover() != nil {
			// Sem informacao confiavel, o lado seguro e tratar como
			// scope-aware: uma execucao por lote e mais lenta, nunca incorreta.
			info = adapter.Info{ScopeAware: true}
		}
	}()
	return a.Info()
}

func firstRoot(cfg *config.Config) string {
	if len(cfg.General.Roots) == 0 {
		return ""
	}
	return cfg.General.Roots[0]
}

func orMode(m schema.ScanMode) schema.ScanMode {
	if m == "" {
		return schema.ModeIncremental
	}
	return m
}

func scanID(t time.Time, mode schema.ScanMode) string {
	prefixo := "s"
	if mode == schema.ModeFull {
		prefixo = "sf"
	}
	return fmt.Sprintf("%s_%s", prefixo, t.UTC().Format("20060102_150405"))
}
