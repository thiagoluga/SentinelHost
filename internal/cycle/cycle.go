// Package cycle orchestrates a complete cycle: walk, scan with the available
// engines, consolidate verdicts and act.
//
// It is the only place that knows every piece. Each of them still knows nothing
// about the others: the adapters do not know about the verdict, the verdict does
// not know about the quarantine, and the quarantine does not know about the
// alerts.
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

// Dispatcher delivers events to the alert channels.
//
// It is an interface so the cycle does not depend on the alerts package: a
// webhook that is down must have no way of taking a scan down.
type Dispatcher interface {
	Dispatch(ctx context.Context, event string, data any) error
}

// Runner runs cycles.
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

// New assembles the runner.
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

// WithDispatcher wires the alerts up.
func (r *Runner) WithDispatcher(d Dispatcher) *Runner {
	r.dispatch = d
	return r
}

// WithClock swaps the clock. Tests only.
func (r *Runner) WithClock(fn func() time.Time) *Runner {
	r.now = fn
	return r
}

// Options parameterizes the cycle.
type Options struct {
	// Mode: incremental, full or targeted.
	Mode schema.ScanMode
	// Paths is only used in targeted mode.
	Paths []string
	// DryRun computes everything and acts on nothing, even with automatic action
	// allowed.
	DryRun bool
	// SkipLock turns the single-instance lock off. Tests only.
	SkipLock bool
}

// EngineOutcome summarizes what happened to an engine.
type EngineOutcome struct {
	Slug      string
	Available bool
	Reason    string
	Status    schema.ScanStatus
	Findings  int
	Duration  time.Duration
	// Skipped is what the engine skipped and why, taken from its own report.
	//
	// It travels up from the ScanReport to here because the text report has to
	// show it: wp-checksums records how many plugins it could NOT verify, and that
	// number must not stay only in the database. An unverified plugin that shows
	// up nowhere looks like a plugin that was verified and found clean — the same
	// silent failure the project fights everywhere.
	Skipped map[string]int
}

// Summary is the cycle's result.
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

	// ObservationReason explains why no automatic action took place.
	ObservationReason string
}

// AnyEngineVoted answers whether a single engine actually contributed to this cycle.
//
// It is the cycle-level counterpart of ScanStatus.CountsAsVote(). When it is false the
// cycle looked at nothing, and "no findings" carries no information at all — so the
// status, the exit code and the report all have to say so rather than let the absence
// of verdicts read as good news.
func (s *Summary) AnyEngineVoted() bool {
	for _, e := range s.Engines {
		if e.Available && e.Status.CountsAsVote() {
			return true
		}
	}
	return false
}

// Run runs a complete cycle.
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
		return sum, fmt.Errorf("no root configured: there is nothing to scan")
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

	// The cycle gets a timeout of its own: the hosting kills long processes, and
	// finishing by our own decision (with a partial report written) beats being
	// killed halfway leaving no trace.
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
	r.log(ctx, "info", store.CatScan, "cycle started", sum.ScanID, map[string]any{
		"mode": string(sum.Mode), "roots": sum.Roots,
	})

	// 1. Find out what to scan.
	targets, bl, err := r.collectTargets(ctx, opts, &sum)
	if err != nil {
		r.finish(ctx, &sum, schema.StatusFailed)
		return sum, err
	}

	// 2. Run the available engines.
	reports := r.runEngines(ctx, opts, targets, &sum)

	// 3. Consolidate.
	consolidated := r.verdict.Consolidate(verdict.Input{
		ScanID:          sum.ScanID,
		Reports:         reports,
		ExpectedEngines: r.enabledSlugs(),
		Whitelist:       r.cfg.Verdict.Whitelist,
		Now:             r.now(),
	})
	sum.Abstentions = consolidated.Abstentions
	sum.Verdicts = consolidated.Verdicts

	// 4. Persist findings and verdicts.
	if err := r.persist(ctx, reports, consolidated.Verdicts); err != nil {
		r.finish(ctx, &sum, schema.StatusPartial)
		return sum, err
	}

	// 5. Act.
	r.act(ctx, opts, &sum)

	// 6. Update the baseline and close.
	if bl != nil {
		if err := bl.Save(r.cfg.BaselinePath()); err != nil {
			// An unsaved baseline costs a more expensive cycle later, not the
			// protection. Record it and move on.
			r.log(ctx, "warn", store.CatSystem, "could not save the baseline: "+err.Error(), sum.ScanID, nil)
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

	// A cycle in which NO engine voted did not scan anything, and must never be recorded
	// as `completed`.
	//
	// `ScanStatus.CountsAsVote()` already enforces this one level down: an engine that
	// could not run abstains rather than reporting zero findings. The cycle had no
	// equivalent, so four abstentions out of four still produced
	// `status: completed`, `verdicts: {}` and exit code 0 — which to the panel, to a
	// webhook consumer, or to anything checking `status == "completed" && no verdicts`
	// is indistinguishable from "scanned everything, site is clean".
	//
	// That is this project's defining failure mode reaching the machine-readable
	// interface, where nobody is reading a sentence about reduced coverage. The
	// human-readable output did say so; JSON, exit codes and the store did not.
	//
	// Some abstentions still count as `completed`: a cycle with one working engine
	// really did scan, and its result is incomplete rather than absent. Marking every
	// such cycle partial would make `partial` the permanent normal state on any host
	// without yara and maldet installed — which is most of them — and a status that is
	// always on carries no information.
	if !sum.AnyEngineVoted() {
		status = schema.StatusPartial
	}
	r.finish(ctx, &sum, status)
	r.emit(ctx, "scan.completed", sum.Event())
	return sum, nil
}

// collectTargets walks the roots and decides the cycle's file list.
func (r *Runner) collectTargets(ctx context.Context, opts Options, sum *Summary) ([]string, *baseline.Baseline, error) {
	if sum.Mode == schema.ModeTargeted {
		sum.FilesConsidered = len(opts.Paths)
		sum.FilesScanned = len(opts.Paths)
		return opts.Paths, nil, nil
	}

	bl, err := baseline.Load(r.cfg.BaselinePath(), r.cfg.General.Roots)
	if err != nil {
		// A corrupted baseline already returned a usable empty one; just record it.
		r.log(ctx, "warn", store.CatSystem, err.Error(), sum.ScanID, nil)
	}

	var all []baseline.Entry
	for _, root := range r.cfg.General.Roots {
		res, err := baseline.Walk(ctx, baseline.WalkOptions{
			Root:             root,
			Exclude:          r.cfg.Limits.Exclude,
			MaxDepth:         r.cfg.Limits.MaxDepth,
			MaxFileSizeBytes: int64(r.cfg.Limits.MaxFileSizeMB) << 20,
			MaxFiles:         r.cfg.Limits.MaxFilesPerCycle,
		})
		if err != nil {
			// An inaccessible root does not take the other roots down.
			r.log(ctx, "error", store.CatScan,
				fmt.Sprintf("root %s is inaccessible: %v", root, err), sum.ScanID, nil)
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
		all = append(all, res.Entries...)
	}

	// Hash only what changed in the size+mtime pair: that is what makes the
	// incremental cycle cheap enough to run hourly.
	var toHash []baseline.Entry
	if sum.Mode == schema.ModeFull {
		toHash = all
	} else {
		toHash = bl.NeedsHash(all)
	}
	hashed := baseline.HashEntries(ctx, toHash, sum.SkippedCounts)

	// Assemble the current state: what was just hashed + what the baseline
	// already knew and did not change.
	newHashes := make(map[string]baseline.Entry, len(hashed))
	for _, e := range hashed {
		newHashes[e.Path] = e
	}
	current := make([]baseline.Entry, 0, len(all))
	for _, e := range all {
		if h, ok := newHashes[e.Path]; ok {
			current = append(current, h)
			continue
		}
		if previous, ok := bl.Get(e.Path); ok {
			e.SHA256 = previous.SHA256
		}
		current = append(current, e)
	}

	var targets []string
	if sum.Mode == schema.ModeFull {
		for _, e := range current {
			if e.SHA256 != "" {
				targets = append(targets, e.Path)
			}
		}
	} else {
		d := bl.Compare(current)
		targets = d.Targets()
		sum.SkippedCounts["unchanged"] += d.Unchanged
		bl.Update(current, d.Removed)
	}
	if sum.Mode == schema.ModeFull {
		bl.Update(current, nil)
	}

	sum.FilesScanned = len(targets)
	return targets, bl, nil
}

// runEngines probes and runs each enabled engine.
func (r *Runner) runEngines(ctx context.Context, opts Options, targets []string, sum *Summary) []schema.ScanReport {
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
			// An unavailable engine is information, not silence. The user has to
			// see the reason (FR-001).
			sum.Engines = append(sum.Engines, EngineOutcome{Slug: slug, Reason: probe.Reason})
			r.log(ctx, "warn", store.CatEngine,
				fmt.Sprintf("engine %s is unavailable: %s", slug, probe.Reason), sum.ScanID, nil)
			continue
		}

		if len(targets) == 0 {
			// Nothing changed: the engine does not run, but that is NOT an
			// abstention — it is a cycle with no targets. Recording it as a
			// completed report with zero findings keeps the accounting honest.
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

		start := r.now()
		partials := r.runEngineBatches(ctx, a, env, slug, targets, sum, batcher, probe.Version)
		merged := mergeReports(sum.ScanID, slug, probe.Version, partials, firstRoot(r.cfg), sum.Mode)
		reports = append(reports, merged)

		outcome := EngineOutcome{
			Slug: slug, Available: true, Status: merged.Status,
			Findings: len(merged.Findings), Duration: r.now().Sub(start),
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

// runEngineBatches runs the engine in batches, with a pause between them.
//
// Engines that do NOT know how to restrict their scan to a file list
// (Info().ScopeAware == false) are run ONCE, with the whole list. Running them
// per batch would multiply the work by the number of batches, because each
// invocation walks the entire root again — measured in the validation container:
// on a 3,000-file WordPress, AMWScan took 13m54s and wp-checksums 7m02s in a
// cycle that should cost minutes.
func (r *Runner) runEngineBatches(
	ctx context.Context,
	a adapter.Adapter,
	env adapter.Environment,
	slug string,
	targets []string,
	sum *Summary,
	batcher *sexec.Batcher,
	engineVersion string,
) []schema.ScanReport {
	var partials []schema.ScanReport

	run := func(ctx context.Context, batch []string) error {
		rep := adapter.SafeScanAndParse(ctx, a, env, adapter.ScanRequest{
			ScanID:           sum.ScanID,
			Root:             firstRoot(r.cfg),
			Paths:            batch,
			Mode:             sum.Mode,
			Timeout:          r.cfg.EngineTimeoutFor(slug),
			MaxFileSizeBytes: int64(r.cfg.Limits.MaxFileSizeMB) << 20,
		})
		if rep.EngineVersion == "" {
			rep.EngineVersion = engineVersion
		}
		partials = append(partials, rep)
		return nil
	}

	if !safeInfo(a).ScopeAware {
		// A single execution. The pause between batches does not apply here — what
		// holds the consumption down is the executor's nice/ionice.
		if err := run(ctx, targets); err != nil {
			partials = append(partials, schema.FailedReport(sum.ScanID, slug, schema.StatusKilled, err, r.now()))
		}
		return partials
	}

	err := batcher.Each(ctx, targets, func(ctx context.Context, batch []string) error {
		rep := adapter.SafeScanAndParse(ctx, a, env, adapter.ScanRequest{
			ScanID:           sum.ScanID,
			Root:             firstRoot(r.cfg),
			Paths:            batch,
			Mode:             sum.Mode,
			Timeout:          r.cfg.EngineTimeoutFor(slug),
			MaxFileSizeBytes: int64(r.cfg.Limits.MaxFileSizeMB) << 20,
		})
		if rep.EngineVersion == "" {
			rep.EngineVersion = engineVersion
		}
		partials = append(partials, rep)
		return nil
	})
	if err != nil {
		// The whole cycle was cancelled. What already ran still counts.
		partials = append(partials, schema.FailedReport(sum.ScanID, slug, schema.StatusKilled, err, r.now()))
	}
	return partials
}

// envFor assembles the adapter's environment.
func (r *Runner) envFor(slug string) adapter.Environment {
	e := r.cfg.Engines[slug]
	binPath := e.Path
	if slug == "wp-checksums" && binPath == "" {
		// A native adapter: what it needs to know is where to look, not which
		// binary to run.
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

// safeInfo reads the adapter's Info without letting a panic take the cycle down.
//
// A third-party adapter must not decide the cycle's fate, not even in the most
// trivial method it exposes.
func safeInfo(a adapter.Adapter) (info adapter.Info) {
	defer func() {
		if recover() != nil {
			// With no trustworthy information, the safe side is to treat it as
			// scope-aware: one execution per batch is slower, never incorrect.
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
	prefix := "s"
	if mode == schema.ModeFull {
		prefix = "sf"
	}
	return fmt.Sprintf("%s_%s", prefix, t.UTC().Format("20060102_150405"))
}
