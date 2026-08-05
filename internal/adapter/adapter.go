// Package adapter defines the contract every engine has to satisfy to be
// plugged into SentinelHost.
//
// The verdict engine only knows the normalized schema, never a specific engine
// (Principle VI). The adapter is the only piece that knows how one engine
// speaks — and the only one that has to change when that engine changes format.
//
// Full contract: docs/schema-and-adapters.md section 2.
package adapter

import (
	"context"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Cost is the relative cost declared by the adapter, so the scheduler can
// interleave heavy engines with light ones instead of queueing all the expensive
// ones together.
type Cost string

const (
	CostLight  Cost = "light"
	CostMedium Cost = "medium"
	CostHeavy  Cost = "heavy"
)

// Info is the adapter's identity and metadata.
type Info struct {
	Slug string
	Name string
	// License of the ENGINE, not of the adapter. GPL engines are invoked
	// exclusively as external processes, never linked, so the orchestrator can
	// keep MIT (Principle II).
	License  string
	Homepage string
	// Categories this engine is able to report.
	Categories []schema.Category
	// Kind this engine produces. The MVP only has malware adapters.
	Kind schema.Kind
	Cost Cost
	// RequiresNetwork marks engines that depend on the network (wp-checksums
	// queries the WordPress.org API). On hosting with outbound traffic blocked
	// they abstain instead of stalling the cycle.
	RequiresNetwork bool

	// ScopeAware says whether the engine can restrict its SCAN to a file list,
	// rather than only filtering the report at the end.
	//
	// This is not an optimization detail: the orchestrator runs each engine once
	// per BATCH, and an engine that ignores the list walks the whole root on
	// every batch. On a 3,000-file WordPress with batches of 200, that multiplies
	// the work by 16 — measured in the validation container: 13m54s for AMWScan
	// and 7m02s for wp-checksums in a cycle that should take minutes.
	//
	// Engines like that are run ONCE per cycle, with the whole list. The cost is
	// still that of walking everything, because that is what the engine knows how
	// to do — but once, not sixteen times.
	ScopeAware bool

	// DefaultWeight is the suggested consensus weight. The user's configuration
	// always wins.
	DefaultWeight float64
}

// Environment is what the orchestrator offers the adapter.
type Environment struct {
	// DataDir is where the adapter may install the engine and keep rules. No
	// adapter writes outside it (obligation 1 of the contract).
	DataDir string
	// Runner is the only way to execute a process. An adapter calling os/exec
	// directly would escape the resource limits.
	Runner *exec.Runner
	// BinaryPath forced by the user's configuration, when the automatic probe
	// cannot find the engine.
	BinaryPath string
	// ExtraArgs from the configuration.
	ExtraArgs []string
	// Offline disables any network access (probe, install, checksums).
	Offline bool
}

// ProbeResult says whether the engine runs IN THIS environment.
//
// Reason is mandatory when Available is false: FR-001 requires the user to see
// why each engine is unavailable. "Not available" with no reason turns a solvable
// problem (install the PHP CLI) into a mystery.
type ProbeResult struct {
	Available bool
	Reason    string
	Version   string
	// BinaryPath as resolved, for the panel and the doctor command.
	BinaryPath string
	// SignaturesUpdatedAt when the engine separates signatures from its
	// installation.
	SignaturesUpdatedAt time.Time
	// Installable indicates Install() can resolve the unavailability without
	// root. It is what lets the panel offer an "install" button.
	Installable bool
}

// Unavailable builds an unavailable ProbeResult with a reason.
func Unavailable(reason string) ProbeResult {
	return ProbeResult{Available: false, Reason: reason}
}

// UnavailableInstallable builds an unavailable ProbeResult that Install() can
// resolve.
func UnavailableInstallable(reason string) ProbeResult {
	return ProbeResult{Available: false, Reason: reason, Installable: true}
}

// ScanRequest is the work the orchestrator asks the adapter to do.
//
// The path list arrives ready: the ORCHESTRATOR decides the scope (incremental
// by mtime/baseline, exclusions, size limit). The adapter never picks what to
// scan, otherwise two engines would walk different sets and the consensus would
// be comparing incomparable things.
type ScanRequest struct {
	ScanID string
	Root   string
	Paths  []string
	Mode   schema.ScanMode
	// Timeout of this execution.
	Timeout time.Duration
	// MaxFileSizeBytes: larger files should be skipped by the engine when it
	// supports the option.
	MaxFileSizeBytes int64
}

// RawOutput is the engine's raw output, preserved for auditing and for
// reprocessing through Parse() when the rule→category mapping improves.
type RawOutput struct {
	Engine        string
	EngineVersion string
	ScanID        string
	Root          string
	Mode          schema.ScanMode

	Stdout   []byte
	Stderr   []byte
	ExitCode int

	StartedAt  time.Time
	FinishedAt time.Time

	// Status and Err come from the executor: they are what decides vote or
	// abstention.
	Status schema.ScanStatus
	Err    error

	// RawRef points at the copy archived on disk.
	RawRef string
	// PathsRequested is how many paths the orchestrator asked to be scanned.
	PathsRequested int
	// UnscannablePaths counts paths the engine could not be asked about at all.
	//
	// A path holding a newline cannot be expressed in a one-path-per-line scope file, so
	// it is refused before the engine runs. It travels here so Parse can fold it into
	// SkippedReasonCounts: the file was not scanned, and that has to reach the report
	// rather than being lost between Scan and Parse.
	UnscannablePaths int

	// Truncated indicates the capture hit its ceiling.
	Truncated bool

	// Extra lets the adapter carry data from Scan to Parse without re-running
	// anything (e.g. wp-checksums carries the list of official files).
	Extra map[string]any
}

// FromExecResult converts the executor's result into a RawOutput.
func FromExecResult(req ScanRequest, engine string, res exec.Result) RawOutput {
	return RawOutput{
		Engine:         engine,
		ScanID:         req.ScanID,
		Root:           req.Root,
		Mode:           req.Mode,
		Stdout:         res.Stdout,
		Stderr:         res.Stderr,
		ExitCode:       res.ExitCode,
		FinishedAt:     time.Now(),
		StartedAt:      time.Now().Add(-res.Duration),
		Status:         res.Status,
		Err:            res.Err,
		RawRef:         res.RawRef,
		PathsRequested: len(req.Paths),
		Truncated:      res.Truncated,
	}
}

// Adapter is the integration contract for an engine.
//
// Scan and Parse are separate on purpose: it allows reprocessing old output when
// the rule→category mapping improves, without running the engine again.
type Adapter interface {
	// Info returns identity and metadata.
	Info() Info

	// Probe detects whether the engine runs in this environment.
	Probe(ctx context.Context, env Environment) ProbeResult

	// Install installs or updates the engine in user space, without root, where
	// supported. Adapters that do not install return ErrNotInstallable.
	Install(ctx context.Context, env Environment) error

	// UpdateSignatures updates rules/signatures when the engine keeps them
	// separate from its installation.
	UpdateSignatures(ctx context.Context, env Environment) (time.Time, error)

	// Scan runs the engine over the path list it receives.
	Scan(ctx context.Context, env Environment, req ScanRequest) (RawOutput, error)

	// Parse converts the raw output into the normalized schema.
	Parse(raw RawOutput) (schema.ScanReport, error)
}
