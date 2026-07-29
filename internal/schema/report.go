package schema

import (
	"fmt"
	"time"
)

// Scope describes what the engine was given to scan in this cycle.
//
// The ORCHESTRATOR decides the list (incremental by mtime/baseline); the
// adapter never picks its own scope.
type Scope struct {
	Root            string   `json:"root"`
	Mode            ScanMode `json:"mode"`
	FilesConsidered int      `json:"files_considered"`
	FilesScanned    int      `json:"files_scanned"`
	// SkippedReasonCounts maps reason→count ("unchanged", "too_large",
	// "unreadable", "excluded", "symlink").
	SkippedReasonCounts map[string]int `json:"skipped_reason_counts,omitempty"`
}

// ResourceUsage is the real cost of running the engine. It feeds the panel and
// the scheduler (Principle IV: a well-behaved hosting tenant).
type ResourceUsage struct {
	WallSeconds float64 `json:"wall_seconds"`
	MaxRSSMB    int     `json:"max_rss_mb,omitempty"`
}

// ScanReport is the result of ONE execution of ONE engine in a cycle.
type ScanReport struct {
	SchemaVersion string `json:"schema_version"`
	ScanID        string `json:"scan_id"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version,omitempty"`
	// SignaturesUpdatedAt is the date of the signatures/rules at scan time.
	// Zero when the engine does not separate signatures from its installation.
	SignaturesUpdatedAt time.Time `json:"signatures_updated_at,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Scope Scope `json:"scope"`

	Status ScanStatus `json:"status"`
	// Error is the real error message when Status != completed. It is never
	// empty on a failure status: the user has to be able to learn the reason.
	Error string `json:"error,omitempty"`

	ResourceUsage ResourceUsage `json:"resource_usage"`
	Findings      []Finding     `json:"findings"`

	// CleanFiles lists the sha256 values this engine positively asserts are
	// legitimate. Only wp-checksums fills this in (files identical to the
	// official WordPress.org checksum). It is the basis of the verdict engine's
	// false-positive protection.
	CleanFiles []string `json:"clean_files,omitempty"`

	// RawRef points at this scan's archived raw output, for auditing and for
	// reprocessing through Parse().
	RawRef string `json:"raw_ref,omitempty"`
}

// Abstains answers whether this report should become an abstention in the
// consensus.
//
// A ScanReport with status != completed NEVER counts as "the engine found
// nothing": it counts as an abstention (Principle VI).
func (r ScanReport) Abstains() bool {
	return !r.Status.CountsAsVote()
}

// Duration is the wall-clock time of the execution.
func (r ScanReport) Duration() time.Duration {
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return 0
	}
	return r.FinishedAt.Sub(r.StartedAt)
}

// FailedReport builds the abstention report of an engine that failed. It is the
// single path through which an adapter failure enters the consensus: it never
// collapses the cycle, and it is always a recorded abstention.
func FailedReport(scanID, engine string, status ScanStatus, err error, started time.Time) ScanReport {
	msg := "unknown error"
	if err != nil {
		msg = err.Error()
	}
	if status.CountsAsVote() {
		// Guard against a wrong call: a failure report may never leave here
		// with a status that counts as a vote.
		status = StatusFailed
	}
	return ScanReport{
		SchemaVersion: Version,
		ScanID:        scanID,
		Engine:        engine,
		StartedAt:     started,
		FinishedAt:    time.Now(),
		Status:        status,
		Error:         msg,
		Findings:      []Finding{},
	}
}

// String renders the report compactly, for logs.
func (r ScanReport) String() string {
	if r.Abstains() {
		return fmt.Sprintf("%s: %s (%s)", r.Engine, r.Status, r.Error)
	}
	return fmt.Sprintf("%s: %s, %d finding(s)", r.Engine, r.Status, len(r.Findings))
}
