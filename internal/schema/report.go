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
	// "unreadable", "excluded", "symlink", "symlinked_directory",
	// "symlinked_directory_already_covered").
	//
	// "symlink" and "symlinked_directory" are separate on purpose. A skipped linked
	// file costs one file; a skipped linked directory costs everything under it, and
	// if the target sits outside the configured roots nothing ever opens it while the
	// web server may still serve it. One bucket could not tell those apart (D-053).
	//
	// "symlinked_directory_already_covered" is the benign half: the link resolves
	// inside a configured root, so the target is walked under its real name and
	// nothing is unseen. Counted, because nothing skipped goes unrecorded — but not
	// as a gap. On cPanel every account links www to public_html, and a warning that
	// fires on every install is one its reader learns to skip.
	SkippedReasonCounts map[string]int `json:"skipped_reason_counts,omitempty"`

	// NoteCounts is bookkeeping an engine wants recorded that is NOT a coverage gap.
	//
	// It exists because SkippedReasonCounts answers exactly one question — what did the
	// scan NOT look at? — and things that are not gaps kept ending up in it, where every
	// reader downstream treats them as lost coverage.
	//
	// wpchecksums learned this first: a plugin that verified CLEAN was once counted under
	// "plugin_verified", so a user reading "skipped: plugin_verified=1" concluded coverage
	// was lost and went hunting for a problem that did not exist. It was taken out. The
	// same mistake was still live in two other adapters:
	//
	//   - "unknown_rule" counts a finding whose rule is not in the adapter's table. The
	//     finding IS reported, as other/medium/heuristic; the count exists so the table
	//     gets maintained. On a real account this reads 260, and calling that a gap tells
	//     the operator 260 files went unexamined when every one of them is in the report.
	//   - "outside_requested_scope" counts findings the engine volunteered about paths the
	//     orchestrator did not ask for. Dropping them is correct and costs no coverage of
	//     what WAS asked for.
	//
	// Both are worth recording — nothing an engine reports gets discarded silently — but
	// not in the field that means "unexamined".
	NoteCounts map[string]int `json:"note_counts,omitempty"`
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
