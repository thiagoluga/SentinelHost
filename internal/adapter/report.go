package adapter

import "github.com/thiagoluga/SentinelHost/internal/schema"

// NewScanReport builds the envelope every adapter's Parse starts from.
//
// It was copied verbatim into three adapters, and identical copies of a report
// constructor are worse than merely repetitive here: the defaults it sets are the ones
// that decide whether a vote counts. `Status: StatusCompleted` means "this engine ran
// and its answer is a vote", and `Findings` as an empty slice rather than nil means "it
// ran and found nothing" — which the schema and the panel distinguish from "no answer".
// Getting either wrong in one copy and not the others produces a report that looks fine
// and votes when it should abstain.
//
// FilesScanned starts at what the orchestrator ASKED for. An adapter whose engine
// reports its own file count should overwrite it with that number afterwards: it is the
// honest one, because it says what the engine actually looked at rather than what it was
// pointed at.
func NewScanReport(engineSlug string, raw RawOutput) schema.ScanReport {
	return schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        raw.ScanID,
		Engine:        engineSlug,
		EngineVersion: raw.EngineVersion,
		StartedAt:     raw.StartedAt,
		FinishedAt:    raw.FinishedAt,
		Status:        schema.StatusCompleted,
		Scope: schema.Scope{
			Root: raw.Root, Mode: raw.Mode,
			FilesConsidered: raw.PathsRequested,
			FilesScanned:    raw.PathsRequested,
		},
		Findings: []schema.Finding{},
		RawRef:   raw.RawRef,
	}
}
