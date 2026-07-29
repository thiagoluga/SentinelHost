package adapter

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// This file implements obligation 5 of the adapter contract: a panic or timeout
// in ONE adapter does not bring the cycle down — it becomes
// ScanReport{status: failed} and an abstention in the consensus.
//
// The shielding lives here, in the orchestrator, rather than relying on each
// adapter's good behaviour. A third-party adapter with an off-by-one bug must not
// be able to take down protection for the entire site.

// SafeProbe runs Probe without letting a panic escape.
func SafeProbe(ctx context.Context, a Adapter, env Environment) (res ProbeResult) {
	slug := safeSlug(a)
	defer func() {
		if p := recover(); p != nil {
			res = Unavailable(fmt.Sprintf(
				"adapter %s panicked during the probe: %v", slug, p))
		}
	}()
	res = a.Probe(ctx, env)
	// An empty reason on an unavailability is an adapter bug that penalizes the
	// user: they are left without knowing what to do to enable the engine.
	if !res.Available && res.Reason == "" {
		res.Reason = "unavailable (the adapter did not report a reason)"
	}
	return res
}

// SafeScanAndParse runs an adapter's Scan and Parse fully shielded.
//
// Any bad outcome — panic, error, timeout, unreadable output, a report that fails
// schema validation — becomes a failure ScanReport, which the verdict engine
// treats as an abstention. Under no circumstances does it become "the engine
// found nothing".
func SafeScanAndParse(ctx context.Context, a Adapter, env Environment, req ScanRequest) (report schema.ScanReport) {
	slug := safeSlug(a)
	started := time.Now()

	defer func() {
		if p := recover(); p != nil {
			report = schema.FailedReport(req.ScanID, slug, schema.StatusFailed,
				fmt.Errorf("panic in adapter %s: %v\n%s", slug, p, debug.Stack()),
				started)
		}
	}()

	raw, err := a.Scan(ctx, env, req)
	if err != nil {
		return schema.FailedReport(req.ScanID, slug, statusOr(raw.Status, schema.StatusFailed), err, started)
	}
	// A Scan that "succeeded" but returned a failure status is still a failure:
	// the executor has already translated timeout and kill into the schema's
	// vocabulary.
	if raw.Status != "" && !raw.Status.CountsAsVote() {
		return schema.FailedReport(req.ScanID, slug, raw.Status, orErr(raw.Err, "the engine did not complete"), started)
	}

	report, err = a.Parse(raw)
	if err != nil {
		return schema.FailedReport(req.ScanID, slug, schema.StatusFailed,
			fmt.Errorf("the output of engine %s cannot be interpreted: %w", slug, err), started)
	}

	// Fill in whatever the adapter may have forgotten, before validating.
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

	// An invalid report is worse than no report: it would enter the consensus
	// carrying data the rest of the system does not know how to interpret.
	if err := report.Validate(); err != nil {
		return schema.FailedReport(req.ScanID, slug, schema.StatusFailed,
			fmt.Errorf("the report of engine %s does not satisfy the schema: %w", slug, err), started)
	}

	return report
}

// SafeUpdateSignatures shields the signature update.
func SafeUpdateSignatures(ctx context.Context, a Adapter, env Environment) (t time.Time, err error) {
	slug := safeSlug(a)
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic while updating the signatures of %s: %v", slug, p)
		}
	}()
	return a.UpdateSignatures(ctx, env)
}

// SafeInstall shields the installation.
func SafeInstall(ctx context.Context, a Adapter, env Environment) (err error) {
	slug := safeSlug(a)
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic while installing %s: %v", slug, p)
		}
	}()
	return a.Install(ctx, env)
}

func safeSlug(a Adapter) (slug string) {
	defer func() {
		if recover() != nil {
			slug = "unknown"
		}
	}()
	if s := a.Info().Slug; s != "" {
		return s
	}
	return "unknown"
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
