package schema

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrIncompatibleVersion signals an object from a schema version this binary
// cannot read.
var ErrIncompatibleVersion = errors.New("incompatible schema version")

// ValidationError collects every problem with an object at once. A broken
// adapter should see the full list of what it needs to fix, not one error per
// run.
type ValidationError struct {
	Object   string
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Object, strings.Join(e.Problems, "; "))
}

type problems struct {
	list []string
}

func (p *problems) addf(format string, args ...any) {
	p.list = append(p.list, fmt.Sprintf(format, args...))
}

func (p *problems) result(object string) error {
	if len(p.list) == 0 {
		return nil
	}
	return &ValidationError{Object: object, Problems: p.list}
}

// CompatibleVersion accepts objects from the same schema major version.
//
// Empty is accepted and treated as Version: third-party adapters written before
// the field existed keep working. A version higher than ours is refused —
// reading a schema from the future by guessing fields is like an adapter lying
// to the verdict engine.
func CompatibleVersion(v string) error {
	if v == "" || v == Version {
		return nil
	}
	got, err := majorOf(v)
	if err != nil {
		return fmt.Errorf("%w: %q is not semver", ErrIncompatibleVersion, v)
	}
	mine, err := majorOf(Version)
	if err != nil {
		return fmt.Errorf("%w: internal version %q is invalid", ErrIncompatibleVersion, Version)
	}
	if got != mine {
		return fmt.Errorf("%w: object is %q, this binary reads %q", ErrIncompatibleVersion, v, Version)
	}
	return nil
}

func majorOf(v string) (int, error) {
	part, _, _ := strings.Cut(v, ".")
	return strconv.Atoi(part)
}

// isSHA256 validates the hash format. The verdict engine deduplicates by this
// field; a malformed hash would silently create a separate target and split one
// file's votes across two verdicts.
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// Validate checks a Finding coming from an adapter.
func (f Finding) Validate() error {
	var p problems

	if err := CompatibleVersion(f.SchemaVersion); err != nil {
		p.addf("%v", err)
	}
	if f.Engine == "" {
		p.addf("empty engine")
	}
	if f.Rule == "" {
		p.addf("empty rule (use the name the engine reports)")
	}
	if k := f.EffectiveKind(); !k.Valid() {
		p.addf("unknown kind %q", f.Kind)
	}
	if !f.Category.Valid() {
		p.addf("unknown category %q (map it to other if you don't know)", f.Category)
	}
	if !f.Severity.Valid() {
		p.addf("unknown severity %q", f.Severity)
	}
	if !f.Confidence.Valid() {
		p.addf("unknown confidence %q", f.Confidence)
	}
	if f.DetectedAt.IsZero() {
		p.addf("detected_at is zero")
	}
	if len(f.MatchedContent) > MaxMatchedContentBytes {
		p.addf("matched_content is %d bytes, the limit is %d (use SanitizeSnippet)",
			len(f.MatchedContent), MaxMatchedContentBytes)
	}

	switch f.EffectiveKind() {
	case KindVulnerability:
		// Vulnerabilities are consolidated per component, not per file: sha256
		// is not required, the component block is.
		if f.Component == nil {
			p.addf("kind=vulnerability requires the component block")
		} else {
			if f.Component.Slug == "" {
				p.addf("empty component.slug")
			}
			if f.Component.InstalledVersion == "" {
				p.addf("empty component.installed_version")
			}
		}
	default:
		if !isSHA256(f.File.SHA256) {
			p.addf("invalid file.sha256 %q: it is the deduplication key across engines and is mandatory", f.File.SHA256)
		}
		if f.File.Path == "" {
			p.addf("empty file.path")
		}
	}

	return p.result("Finding")
}

// Validate checks a ScanReport produced by an adapter.
func (r ScanReport) Validate() error {
	var p problems

	if err := CompatibleVersion(r.SchemaVersion); err != nil {
		p.addf("%v", err)
	}
	if r.ScanID == "" {
		p.addf("empty scan_id")
	}
	if r.Engine == "" {
		p.addf("empty engine")
	}
	if !r.Status.Valid() {
		p.addf("unknown status %q", r.Status)
	}
	// A failure status with no reason turns a diagnosable problem into a
	// mystery for the user.
	if r.Status.Valid() && !r.Status.CountsAsVote() && r.Error == "" {
		p.addf("status %q requires error to be filled in", r.Status)
	}
	if r.Scope.Mode != "" && !r.Scope.Mode.Valid() {
		p.addf("unknown scope.mode %q", r.Scope.Mode)
	}
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		p.addf("finished_at is before started_at")
	}

	for i, f := range r.Findings {
		if err := f.Validate(); err != nil {
			p.addf("findings[%d]: %v", i, err)
		}
		if f.Engine != "" && r.Engine != "" && f.Engine != r.Engine {
			p.addf("findings[%d]: engine %q differs from the report's (%q)", i, f.Engine, r.Engine)
		}
	}
	for i, h := range r.CleanFiles {
		if !isSHA256(h) {
			p.addf("clean_files[%d]: invalid sha256 %q", i, h)
		}
	}

	return p.result("ScanReport")
}

// Validate checks a Verdict before it is persisted or displayed.
func (v Verdict) Validate() error {
	var p problems

	if err := CompatibleVersion(v.SchemaVersion); err != nil {
		p.addf("%v", err)
	}
	if v.VerdictID == "" {
		p.addf("empty verdict_id")
	}
	if !isSHA256(v.FileSHA256) {
		p.addf("invalid file_sha256 %q", v.FileSHA256)
	}
	if !v.Level.Valid() {
		p.addf("unknown level %q", v.Level)
	}
	if v.Score < 0 || v.Score > 1 {
		p.addf("score %v is outside [0,1]", v.Score)
	}
	if v.ActionTaken != "" && !v.ActionTaken.Valid() {
		p.addf("unknown action_taken %q", v.ActionTaken)
	}
	if v.ActionTaken == ActionQuarantined && v.QuarantineRef == "" {
		p.addf("action_taken=quarantined requires quarantine_ref (without it the file is not restorable)")
	}
	if v.ActionTaken == ActionFailed && v.ActionError == "" {
		p.addf("action_taken=failed requires action_error")
	}
	for i, vote := range v.Votes {
		if vote.Engine == "" {
			p.addf("votes[%d]: empty engine", i)
		}
		if vote.Weight < 0 {
			p.addf("votes[%d]: negative weight", i)
		}
	}

	return p.result("Verdict")
}
