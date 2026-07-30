package verdict_test

import (
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

// The same content planted at several paths must produce a verdict for EACH path.
//
// Found on a real HostGator account: three identical files planted in three WordPress
// directories produced three findings from wp-checksums and exactly ONE verdict. The
// other two appeared in no verdict, in no summary bucket, and in no skipped counter.
// They were simply gone.
//
// The consequence is the failure mode this project exists to prevent, arriving at the
// worst possible moment. Planting identical copies across many directories is standard
// webshell behaviour, done precisely to survive a cleanup. Under the old grouping the
// tool would quarantine one copy, report the site as handled, and leave the rest in
// place — manufactured confidence on a site that is still compromised.
//
// Grouping by sha256 is right for its actual purpose: the same file flagged by N engines
// is N votes on ONE target, not N targets. What was wrong is that the group was also the
// unit of OUTPUT. Votes are merged per content; verdicts are emitted per path.

const (
	shaShared = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaOther  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func findingAt(engine, rule, path, sha string, conf schema.Confidence) schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		Kind:          schema.KindMalware,
		Engine:        engine,
		Rule:          rule,
		File: schema.FileRef{
			Path: path, SHA256: sha, SizeBytes: 82, Perms: "0644",
			MTime: time.Unix(1785000000, 0),
		},
		Category:   schema.CategoryWebshell,
		Severity:   schema.SeverityHigh,
		Confidence: conf,
		ScanID:     "s_test",
		DetectedAt: time.Unix(1785000000, 0),
	}
}

// newEngine builds the consolidator with the shipped defaults, so the thresholds and
// weights under test are the ones users actually get.
func newEngine() *verdict.Engine {
	cfg := config.Default()
	return verdict.New(cfg.Verdict, cfg.Engines)
}

func reportWith(engine string, findings ...schema.Finding) schema.ScanReport {
	return schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_test",
		Engine:        engine,
		Status:        schema.StatusCompleted,
		Findings:      findings,
	}
}

func TestIdenticalContentAtSeveralPathsGetsAVerdictPerPath(t *testing.T) {
	// Exactly the shape observed on the real account.
	paths := []string{
		"/site/wp-includes/class-wp-cache-helper.php",
		"/site/wp-admin/includes/update-core-helper.php",
		"/site/wp-content/plugins/akismet/cache-helper.php",
	}
	var findings []schema.Finding
	for _, p := range paths {
		findings = append(findings,
			findingAt("wp-checksums", "core_file_unexpected", p, shaShared, schema.ConfidenceSignature))
	}

	res := newEngine().Consolidate(verdict.Input{
		ScanID:  "s_test",
		Reports: []schema.ScanReport{reportWith("wp-checksums", findings...)},
		Now:     time.Unix(1785000000, 0),
	})

	if len(res.Verdicts) != len(paths) {
		t.Fatalf("got %d verdict(s) for %d planted copies — the missing ones would never be "+
			"quarantined, and nothing reports them as skipped", len(res.Verdicts), len(paths))
	}

	seen := map[string]bool{}
	for _, v := range res.Verdicts {
		seen[v.FilePath] = true
		if v.FileSHA256 != shaShared {
			t.Errorf("verdict for %s lost the content hash", v.FilePath)
		}
		if len(v.Votes) != 1 {
			t.Errorf("%s: %d vote(s), want the single wp-checksums vote", v.FilePath, len(v.Votes))
		}
	}
	for _, p := range paths {
		if !seen[p] {
			t.Errorf("no verdict names %s: that copy stays on the site", p)
		}
	}
}

// The reason grouping by content exists in the first place, which must keep working:
// one file flagged by several engines is ONE target carrying several votes, not several
// targets. Breaking this would turn a single confirmed file into N weak verdicts.
func TestOneFileFlaggedBySeveralEnginesStaysOneVerdictWithEveryVote(t *testing.T) {
	const path = "/site/wp-content/uploads/x.php"

	res := newEngine().Consolidate(verdict.Input{
		ScanID: "s_test",
		Reports: []schema.ScanReport{
			reportWith("wp-checksums",
				findingAt("wp-checksums", "core_file_modified", path, shaShared, schema.ConfidenceSignature)),
			reportWith("amwscan",
				findingAt("amwscan", "eval_obfuscated", path, shaShared, schema.ConfidenceHeuristic)),
			reportWith("maldet",
				findingAt("maldet", "php.corpus.marker.v1", path, shaShared, schema.ConfidenceSignature)),
		},
		Now: time.Unix(1785000000, 0),
	})

	if len(res.Verdicts) != 1 {
		t.Fatalf("got %d verdicts for one file seen by three engines; the votes were split",
			len(res.Verdicts))
	}
	if len(res.Verdicts[0].Votes) != 3 {
		t.Errorf("got %d vote(s), want 3: splitting them would drop the score below confirmed",
			len(res.Verdicts[0].Votes))
	}
}

// The mixed case, which is what a real compromise looks like: one engine sees the copies
// by path, another recognises the content. Each path still gets its own verdict, and
// each one carries BOTH votes — because both engines are talking about that content.
func TestEachCopyCarriesEveryEnginesVoteForThatContent(t *testing.T) {
	a := "/site/wp-includes/helper.php"
	b := "/site/wp-admin/helper.php"

	res := newEngine().Consolidate(verdict.Input{
		ScanID: "s_test",
		Reports: []schema.ScanReport{
			reportWith("wp-checksums",
				findingAt("wp-checksums", "core_file_unexpected", a, shaShared, schema.ConfidenceSignature),
				findingAt("wp-checksums", "core_file_unexpected", b, shaShared, schema.ConfidenceSignature)),
			reportWith("amwscan",
				findingAt("amwscan", "eval_obfuscated", a, shaShared, schema.ConfidenceHeuristic),
				findingAt("amwscan", "eval_obfuscated", b, shaShared, schema.ConfidenceHeuristic)),
		},
		Now: time.Unix(1785000000, 0),
	})

	if len(res.Verdicts) != 2 {
		t.Fatalf("got %d verdict(s), want one per path", len(res.Verdicts))
	}
	for _, v := range res.Verdicts {
		if len(v.Votes) != 2 {
			t.Errorf("%s: %d vote(s), want both engines — each copy is as confirmed as the other",
				v.FilePath, len(v.Votes))
		}
	}
	// Both must reach the same level: they are the same content, equally proven.
	if res.Verdicts[0].Level != res.Verdicts[1].Level {
		t.Errorf("identical content scored differently: %q vs %q",
			res.Verdicts[0].Level, res.Verdicts[1].Level)
	}
}

// Different content stays separate, which is the baseline the above must not disturb.
func TestDifferentContentStillProducesSeparateVerdicts(t *testing.T) {
	res := newEngine().Consolidate(verdict.Input{
		ScanID: "s_test",
		Reports: []schema.ScanReport{
			reportWith("amwscan",
				findingAt("amwscan", "eval_obfuscated", "/site/a.php", shaShared, schema.ConfidenceHeuristic),
				findingAt("amwscan", "eval_obfuscated", "/site/b.php", shaOther, schema.ConfidenceHeuristic)),
		},
		Now: time.Unix(1785000000, 0),
	})
	if len(res.Verdicts) != 2 {
		t.Fatalf("got %d verdict(s), want 2", len(res.Verdicts))
	}
}
