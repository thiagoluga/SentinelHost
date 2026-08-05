// Package integration_test exercises the consensus end to end over the synthetic
// corpus.
//
// The real engines are not executed (DECISIONS.md D-011): the test adapters emit
// the ScanReports the manifest declares. What is under test is the CONSOLIDATION —
// whether two heuristic engines agreeing give `likely`, whether a file with an
// official checksum survives two signature votes, whether an abstention dilutes the
// score. None of that depends on the quality of a third party's signature, and all
// of it is what SentinelHost actually implements.
package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

// Manifest is the expectation declared in tests/testdata/corpus/manifest.json.
type Manifest struct {
	Samples []Sample     `json:"samples"`
	Clean   []CleanEntry `json:"clean"`
}

type Sample struct {
	File          string   `json:"file"`
	SimulatedPath string   `json:"simulated_path"`
	Simulates     string   `json:"simulates"`
	Category      string   `json:"category"`
	Severity      string   `json:"severity"`
	Confidence    string   `json:"confidence"`
	MinimumLevel  string   `json:"minimum_expected_level"`
	Engines       []string `json:"engines_that_should_flag"`
}

type CleanEntry struct {
	File             string `json:"file"`
	SimulatedPath    string `json:"simulated_path"`
	MaximumLevel     string `json:"maximum_acceptable_level"`
	OfficialChecksum bool   `json:"official_checksum"`
	Note             string `json:"note"`
}

const corpusDir = "../testdata/corpus"

func loadManifest(t *testing.T) Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading the manifest: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid manifest: %v", err)
	}
	return m
}

// TestEveryCorpusFileIsInTheManifest keeps anyone from adding a sample without
// declaring what they expect from it.
func TestEveryCorpusFileIsInTheManifest(t *testing.T) {
	m := loadManifest(t)

	declared := map[string]bool{}
	for _, s := range m.Samples {
		declared[filepath.ToSlash(s.File)] = true
	}
	for _, c := range m.Clean {
		declared[filepath.ToSlash(c.File)] = true
	}

	var missing []string
	err := filepath.Walk(corpusDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(corpusDir, p)
		rel = filepath.ToSlash(rel)
		// The documentation and the manifest are not samples.
		if strings.HasSuffix(rel, ".md") || rel == "manifest.json" {
			return nil
		}
		if !declared[rel] {
			missing = append(missing, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the corpus: %v", err)
	}
	if len(missing) > 0 {
		t.Errorf("corpus files outside the manifest: %v\n"+
			"Every sample has to declare its expectation (SAMPLES.md and manifest.json).", missing)
	}
}

// TestTheSamplesAreInert checks the guarantees that make the corpus safe.
func TestTheSamplesAreInert(t *testing.T) {
	m := loadManifest(t)

	for _, s := range m.Samples {
		t.Run(s.File, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(corpusDir, s.File))
			if err != nil {
				t.Fatalf("reading the sample: %v", err)
			}
			content := string(b)

			if !strings.Contains(content, "SENTINELHOST-SYNTHETIC-CORPUS") {
				t.Error("the marker identifying the sample as synthetic is missing")
			}
			// The first executable statement has to be an exit().
			idx := strings.Index(content, "exit(")
			if idx < 0 {
				t.Fatal("the sample has no exit() and is therefore not inert")
			}
			beforeExit := content[:idx]
			for _, dangerous := range []string{
				"eval(", "system(", "shell_exec(", "passthru(", "proc_open(",
				"fsockopen(", "file_put_contents(", "move_uploaded_file(",
				"base64_decode(", "assert(", "include ", "require ",
			} {
				if strings.Contains(beforeExit, dangerous) {
					t.Errorf("the dangerous call %q appears BEFORE the exit()", dangerous)
				}
			}
		})
	}
}

// SC-001 -----------------------------------------------------------------------

// TestSC001Detection measures the consensus over the corpus.
//
// The spec demands >= 95% of the samples in `confirmed`/`likely` and ZERO
// `confirmed` false positives on an official core file.
//
// The denominator is the malicious-CONTENT samples. The two samples whose only
// signal is an anomaly (a file in the wrong place, loose permissions) are measured
// separately, against the `suspicious` floor the manifest declares — see
// DECISIONS.md D-016.
func TestSC001Detection(t *testing.T) {
	m := loadManifest(t)
	cfg := config.Default()
	engine := verdict.New(cfg.Verdict, cfg.Engines)

	reports, hashes, clean := buildCycle(t, m)

	res := engine.Consolidate(verdict.Input{
		ScanID:          "s_sc001",
		Reports:         reports,
		ExpectedEngines: []string{"wp-checksums", "amwscan", "php-malware-finder", "maldet"},
		Now:             time.Now(),
	})

	byHash := map[string]schema.Verdict{}
	for _, v := range res.Verdicts {
		byHash[v.FileSHA256] = v
	}

	var maliciousContent, detected int
	var failures []string

	for _, s := range m.Samples {
		v, ok := byHash[hashes[s.File]]
		if !ok {
			failures = append(failures, s.File+": no verdict was produced")
			continue
		}
		floor := schema.Level(s.MinimumLevel)
		if !v.Level.AtLeast(floor) {
			failures = append(failures,
				s.File+": level "+string(v.Level)+", expected at least "+string(floor))
		}

		// The malicious-content samples are the ones the manifest expects at likely
		// or confirmed.
		if floor.AtLeast(schema.LevelLikely) {
			maliciousContent++
			if v.Level.AtLeast(schema.LevelLikely) {
				detected++
			}
		}
	}

	for _, f := range failures {
		t.Errorf("SC-001: %s", f)
	}

	if maliciousContent == 0 {
		t.Fatal("the corpus declares no malicious-content samples")
	}
	rate := float64(detected) / float64(maliciousContent)
	t.Logf("SC-001: %d/%d malicious-content samples in confirmed/likely (%.1f%%)",
		detected, maliciousContent, rate*100)
	if rate < 0.95 {
		t.Errorf("SC-001 failed: detection rate %.1f%%, minimum 95%%", rate*100)
	}

	// Zero `confirmed` false positives on an official core file.
	for _, c := range clean {
		v, ok := byHash[c.hash]
		if !ok {
			continue
		}
		maximum := schema.Level(c.maximumLevel)
		if v.Level.Rank() > maximum.Rank() {
			t.Errorf("SC-001: false positive on %s — level %s, maximum acceptable %s",
				c.file, v.Level, maximum)
		}
		if c.officialChecksum {
			if v.Level != schema.LevelClean {
				t.Errorf("SC-001: a file with an official checksum came out as %s (%s)", v.Level, c.file)
			}
			if v.CleanReason != verdict.CleanReasonOfficialChecksum {
				t.Errorf("SC-001: the checksum veto was not recorded on %s (clean_reason=%q)",
					c.file, v.CleanReason)
			}
			// And most importantly: the votes the veto overruled stay visible, so the
			// user can understand what happened.
			if len(v.Votes) == 0 {
				t.Errorf("SC-001: the votes overruled by the veto vanished on %s", c.file)
			}
		}
	}
}

type resolvedClean struct {
	file             string
	hash             string
	maximumLevel     string
	officialChecksum bool
}

// buildCycle turns the manifest into engine reports.
//
// Each "engine" emits exactly what the manifest declares. The hashes are the real
// ones of the corpus files, computed here — the same path the orchestrator uses in
// production.
func buildCycle(t *testing.T, m Manifest) ([]schema.ScanReport, map[string]string, []resolvedClean) {
	t.Helper()

	byEngine := map[string][]schema.Finding{}
	hashes := map[string]string{}
	now := time.Now()

	for _, s := range m.Samples {
		h, err := baseline.HashFile(filepath.Join(corpusDir, s.File))
		if err != nil {
			t.Fatalf("hash of %s: %v", s.File, err)
		}
		hashes[s.File] = h

		for _, eng := range s.Engines {
			conf := schema.Confidence(s.Confidence)
			// wp-checksums only speaks about core integrity, and always with
			// signature confidence.
			if eng == "wp-checksums" {
				conf = schema.ConfidenceSignature
			}
			byEngine[eng] = append(byEngine[eng], schema.Finding{
				SchemaVersion: schema.Version,
				ID:            verdict.FindingID("s_sc001", eng, s.Category, h, "/home/user/public_html/"+s.SimulatedPath),
				Engine:        eng,
				Rule:          ruleFor(eng, s),
				File: schema.FileRef{
					Path: "/home/user/public_html/" + s.SimulatedPath, SHA256: h, SizeBytes: 1024,
				},
				Category:   schema.Category(s.Category),
				Severity:   schema.Severity(s.Severity),
				Confidence: conf,
				ScanID:     "s_sc001",
				DetectedAt: now,
			})
		}
	}

	var clean []resolvedClean
	var cleanFiles []string

	for _, c := range m.Clean {
		h, err := baseline.HashFile(filepath.Join(corpusDir, c.File))
		if err != nil {
			t.Fatalf("hash of %s: %v", c.File, err)
		}
		clean = append(clean, resolvedClean{
			file: c.File, hash: h,
			maximumLevel: c.MaximumLevel, officialChecksum: c.OfficialChecksum,
		})

		if !c.OfficialChecksum {
			continue
		}
		cleanFiles = append(cleanFiles, h)

		// The scenario SC-001 really tests: TWO engines flag the official file with
		// signature confidence (which would give `confirmed`), and the checksum veto
		// has to win anyway.
		for _, eng := range []string{"maldet", "amwscan"} {
			byEngine[eng] = append(byEngine[eng], schema.Finding{
				SchemaVersion: schema.Version,
				ID:            verdict.FindingID("s_sc001", eng, "false_positive", h, "/home/user/public_html/"+c.SimulatedPath),
				Engine:        eng,
				Rule:          "FALSE_POSITIVE_ON_OFFICIAL_FILE",
				File: schema.FileRef{
					Path: "/home/user/public_html/" + c.SimulatedPath, SHA256: h, SizeBytes: 2048,
				},
				Category:   schema.CategoryKnownMalware,
				Severity:   schema.SeverityCritical,
				Confidence: schema.ConfidenceSignature,
				ScanID:     "s_sc001",
				DetectedAt: now,
			})
		}
	}

	var reports []schema.ScanReport
	for _, eng := range []string{"wp-checksums", "amwscan", "php-malware-finder", "maldet"} {
		r := schema.ScanReport{
			SchemaVersion: schema.Version,
			ScanID:        "s_sc001",
			Engine:        eng,
			Status:        schema.StatusCompleted,
			StartedAt:     now.Add(-time.Minute),
			FinishedAt:    now,
			Scope:         schema.Scope{Root: "/home/user/public_html", Mode: schema.ModeFull},
			Findings:      byEngine[eng],
		}
		if eng == "wp-checksums" {
			r.CleanFiles = cleanFiles
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("the test report of engine %s is invalid: %v", eng, err)
		}
		reports = append(reports, r)
	}
	return reports, hashes, clean
}

func ruleFor(engine string, s Sample) string {
	switch engine {
	case "wp-checksums":
		return "core_file_modified"
	case "php-malware-finder":
		return "YaraRule_" + s.Category
	default:
		return strings.ToUpper(s.Category)
	}
}

// TestAnAnomalyAloneDoesNotReachLikely documents and pins the behaviour that
// justifies SC-001's denominator (D-016).
func TestAnAnomalyAloneDoesNotReachLikely(t *testing.T) {
	cfg := config.Default()
	engine := verdict.New(cfg.Verdict, cfg.Engines)

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res := engine.Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{{
			SchemaVersion: schema.Version, ScanID: "s_1", Engine: "php-malware-finder",
			Status: schema.StatusCompleted,
			Findings: []schema.Finding{{
				SchemaVersion: schema.Version, Engine: "php-malware-finder", Rule: "PhpInUploads",
				File:       schema.FileRef{Path: "/site/uploads/x.php", SHA256: sha},
				Category:   schema.CategorySuspiciousLocation,
				Severity:   schema.SeverityMedium,
				Confidence: schema.ConfidenceAnomaly,
				DetectedAt: time.Now(),
			}},
		}},
	})

	if len(res.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(res.Verdicts))
	}
	v := res.Verdicts[0]
	if v.Level.AtLeast(schema.LevelLikely) {
		t.Fatalf("a single anomaly signal must not reach %s: "+
			"that would let one engine alone trigger an action-recommended alert", v.Level)
	}
	if v.Actionable() {
		t.Error("an anomaly alone can never authorize an automatic action")
	}
}
