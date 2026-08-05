package verdict_test

import (
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/verdict"
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func engine() *verdict.Engine {
	cfg := config.Default()
	return verdict.New(cfg.Verdict, cfg.Engines)
}

func finding(eng, rule, sha, path string, conf schema.Confidence) schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		ID:            verdict.FindingID("s_1", eng, rule, sha, path),
		Engine:        eng,
		Rule:          rule,
		File:          schema.FileRef{Path: path, SHA256: sha, SizeBytes: 1024},
		Category:      schema.CategoryBackdoor,
		Severity:      schema.SeverityHigh,
		Confidence:    conf,
		ScanID:        "s_1",
		DetectedAt:    time.Now(),
	}
}

func report(eng string, findings ...schema.Finding) schema.ScanReport {
	return schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        "s_1",
		Engine:        eng,
		Status:        schema.StatusCompleted,
		Findings:      findings,
	}
}

func oneVerdict(t *testing.T, r verdict.Result) schema.Verdict {
	t.Helper()
	if len(r.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(r.Verdicts))
	}
	return r.Verdicts[0]
}

// Scenarios from the spec -----------------------------------------------------

func TestTwoEnginesWithASignatureGiveConfirmed(t *testing.T) {
	// Scenario 2 of US1: two engines with confidence=signature -> confirmed.
	// With the weights from the schema document: maldet 1.0 + amwscan 0.8 = 1.8,
	// over the ceiling of 2.0 = 0.90, exactly the confirmed threshold.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("maldet", finding("maldet", "php.corpus.marker.v1", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "SIGNATURE_KNOWN_MARKER", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := oneVerdict(t, r)
	if v.Level != schema.LevelConfirmed {
		t.Fatalf("expected confirmed, got %s (score %.4f)", v.Level, v.Score)
	}
	if len(v.Votes) != 2 {
		t.Errorf("expected 2 votes, got %d", len(v.Votes))
	}
	if !v.Actionable() {
		t.Error("confirmed with no veto should be actionable")
	}
}

func TestOneHeuristicEngineGivesSuspicious(t *testing.T) {
	// Scenario 3 of US1: one heuristic engine alone -> suspicious, no action.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan", finding("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	})

	v := oneVerdict(t, r)
	// 0.8 * 0.8 = 0.64, over 2.0 = 0.32 -> suspicious.
	if v.Level != schema.LevelSuspicious {
		t.Fatalf("expected suspicious, got %s (score %.4f)", v.Level, v.Score)
	}
	if v.Actionable() {
		t.Error("suspicious can never authorize an automatic action")
	}
}

func TestTwoHeuristicEnginesGiveLikely(t *testing.T) {
	// The schema document describes exactly this case as likely.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan", finding("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
			report("php-malware-finder", finding("php-malware-finder", "DangerousPhp", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	})

	v := oneVerdict(t, r)
	// (0.8*0.8) * 2 = 1.28, over 2.0 = 0.64 -> likely.
	if v.Level != schema.LevelLikely {
		t.Fatalf("expected likely, got %s (score %.4f)", v.Level, v.Score)
	}
	if v.Actionable() {
		t.Error("likely waits for a human decision")
	}
}

func TestADivergentChecksumPlusOneEngineGivesConfirmed(t *testing.T) {
	// The schema document cites "divergent official checksum + 1 engine" as an
	// example of confirmed. wp-checksums weighs 1.5.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("wp-checksums", finding("wp-checksums", "core_file_modified", shaA, "/site/wp-includes/pluggable.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "EVAL_BASE64", shaA, "/site/wp-includes/pluggable.php", schema.ConfidenceHeuristic)),
		},
	})

	v := oneVerdict(t, r)
	if v.Level != schema.LevelConfirmed {
		t.Fatalf("expected confirmed, got %s (score %.4f)", v.Level, v.Score)
	}
}

func TestAnOfficialChecksumVetoesEvenWithConfirmedVotes(t *testing.T) {
	// Scenario 5 of US1 and the schema's fixed rule: a file identical to the
	// official checksum is NEVER quarantined, regardless of votes. Engines produce
	// false positives on legitimate minified files, and one false positive in the
	// core takes the whole site down.
	clean := report("wp-checksums")
	clean.CleanFiles = []string{shaA}

	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			clean,
			report("maldet", finding("maldet", "php.x", shaA, "/site/wp-includes/version.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "KNOWN_MALWARE", shaA, "/site/wp-includes/version.php", schema.ConfidenceSignature)),
		},
	})

	v := oneVerdict(t, r)
	if v.Level != schema.LevelClean {
		t.Fatalf("the official checksum should have vetoed: got %s (score %.4f)", v.Level, v.Score)
	}
	if v.Score != 0 {
		t.Errorf("the score should be zeroed by the veto, got %.4f", v.Score)
	}
	if v.CleanReason != verdict.CleanReasonOfficialChecksum {
		t.Errorf("the reason has to stay on record, got %q", v.CleanReason)
	}
	if v.Actionable() {
		t.Error("a vetoed verdict can never be actionable")
	}
	// The votes stay visible: the user needs to see that the engines flagged it and
	// why they were overruled (Principle V).
	if len(v.Votes) != 2 {
		t.Errorf("the overruled votes should stay on record, got %d", len(v.Votes))
	}
	if v.ActionTaken != schema.ActionSkippedOfficial {
		t.Errorf("action_taken should explain the veto, got %q", v.ActionTaken)
	}
}

func TestAnEngineThatFailsBecomesAnAbstentionAndTheCycleCompletes(t *testing.T) {
	// Scenario 4 of US1.
	failed := schema.FailedReport("s_1", "maldet", schema.StatusTimeout,
		errTimeout{}, time.Now())

	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			failed,
			report("amwscan", finding("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	})

	v := oneVerdict(t, r)
	if len(v.Abstentions) != 1 || v.Abstentions[0] != "maldet" {
		t.Fatalf("maldet should show up as an abstention, got %v", v.Abstentions)
	}
	if reason := r.Abstentions["maldet"]; reason == "" {
		t.Error("the abstention has to carry the real reason")
	}
	// And most importantly: the verdict came out. The cycle completed with the rest.
	if v.Level != schema.LevelSuspicious {
		t.Errorf("the verdict should have come out normally, got %s", v.Level)
	}
}

// Structural rules ------------------------------------------------------------

func TestAnAbstentionDoesNotDiluteTheScore(t *testing.T) {
	// If the abstention entered the denominator, an engine that hit its timeout
	// would downgrade a confirmed to likely — turning a technical failure into a
	// security decision (DECISIONS.md D-004).
	withAbstention := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("maldet", finding("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			schema.FailedReport("s_1", "php-malware-finder", schema.StatusFailed, errTimeout{}, time.Now()),
		},
		ExpectedEngines: []string{"maldet", "amwscan", "php-malware-finder", "wp-checksums"},
	})

	withoutAbstention := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("maldet", finding("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	a := oneVerdict(t, withAbstention)
	b := oneVerdict(t, withoutAbstention)
	if a.Score != b.Score {
		t.Fatalf("the abstention changed the score: %.4f with, %.4f without", a.Score, b.Score)
	}
	if a.Level != schema.LevelConfirmed {
		t.Errorf("the level was downgraded because of a technical failure: %s", a.Level)
	}
	// But the abstention MUST show up: 2 failed or vanished.
	if len(a.Abstentions) != 2 {
		t.Errorf("expected 2 recorded abstentions, got %v", a.Abstentions)
	}
}

func TestAnEnabledEngineThatVanishedAlsoAbstains(t *testing.T) {
	// Vanishing silently must not look like "it ran and found nothing".
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan", finding("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
		ExpectedEngines: []string{"amwscan", "maldet", "wp-checksums"},
	})

	if _, ok := r.Abstentions["maldet"]; !ok {
		t.Error("an enabled engine with no report should show up as an abstention")
	}
	if _, ok := r.Abstentions["wp-checksums"]; !ok {
		t.Error("an enabled engine with no report should show up as an abstention")
	}
	if _, ok := r.Abstentions["amwscan"]; ok {
		t.Error("an engine that ran must not show up as an abstention")
	}
}

func TestOneEngineWithSeveralRulesIsStillASingleVote(t *testing.T) {
	// Counting five rules as five votes would let a single scanner decide any
	// verdict on its own — the opposite of consensus.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan",
				finding("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceSignature),
				finding("amwscan", "SHELL_EXEC", shaA, "/site/x.php", schema.ConfidenceSignature),
				finding("amwscan", "OBFUSCATED_BLOB", shaA, "/site/x.php", schema.ConfidenceSignature),
				finding("amwscan", "SEO_SPAM", shaA, "/site/x.php", schema.ConfidenceSignature),
			),
		},
	})

	v := oneVerdict(t, r)
	if len(v.Votes) != 1 {
		t.Fatalf("four rules from the same engine should give 1 vote, got %d", len(v.Votes))
	}
	if v.Level == schema.LevelConfirmed {
		t.Error("one engine alone cannot reach confirmed just by repeating rules")
	}
}

func TestTheVoteUsesTheEnginesStrongestRule(t *testing.T) {
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan",
				finding("amwscan", "SUSPICIOUS_TITLE", shaA, "/site/x.php", schema.ConfidenceAnomaly),
				finding("amwscan", "KNOWN_MALWARE", shaA, "/site/x.php", schema.ConfidenceSignature),
			),
		},
	})

	v := oneVerdict(t, r)
	if v.Votes[0].Confidence != schema.ConfidenceSignature {
		t.Errorf("the vote should use the strongest rule, got %q", v.Votes[0].Confidence)
	}
	if v.Votes[0].Rule != "KNOWN_MALWARE" {
		t.Errorf("the recorded rule should be the strongest one, got %q", v.Votes[0].Rule)
	}
}

func TestDeduplicationByHashJoinsEnginesIntoOneVerdict(t *testing.T) {
	// The hash joins the VOTES; the path decides the VERDICTS.
	//
	// This test used to assert that the same content at two paths is "still a single
	// target". A real account disproved it: three identical files produced three findings
	// and one verdict, and the two copies that went unnamed would never have been
	// quarantined and were counted nowhere. Dropping the same webshell in many
	// directories is standard practice precisely so that cleaning one achieves nothing,
	// so each copy needs its own actionable verdict. See D-028.
	//
	// What the hash still does, and must keep doing, is merge the votes: both engines
	// below are talking about the same content, so both copies of it are equally proven.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan", finding("amwscan", "EVAL_POST", shaA, "/site/a.php", schema.ConfidenceHeuristic)),
			report("maldet", finding("maldet", "php.x", shaA, "/site/b.php", schema.ConfidenceHeuristic)),
			report("php-malware-finder", finding("php-malware-finder", "DangerousPhp", shaB, "/site/c.php", schema.ConfidenceHeuristic)),
		},
	})

	if len(r.Verdicts) != 3 {
		t.Fatalf("expected 3 verdicts (3 distinct paths), got %d", len(r.Verdicts))
	}

	ids := map[string]bool{}
	for _, v := range r.Verdicts {
		if ids[v.VerdictID] {
			t.Errorf("two verdicts share the id %s: one of them would be lost on write", v.VerdictID)
		}
		ids[v.VerdictID] = true

		if v.FileSHA256 == shaA && len(v.Votes) != 2 {
			t.Errorf("%s: %d vote(s) — both engines flagged this content, so every copy of it "+
				"carries both", v.FilePath, len(v.Votes))
		}
	}
}

func TestTheWhitelistBlocksTheActionButKeepsTheVerdict(t *testing.T) {
	// D-006: the file stays visible in the report at its real level. Downgrading it
	// to clean would hide that the engines keep flagging it.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("maldet", finding("maldet", "r", shaA, "/site/wp-content/plugins/mine/x.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "r", shaA, "/site/wp-content/plugins/mine/x.php", schema.ConfidenceSignature)),
		},
		Whitelist: []string{"**/wp-content/plugins/mine/**"},
	})

	v := oneVerdict(t, r)
	if v.Level != schema.LevelConfirmed {
		t.Fatalf("the whitelist must not change the level, got %s", v.Level)
	}
	if v.ActionTaken != schema.ActionSkippedWhitelist {
		t.Fatalf("the action should be blocked by the whitelist, got %q", v.ActionTaken)
	}
	// The user needs to know WHICH rule protected the file.
	if !strings.Contains(v.ActionError, "mine") {
		t.Errorf("the protecting rule should be on record, got %q", v.ActionError)
	}
}

func TestAReportThatAbstainsContributesNoFindings(t *testing.T) {
	// An engine that did not finish looking may have partial findings; accepting
	// them as a vote would give weight to an incomplete read.
	partial := report("maldet", finding("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature))
	partial.Status = schema.StatusPartial
	partial.Error = "read error on 12 files"

	r := engine().Consolidate(verdict.Input{
		ScanID:  "s_1",
		Reports: []schema.ScanReport{partial},
	})

	if len(r.Verdicts) != 0 {
		t.Fatalf("a finding from a partial report should not become a verdict, got %d", len(r.Verdicts))
	}
	if r.Abstentions["maldet"] == "" {
		t.Error("the partial engine should show up as an abstention with a reason")
	}
}

func TestCleanFilesFromAFailedReportDoNotCount(t *testing.T) {
	// A wp-checksums that died halfway only checked part of the files. Accepting
	// that list would grant immunity to files nobody checked.
	failed := schema.FailedReport("s_1", "wp-checksums", schema.StatusTimeout, errTimeout{}, time.Now())
	failed.CleanFiles = []string{shaA}

	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			failed,
			report("maldet", finding("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := oneVerdict(t, r)
	if v.CleanReason != "" {
		t.Fatal("a clean list from a failed report must not veto")
	}
	if v.Level != schema.LevelConfirmed {
		t.Errorf("the verdict should follow the votes, got %s", v.Level)
	}
}

func TestAnEngineWithZeroWeightHasNoInfluence(t *testing.T) {
	cfg := config.Default()
	cfg.Engines["amwscan"] = config.Engine{Enabled: true, Weight: 0}
	e := verdict.New(cfg.Verdict, cfg.Engines)

	r := e.Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan", finding("amwscan", "KNOWN_MALWARE", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := oneVerdict(t, r)
	if len(v.Votes) != 0 {
		t.Errorf("an engine with weight 0 should not vote, got %d votes", len(v.Votes))
	}
	if v.Level != schema.LevelClean {
		t.Errorf("with no votes the level should be clean, got %s", v.Level)
	}
}

func TestAnUnknownEngineDoesNotVote(t *testing.T) {
	// An adapter not registered in the configuration must not influence a verdict
	// just by showing up in a report.
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("unconfigured-engine", finding("unconfigured-engine", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := oneVerdict(t, r)
	if len(v.Votes) != 0 {
		t.Errorf("an unknown engine should not vote, got %d", len(v.Votes))
	}
}

func TestTheScoreSaturates(t *testing.T) {
	// Five strong engines must not blow past the [0,1] interval.
	cfg := config.Default()
	cfg.Engines["e1"] = config.Engine{Enabled: true, Weight: 1.5}
	cfg.Engines["e2"] = config.Engine{Enabled: true, Weight: 1.5}
	cfg.Engines["e3"] = config.Engine{Enabled: true, Weight: 1.5}
	e := verdict.New(cfg.Verdict, cfg.Engines)

	r := e.Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("e1", finding("e1", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("e2", finding("e2", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("e3", finding("e3", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
		},
	})

	v := oneVerdict(t, r)
	if v.Score > 1.0 {
		t.Fatalf("the score blew past the interval: %.4f", v.Score)
	}
	if err := v.Validate(); err != nil {
		t.Errorf("a saturated verdict should be valid: %v", err)
	}
}

func TestAVulnerabilityFindingDoesNotEnterTheMalwareScore(t *testing.T) {
	// Malware and vulnerability are parallel pipelines that never mix into the same
	// score (schema section 3).
	vuln := finding("amwscan", "vulnerable-component", shaA, "/site/x.php", schema.ConfidenceSignature)
	vuln.Kind = schema.KindVulnerability
	vuln.Category = schema.CategoryVulnerableComponent
	vuln.Component = &schema.Component{Type: "wordpress-plugin", Slug: "cf7", InstalledVersion: "5.7.1"}

	r := engine().Consolidate(verdict.Input{
		ScanID:  "s_1",
		Reports: []schema.ScanReport{report("amwscan", vuln)},
	})

	if len(r.Verdicts) != 0 {
		t.Fatalf("a vulnerability finding must not become a malware verdict, got %d", len(r.Verdicts))
	}
}

func TestTheVerdictIDIsDeterministic(t *testing.T) {
	// Re-running the same cycle has to UPDATE the verdict, not duplicate it.
	in := verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan", finding("amwscan", "EVAL_POST", shaA, "/site/x.php", schema.ConfidenceHeuristic)),
		},
	}
	a := oneVerdict(t, engine().Consolidate(in))
	b := oneVerdict(t, engine().Consolidate(in))
	if a.VerdictID != b.VerdictID {
		t.Errorf("different ids for the same cycle and file: %s vs %s", a.VerdictID, b.VerdictID)
	}
}

func TestTheOrderOfTheVerdictsIsStable(t *testing.T) {
	in := verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("amwscan",
				finding("amwscan", "r", shaB, "/site/b.php", schema.ConfidenceHeuristic),
				finding("amwscan", "r", shaA, "/site/a.php", schema.ConfidenceHeuristic),
			),
		},
	}
	first := engine().Consolidate(in)
	for i := 0; i < 10; i++ {
		other := engine().Consolidate(in)
		for j := range first.Verdicts {
			if first.Verdicts[j].FileSHA256 != other.Verdicts[j].FileSHA256 {
				t.Fatal("the order of the verdicts varied between runs")
			}
		}
	}
}

func TestEveryVerdictProducedIsValid(t *testing.T) {
	r := engine().Consolidate(verdict.Input{
		ScanID: "s_1",
		Reports: []schema.ScanReport{
			report("maldet", finding("maldet", "r", shaA, "/site/x.php", schema.ConfidenceSignature)),
			report("amwscan", finding("amwscan", "r", shaB, "/site/y.php", schema.ConfidenceHeuristic)),
		},
	})
	for _, v := range r.Verdicts {
		if err := v.Validate(); err != nil {
			t.Errorf("an invalid verdict came out of the engine: %v", err)
		}
	}
}

type errTimeout struct{}

func (errTimeout) Error() string { return "timeout after 300s" }
