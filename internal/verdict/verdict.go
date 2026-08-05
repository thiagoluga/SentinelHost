// Package verdict consolidates the findings of several engines into one verdict
// per file.
//
// This package knows NO engine: it only understands the normalized schema
// (Principle VI). Replacing AMWScan with another scanner does not change a line
// here.
//
// The formula and the rules are documented in DECISIONS.md D-003 through D-006.
package verdict

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
	"github.com/thiagoluga/SentinelHost/internal/reach"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// CleanReasonOfficialChecksum is the only veto reason today.
const CleanReasonOfficialChecksum = "official_checksum_match"

// Engine is the consensus engine.
type Engine struct {
	cfg     config.VerdictConfig
	weights map[string]float64
}

// New creates the engine from the configuration.
func New(cfg config.VerdictConfig, engines map[string]config.Engine) *Engine {
	w := make(map[string]float64, len(engines))
	for slug, e := range engines {
		w[slug] = e.Weight
	}
	return &Engine{cfg: cfg, weights: w}
}

// Input is everything the engine needs in order to decide.
type Input struct {
	ScanID string
	// Reports are the reports of every engine that ran, including the ones that
	// failed — a failure is information, not the absence of information.
	Reports []schema.ScanReport
	// ExpectedEngines are the engines enabled in the configuration. An enabled
	// engine that produced no report at all is also an abstention: vanishing
	// silently must not look like "it ran and found nothing".
	ExpectedEngines []string
	// Whitelist of the user's globs.
	Whitelist []string
	// Reach classifies a path as served by the web or not. Optional: without it every
	// verdict is treated as reachable, which is the safe reading of "not known".
	Reach *reach.Classifier
	Now   time.Time
}

// Result is the output of the consolidation.
type Result struct {
	Verdicts []schema.Verdict
	// Abstentions lists the engines that did not vote, with the reason.
	Abstentions map[string]string
	// CleanFileCount is how many hashes were declared legitimate by an official
	// checksum.
	CleanFileCount int
}

// Consolidate turns the reports into verdicts, one per file.
func (e *Engine) Consolidate(in Input) Result {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	abstentions := e.collectAbstentions(in)
	official := collectOfficialCleanHashes(in.Reports)

	// Group findings by sha256: it is the deduplication key across engines. The
	// same file flagged by N engines = N votes on the SAME target.
	groups := groupBySHA(in.Reports)

	abstentionList := make([]string, 0, len(abstentions))
	for slug := range abstentions {
		abstentionList = append(abstentionList, slug)
	}
	sort.Strings(abstentionList)

	// Votes are merged per CONTENT; verdicts are emitted per PATH.
	//
	// The group is the right unit for scoring — the same file flagged by N engines is N
	// votes on one target — and it was the wrong unit for output. Identical content
	// planted at several paths collapsed into a single verdict naming a single path, and
	// the other copies appeared in no verdict, no summary bucket and no skipped counter.
	// They were simply gone: never quarantined, never mentioned, on a site the tool then
	// reported as handled.
	//
	// That is not a corner case. Dropping the same webshell into many directories is
	// standard practice precisely so that cleaning one accomplishes nothing, and it is
	// exactly when a scanner must not manufacture confidence. Found on a real account
	// (DECISIONS.md D-028): three planted copies, three findings, one verdict.
	//
	// Each path gets its own verdict carrying the FULL vote set for that content, so a
	// copy is never less actionable than the one that happened to be named first.
	verdicts := make([]schema.Verdict, 0, len(groups))
	for _, sha := range sortedKeys(groups) {
		findings := groups[sha]
		for _, path := range distinctPaths(findings) {
			verdicts = append(verdicts,
				e.consolidateFile(in, sha, findings, path, official, abstentionList, now))
		}
	}

	return Result{
		Verdicts:       verdicts,
		Abstentions:    abstentions,
		CleanFileCount: len(official),
	}
}

// consolidateFile decides about ONE file.
func (e *Engine) consolidateFile(
	in Input,
	sha string,
	findings []schema.Finding,
	path string,
	official map[string]bool,
	abstentions []string,
	now time.Time,
) schema.Verdict {
	votes := e.buildVotes(findings)

	sum := 0.0
	for _, v := range votes {
		sum += v.EffectiveWeight
	}
	score := e.score(sum)
	level := e.level(score)

	size := sizeAt(findings, path)

	v := schema.Verdict{
		SchemaVersion: schema.Version,
		VerdictID:     verdictID(in.ScanID, sha, path),
		FileSHA256:    sha,
		FilePath:      path,
		FileSize:      size,
		Level:         level,
		Score:         score,
		Votes:         votes,
		Abstentions:   abstentions,
		ActionTaken:   schema.ActionNone,
		ScanID:        in.ScanID,
		CreatedAt:     now,
	}

	// Official-checksum veto (D-005). Applied AFTER the calculation, and not as a
	// negative vote: a vote could be overcome by enough other votes, and the rule
	// is "never, regardless of votes". The votes stay on record so the user can see
	// that the engines did flag it and why they were overruled.
	if official[sha] {
		v.Level = schema.LevelClean
		v.Score = 0
		v.CleanReason = CleanReasonOfficialChecksum
		v.ActionTaken = schema.ActionSkippedOfficial
		return v
	}

	// Where the file sits, relative to what the web serves.
	//
	// Recorded on every verdict, including the reachable ones: "this IS served" is the
	// half of the answer that makes a finding urgent, and leaving it off would make the
	// field look like a flag that only appears for the harmless cases.
	if in.Reach != nil {
		loc := in.Reach.Of(path)
		v.FileLocation = string(loc)

		// Not served means the tool does not act by itself. The verdict is untouched and
		// stays at its real level — this blocks the ACTION only, exactly as the whitelist
		// does (D-006).
		//
		// Moving a file out of the trash and into our vault swaps one holding area for
		// another without reducing any risk, and takes it further from where its owner
		// expects to find it. The reason travels with it, and says what "unreachable"
		// does NOT mean, because that is the half that invites the wrong conclusion.
		if !loc.Reachable() && v.Level != schema.LevelClean {
			v.ActionTaken = schema.ActionSkippedNotReachable
			v.ActionError = "not acted on automatically: " + loc.Explain()
		}
	}

	// The whitelist blocks the ACTION, not the verdict (D-006). The file stays
	// visible in the report at its real level: downgrading it to clean would hide
	// from the user that the engines keep flagging that file.
	//
	// After the reachability check, so an explicit whitelist entry — something the user
	// wrote themselves — is the reason shown when both apply.
	if rule := pathmatch.WhichMatches(in.Whitelist, path); rule != "" && v.Level != schema.LevelClean {
		v.ActionTaken = schema.ActionSkippedWhitelist
		v.ActionError = "protected by the whitelist rule: " + rule
	}

	return v
}

// buildVotes builds one vote per ENGINE, not per finding.
//
// An engine that flags the same file under five different rules is still one
// engine. Counting five votes would let a single scanner decide any verdict on its
// own — the opposite of consensus.
func (e *Engine) buildVotes(findings []schema.Finding) []schema.Vote {
	best := map[string]schema.Vote{}

	for _, f := range findings {
		weight := e.weights[f.Engine]
		if weight <= 0 {
			// An unknown engine, or one with zero weight, does not influence the
			// verdict. Its finding is archived and visible in the panel all the same.
			continue
		}
		effective := weight * e.confidenceMultiplier(f.Confidence)

		current, exists := best[f.Engine]
		if !exists || effective > current.EffectiveWeight {
			best[f.Engine] = schema.Vote{
				Engine:          f.Engine,
				FindingID:       f.ID,
				Weight:          weight,
				Confidence:      f.Confidence,
				EffectiveWeight: effective,
				Rule:            f.Rule,
				Category:        f.Category,
			}
		}
	}

	out := make([]schema.Vote, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	// Stable order, strongest vote first: it is the order in which the user wants
	// to read "why was this file flagged".
	sort.Slice(out, func(i, j int) bool {
		if out[i].EffectiveWeight != out[j].EffectiveWeight {
			return out[i].EffectiveWeight > out[j].EffectiveWeight
		}
		return out[i].Engine < out[j].Engine
	})
	return out
}

func (e *Engine) confidenceMultiplier(c schema.Confidence) float64 {
	switch c {
	case schema.ConfidenceSignature:
		return e.cfg.SignatureMultiplier
	case schema.ConfidenceHeuristic:
		return e.cfg.HeuristicMultiplier
	case schema.ConfidenceAnomaly:
		return e.cfg.AnomalyMultiplier
	default:
		// An unknown confidence weighs as the weakest one. An adapter that invents
		// a new value must not gain weight for it.
		return e.cfg.AnomalyMultiplier
	}
}

// score normalizes the sum of weights by a saturation ceiling.
//
// The sum divided by a ceiling, not an average: with an average, every engine
// that abstains would dilute the score, turning a technical failure into a vote of
// innocence — which Principle VI explicitly forbids (DECISIONS.md D-003 and
// D-004).
func (e *Engine) score(sum float64) float64 {
	sat := e.cfg.Saturation
	if sat <= 0 {
		sat = 2.0
	}
	s := sum / sat
	if s > 1 {
		return 1
	}
	if s < 0 {
		return 0
	}
	return s
}

func (e *Engine) level(score float64) schema.Level {
	switch {
	case score >= e.cfg.ConfirmedAt:
		return schema.LevelConfirmed
	case score >= e.cfg.LikelyAt:
		return schema.LevelLikely
	case score >= e.cfg.SuspiciousAt:
		return schema.LevelSuspicious
	default:
		return schema.LevelClean
	}
}

// collectAbstentions gathers who did not vote, and why.
func (e *Engine) collectAbstentions(in Input) map[string]string {
	out := map[string]string{}

	seen := map[string]bool{}
	for _, r := range in.Reports {
		seen[r.Engine] = true
		if r.Abstains() {
			reason := r.Error
			if reason == "" {
				reason = fmt.Sprintf("report with status %q", r.Status)
			}
			out[r.Engine] = reason
		}
	}

	// An enabled engine that produced no report at all. Vanishing silently must
	// not look like "it ran and found nothing".
	for _, slug := range in.ExpectedEngines {
		if !seen[slug] {
			out[slug] = "the engine was enabled but produced no report in this cycle"
		}
	}
	return out
}

// collectOfficialCleanHashes gathers the hashes declared legitimate.
//
// Only COMPLETED reports count. A wp-checksums that failed halfway may have listed
// as clean only the files it managed to verify; accepting that partial list would
// grant immunity to files nobody checked.
func collectOfficialCleanHashes(reports []schema.ScanReport) map[string]bool {
	out := map[string]bool{}
	for _, r := range reports {
		if r.Abstains() {
			continue
		}
		for _, h := range r.CleanFiles {
			out[h] = true
		}
	}
	return out
}

// groupBySHA groups malware findings by the file's hash.
func groupBySHA(reports []schema.ScanReport) map[string][]schema.Finding {
	out := map[string][]schema.Finding{}
	for _, r := range reports {
		// A report that abstains contributes no findings: the engine did not
		// finish looking, and a partial finding of its own cannot become a vote.
		if r.Abstains() {
			continue
		}
		for _, f := range r.Findings {
			if f.EffectiveKind() != schema.KindMalware {
				// Vulnerability and hardening are consolidated per component, in a
				// separate pipeline (spec 002). They never mix into the malware
				// score.
				continue
			}
			if f.File.SHA256 == "" {
				continue
			}
			out[f.File.SHA256] = append(out[f.File.SHA256], f)
		}
	}
	return out
}

// distinctPaths lists every path the findings named, in a stable order.
//
// Stable because a verdict list that reorders itself between cycles is one nobody can
// diff, and diffing two cycles is how a user answers "is this getting better?".
func distinctPaths(findings []schema.Finding) []string {
	seen := make(map[string]bool, len(findings))
	paths := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.File.Path == "" || seen[f.File.Path] {
			continue
		}
		seen[f.File.Path] = true
		paths = append(paths, f.File.Path)
	}
	sort.Strings(paths)
	return paths
}

// sizeAt reports the size recorded for one path, preferring the most recent sighting.
//
// Most recent because engines run at different moments within a cycle, and if a file
// changed underneath them the later reading is the one that describes what is on disk
// now. The size is only ever descriptive — nothing is decided by it — but a number shown
// to a user should be the truest one available.
func sizeAt(findings []schema.Finding, path string) int64 {
	var size int64
	var mostRecent time.Time
	for _, f := range findings {
		if f.File.Path != path {
			continue
		}
		if size == 0 || f.DetectedAt.After(mostRecent) {
			size = f.File.SizeBytes
			mostRecent = f.DetectedAt
		}
	}
	return size
}

// verdictID is deterministic from the cycle and the file.
//
// Determinism matters: re-running the same cycle has to UPDATE the verdict, not
// create a second one. Without that, the panel would fill with duplicates on every
// reprocessing.
// verdictID identifies one verdict: one content, at one path, in one cycle.
//
// The path is part of the identity, not decoration. Now that identical content at
// several paths produces one verdict each, an id derived from (scan, sha) alone would
// be the same string for all of them — and two rows sharing a primary key means the
// store keeps one and loses the rest, which is the very silent loss this change exists
// to fix, moved one layer down.
func verdictID(scanID, sha, path string) string {
	sum := sha256.Sum256([]byte(scanID + ":" + sha + ":" + path))
	return "v_" + hex.EncodeToString(sum[:])[:12]
}

// FindingID generates a finding's id, also deterministically.
//
// The orchestrator generates the ids, never the adapter (schema section 1.1).
//
// The PATH is part of the identity, for the same reason it is part of verdictID: three
// byte-identical copies of a payload produce three findings, and without the path they
// produce one id. findings.id is a TEXT PRIMARY KEY written with ON CONFLICT DO NOTHING,
// so two of the three rows were dropped in silence — and the panel, which fetches evidence
// by (sha, scan, path), then showed a confirmed verdict with its votes above zero pieces
// of evidence.
//
// verdictID was fixed for this and the fix was not carried down one layer.
func FindingID(scanID, engine, rule, sha, path string) string {
	sum := sha256.Sum256([]byte(scanID + ":" + engine + ":" + rule + ":" + sha + ":" + path))
	return "f_" + hex.EncodeToString(sum[:])[:12]
}

func sortedKeys(m map[string][]schema.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
