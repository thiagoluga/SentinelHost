// Package pmf integrates php-malware-finder, a set of YARA rules for malicious
// PHP.
//
// The engine is run through the external `yara` binary, never through libyara:
// linking the library would require CGO and break the static binary Principle
// VII demands. Without `yara` in the environment the engine is unavailable with
// a clear reason and the consensus proceeds with the others (plan.md, technical
// decision 1).
package pmf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/config"
	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Slug of the engine.
const Slug = "php-malware-finder"

// RulesURL is where the YARA rules are downloaded from at install time.
//
// The path is data/php.yar: the repository was rewritten in Go and the
// php-malware-finder/ directory no longer exists on the main branch (the old
// path answers 404).
const RulesURL = "https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/data/php.yar"

// WhitelistURL ships alongside the rules. php-malware-finder uses its own
// whitelist to avoid flagging known-legitimate code; without it the engine
// produces considerably more noise.
const WhitelistURL = "https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/data/whitelist.yar"

// FileStat is the metadata computed by the orchestrator.
type FileStat struct {
	SHA256 string
	Size   int64
	Perms  string
	MTime  time.Time
}

// Adapter integrates php-malware-finder through the yara binary.
type Adapter struct {
	rulesURL string
	stat     func(string) (FileStat, bool)
	// download is injectable in tests.
	download func(ctx context.Context, url, dest string) error
}

// New creates the adapter.
func New() *Adapter {
	return &Adapter{rulesURL: RulesURL, stat: statFile, download: downloadFile}
}

// WithStat swaps the metadata function. Tests only.
func (a *Adapter) WithStat(fn func(string) (FileStat, bool)) *Adapter {
	a.stat = fn
	return a
}

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "php-malware-finder (YARA rules)",
		License:  "GPL-3.0 (rules and the yara binary used as an external process, never linked)",
		Homepage: "https://github.com/jvoisin/php-malware-finder",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryObfuscation, schema.CategoryBackdoor, schema.CategoryWebshell,
			schema.CategorySpamSEO, schema.CategoryPhishing, schema.CategoryInjection,
			schema.CategoryDropper, schema.CategorySuspiciousLocation,
			schema.CategorySuspiciousPerms, schema.CategoryKnownMalware, schema.CategoryOther,
		},
		Cost: adapter.CostMedium,
		// yara honours --scan-list: it walks exactly the list it is handed.
		ScopeAware:    true,
		DefaultWeight: config.WeightPMF,
	}
}

func rulesPath(dataDir string) string {
	return filepath.Join(dataDir, "engines", "pmf", "php.yar")
}

var yaraVersionRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

// Probe checks the yara binary and the rules.
func (a *Adapter) Probe(ctx context.Context, env adapter.Environment) adapter.ProbeResult {
	if env.Runner == nil {
		return adapter.Unavailable("no executor available")
	}
	yara := env.BinaryPath
	if yara == "" {
		yara = "yara"
	}

	res := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-probe",
		Path:   yara,
		Args:   []string{"--version"},
	})
	if res.Status != schema.StatusCompleted || res.ExitCode != 0 {
		return adapter.Unavailable(
			"the `yara` binary was not found on PATH. php-malware-finder is a set of YARA rules and needs yara to run; " +
				"without it this engine abstains and the consensus proceeds with the others")
	}
	version := "unknown"
	if m := yaraVersionRe.FindStringSubmatch(string(res.Stdout)); m != nil {
		version = m[1]
	}

	rules := rulesPath(env.DataDir)
	info, err := os.Stat(rules)
	if err != nil {
		return adapter.UnavailableInstallable(fmt.Sprintf(
			"yara %s is available, but the php-malware-finder rules are not installed at %s yet", version, rules))
	}

	return adapter.ProbeResult{
		Available:           true,
		Version:             "yara " + version,
		BinaryPath:          rules,
		SignaturesUpdatedAt: info.ModTime(),
	}
}

// Install downloads the rules into the user's space.
func (a *Adapter) Install(ctx context.Context, env adapter.Environment) error {
	if env.Offline {
		return errors.New("offline mode: the YARA rules cannot be downloaded")
	}
	dest := rulesPath(env.DataDir)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("creating the rules directory: %w", err)
	}
	return a.download(ctx, a.rulesURL, dest)
}

// UpdateSignatures downloads the rules again.
func (a *Adapter) UpdateSignatures(ctx context.Context, env adapter.Environment) (time.Time, error) {
	if err := a.Install(ctx, env); err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(rulesPath(env.DataDir))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Scan runs yara over the path list.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	if env.Runner == nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, errors.New("no executor available")
	}
	yara := env.BinaryPath
	if yara == "" {
		yara = "yara"
	}
	rules := rulesPath(env.DataDir)
	if _, err := os.Stat(rules); err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed},
			fmt.Errorf("the YARA rules are not installed at %s: %w", rules, err)
	}

	args := []string{
		"--no-warnings",
		"-s", // print the matched strings, which become matched_content
		"-w",
		// An obfuscated file can match the same rule thousands of times.
		// Without a ceiling, ONE file's output dominates the whole report — and
		// matched_content is truncated to 512 bytes anyway.
		"--max-strings-per-rule", "20",
	}
	// The file size limit is applied by the orchestrator's walker, not here: the
	// orchestrator decides the scope (adapter contract).
	// The target list goes through --scan-list. There is NO "@file" syntax in
	// yara — that assumption was in the code and only fell when the real engine
	// was run in a Linux container.
	listFile, cleanup, err := adapter.WriteTargetList(env.DataDir, Slug, req.Paths)
	if err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, err
	}
	defer cleanup()
	args = append(args, "--scan-list")

	args = append(args, env.ExtraArgs...)
	// yara's mandatory order: RULES last, then the target.
	args = append(args, rules, listFile)

	res := env.Runner.Run(ctx, sexec.Command{
		Engine:  Slug,
		ScanID:  req.ScanID,
		Path:    yara,
		Args:    args,
		Dir:     req.Root,
		Timeout: req.Timeout,
	})

	out := adapter.FromExecResult(req, Slug, res)
	if res.Abstains() {
		return out, res.Err
	}
	return out, nil
}

// stringLineRe matches the string lines of yara -s: "0x1f2:$name: snippet".
// Groups: hexadecimal offset, string name, matched snippet.
var stringLineRe = regexp.MustCompile(`^0x([0-9a-fA-F]+):\$?([^:]*):\s?(.*)$`)

// Parse converts yara's text output into the normalized schema.
//
// The format is hierarchical: an unindented "RULE PATH" line, followed by the
// string lines belonging to it. Treating each line in isolation would produce
// findings with no file.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        raw.ScanID,
		Engine:        Slug,
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

	// Empty output from a process that COMPLETED means "no rule matched" — the
	// normal, happy path. Empty output from a process that failed has already
	// been turned into an abstention before reaching here, by SafeScanAndParse.
	// That is why this Parse must not invent an error for empty stdout: it would
	// turn a clean site into an engine failure.
	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	type pending struct {
		rule    string
		path    string
		strings []string
		// offset of the first matched string, so the user knows where to look in
		// the file.
		offset int64
	}
	var current *pending
	unknown := 0

	flush := func() {
		if current == nil {
			return
		}
		defer func() { current = nil }()

		m, known := classify(current.rule)
		if !known {
			unknown++
		}
		st, ok := a.stat(current.path)
		if !ok || st.SHA256 == "" {
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["vanished_before_hashing"]++
			return
		}
		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          current.rule,
			RuleRef:       "https://github.com/jvoisin/php-malware-finder",
			File: schema.FileRef{
				Path:      current.path,
				SizeBytes: st.Size,
				SHA256:    st.SHA256,
				MTime:     st.MTime,
				Perms:     st.Perms,
			},
			Category:   m.category,
			Severity:   m.severity,
			Confidence: m.confidence,
			// The matched snippet is truncated and sanitized: malicious content
			// is never served back by the UI.
			MatchedContent: schema.SanitizeSnippet(strings.Join(current.strings, " | ")),
			MatchedOffset:  current.offset,
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	sc := bufio.NewScanner(strings.NewReader(string(raw.Stdout)))
	// yara -s lines can be long; the 64 KiB default is not enough.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := stringLineRe.FindStringSubmatch(line); m != nil {
			if current != nil {
				if len(current.strings) == 0 {
					if off, err := strconv.ParseInt(m[1], 16, 64); err == nil {
						current.offset = off
					}
				}
				current.strings = append(current.strings, m[3])
			}
			// A string with no preceding rule is debris from truncated output;
			// ignoring it beats creating a finding with no file.
			continue
		}

		rule, path, ok := strings.Cut(line, " ")
		if !ok || rule == "" || path == "" {
			continue
		}
		flush()
		current = &pending{rule: rule, path: strings.TrimSpace(path)}
	}
	flush()

	if err := sc.Err(); err != nil {
		return rep, fmt.Errorf("reading yara's output: %w", err)
	}

	if unknown > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["unknown_rule"] = unknown
	}
	return rep, nil
}

func statFile(path string) (FileStat, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return FileStat{}, false
	}
	f, err := os.Open(path) // path comes from the engine's output over the configured root
	if err != nil {
		return FileStat{}, false
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileStat{}, false
	}
	return FileStat{
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   info.Size(),
		Perms:  fmt.Sprintf("%04o", info.Mode().Perm()),
		MTime:  info.ModTime(),
	}, true
}
