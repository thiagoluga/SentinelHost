// Package amwscan integrates AMWScan (PHP Antimalware Scanner), a scanner
// written in pure PHP that runs on any hosting with a PHP CLI.
//
// It is the most portable engine in the MVP: it needs no compiled binary, only
// `php` on the command line — and the extensions it uses, which is NOT the same
// as "it only needs PHP" (see Probe).
package amwscan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
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
const Slug = "amwscan"

// Phar is pinned: an immutable commit, and the digest of the bytes there.
//
// This was `.../master/dist/scanner`, and the file is a PHP program this tool then
// executes. Downloading an executable from the end of somebody else's branch means
// whoever can push to that branch runs code on every account that installs SentinelHost.
// The project publishes releases without assets, so a commit is the only immutable
// address available — which makes the digest the part that actually protects anything.
var Phar = adapter.Pinned{
	Name:   "the AMWScan scanner",
	URL:    "https://raw.githubusercontent.com/marcocesarato/PHP-Antimalware-Scanner/32aac3dae97b58210541e6c765507155f5e490be/dist/scanner",
	SHA256: "b435438d431da3ff5f6fa4d360e523ca71c98647d021cd299962a278b351dab8",
}

// PharURL keeps the old name for callers that only need the address.
const PharURL = "https://raw.githubusercontent.com/marcocesarato/PHP-Antimalware-Scanner/32aac3dae97b58210541e6c765507155f5e490be/dist/scanner"

// MinPHPVersion required by the engine.
const MinPHPVersion = "7.1"

// AMWScan's incremental scope is applied by the ADAPTER, not by the engine.
//
// Two real limitations, both measured in the validation container, force that
// choice:
//
//  1. `--filter-paths` has AND semantics, not OR. With one path it works; with
//     two or more the engine runs, exits 0, writes the report and flags
//     NOTHING — not even the files that would match on their own. That is the
//     worst possible failure mode for this project: green engine, clean report,
//     infected site.
//  2. `--filter-paths` filters the REPORT, not the set that gets walked. One
//     execution per file cost 1m37s for 11 files, because each one walked the
//     whole root again.
//
// Conclusion: one execution per cycle, over the root, and Parse discards what
// the orchestrator did not ask for. It is more CPU than ideal — AMWScan simply
// does not know how to scan a file list — but it is correct, and correct comes
// first.

// targetsKey is where Scan stores, in RawOutput, the set of paths the
// orchestrator asked for, so Parse can discard the surplus.
const targetsKey = "targets"

// FileStat is the metadata the orchestrator computes about a file flagged by an
// engine that does not report a hash.
type FileStat struct {
	SHA256 string
	Size   int64
	Perms  string
	MTime  time.Time
}

// Adapter integrates AMWScan.
type Adapter struct {
	pharURL string
	http    *http.Client
	// stat is injectable so the contract test can exercise the parser with
	// fixtures that cite paths from a real server.
	stat func(string) (FileStat, bool)
}

// New creates the adapter.
func New() *Adapter {
	return &Adapter{
		pharURL: PharURL,
		http:    &http.Client{Timeout: 2 * time.Minute},
		stat:    statFile,
	}
}

// WithStat swaps the metadata function. Tests only.
func (a *Adapter) WithStat(fn func(string) (FileStat, bool)) *Adapter {
	a.stat = fn
	return a
}

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "AMWScan (PHP Antimalware Scanner)",
		License:  "GPL-3.0 (invoked as an external process, never linked)",
		Homepage: "https://github.com/marcocesarato/PHP-Antimalware-Scanner",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryKnownMalware, schema.CategoryBackdoor, schema.CategoryWebshell,
			schema.CategoryObfuscation, schema.CategoryDropper, schema.CategoryInjection,
			schema.CategorySpamSEO, schema.CategoryPhishing, schema.CategoryOther,
		},
		Cost: adapter.CostMedium,
		// --filter-paths filters the REPORT, not the walk: the engine reads the
		// whole root every time. See D-018.
		ScopeAware:    false,
		DefaultWeight: config.WeightAMWScan,
	}
}

// pharPath is where the executable gets installed in the user's space.
func pharPath(dataDir string) string {
	return filepath.Join(dataDir, "engines", "amwscan", "scanner.phar")
}

// reportBase is the report prefix. AMWScan appends ".log".
func reportBase(dataDir string) string {
	return filepath.Join(dataDir, "engines", "amwscan", "report")
}

var phpVersionRe = regexp.MustCompile(`PHP (\d+)\.(\d+)`)

// Probe checks the PHP CLI, that the executable is present and — what actually
// matters — that it REALLY runs in this environment.
func (a *Adapter) Probe(ctx context.Context, env adapter.Environment) adapter.ProbeResult {
	php := env.BinaryPath
	if php == "" {
		php = "php"
	}
	if env.Runner == nil {
		return adapter.Unavailable("no executor available")
	}

	res := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-probe",
		Path:   php,
		Args:   []string{"-v"},
	})
	if res.Status != schema.StatusCompleted || res.ExitCode != 0 {
		return adapter.Unavailable(fmt.Sprintf(
			"PHP CLI not found or not executable (%s): AMWScan runs on pure PHP and cannot run without it", php))
	}

	m := phpVersionRe.FindStringSubmatch(string(res.Stdout))
	if m == nil {
		return adapter.Unavailable("could not identify the PHP CLI version")
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	phpVer := fmt.Sprintf("%d.%d", major, minor)
	if major < 7 || (major == 7 && minor < 1) {
		return adapter.Unavailable(fmt.Sprintf(
			"PHP %s is older than the minimum AMWScan requires (%s)", phpVer, MinPHPVersion))
	}

	phar := pharPath(env.DataDir)
	info, err := os.Stat(phar)
	if err != nil {
		return adapter.UnavailableInstallable(fmt.Sprintf(
			"PHP %s is available, but AMWScan is not installed at %s yet", phpVer, phar))
	}

	// The check that actually matters: EXECUTE the engine.
	//
	// "PHP exists and the file is there" is not the same as "the engine runs".
	// On hosting without the mbstring extension, AMWScan dies with exit 255 and
	// ZERO output — and a probe that only looks at the version and the file
	// would mark the engine as healthy while it never produces a finding. That
	// is silent coverage degradation, this project's most dangerous failure
	// mode.
	//
	// This case was not hypothetical: it is how the validation container
	// behaved before php-mbstring was installed.
	selfTest := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-selftest",
		Path:   php,
		Args:   []string{phar, "--version"},
	})
	output := strings.TrimSpace(string(selfTest.Stdout)) + strings.TrimSpace(string(selfTest.Stderr))
	if selfTest.Status != schema.StatusCompleted || output == "" {
		return adapter.Unavailable(fmt.Sprintf(
			"AMWScan is installed but does not run on this PHP %s (exited with code %d producing no output). "+
				"The most common cause is a missing PHP extension, typically mbstring: "+
				"ask the hosting support for `php-mbstring`",
			phpVer, selfTest.ExitCode))
	}

	version := "PHP " + phpVer
	if v := extractVersion(output); v != "" {
		version = "AMWScan " + v + " (PHP " + phpVer + ")"
	}

	return adapter.ProbeResult{
		Available:           true,
		Version:             version,
		BinaryPath:          phar,
		SignaturesUpdatedAt: info.ModTime(),
	}
}

var versionRe = regexp.MustCompile(`(?i)version\s+v?(\d+\.\d+(?:\.\d+)?)`)

func extractVersion(s string) string {
	if m := versionRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Install downloads the executable into the user's space, without root.
func (a *Adapter) Install(ctx context.Context, env adapter.Environment) error {
	if env.Offline {
		return errors.New("offline mode: AMWScan cannot be downloaded")
	}
	dest := pharPath(env.DataDir)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("creating the engine directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.pharURL, nil)
	if err != nil {
		return fmt.Errorf("building the download: %w", err)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("downloading AMWScan: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the AMWScan download answered %s", resp.Status)
	}

	// Write to a temporary file and rename: an interrupted download must not
	// leave half an executable where a working one used to be.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".scanner-*.phar")
	if err != nil {
		return fmt.Errorf("creating the temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// The digest is computed as the bytes stream past, so nothing has to trust that the
	// file on disk is still the file that arrived. Verified before the rename, so a
	// rejected download never exists under the name this tool executes.
	h, sum := adapter.Hasher()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing AMWScan: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing AMWScan: %w", err)
	}
	if n < 100<<10 {
		return fmt.Errorf("the download came back with only %d bytes: that does not look like the scanner", n)
	}
	pin := Phar
	if a.pharURL != PharURL {
		// Pointed elsewhere by a test or a fork. Still verified: an override without a
		// digest fails, rather than becoming a way past the check.
		pin = adapter.Pinned{Name: "the AMWScan scanner", URL: a.pharURL}
	}
	if err := pin.Verify(sum()); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o700); err != nil {
		return fmt.Errorf("adjusting permissions: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("installing AMWScan: %w", err)
	}
	return nil
}

// UpdateSignatures reinstalls the executable: in AMWScan the definitions travel
// inside the file itself, so updating signatures means updating the engine.
func (a *Adapter) UpdateSignatures(ctx context.Context, env adapter.Environment) (time.Time, error) {
	if err := a.Install(ctx, env); err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(pharPath(env.DataDir))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Scan runs AMWScan over the path list.
//
// AMWScan writes its result to a report FILE, not to stdout — and it has no
// JSON format, only `html` and `txt`. This adapter's raw output is therefore
// the contents of that file.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	if env.Runner == nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, errors.New("no executor available")
	}
	php := env.BinaryPath
	if php == "" {
		php = "php"
	}
	phar := pharPath(env.DataDir)
	if _, err := os.Stat(phar); err != nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed},
			fmt.Errorf("AMWScan is not installed at %s: %w", phar, err)
	}

	base := reportBase(env.DataDir)
	reportFile := base + ".log"

	out := adapter.RawOutput{
		Engine: Slug, ScanID: req.ScanID, Root: req.Root, Mode: req.Mode,
		StartedAt: time.Now(), PathsRequested: len(req.Paths),
		Status: schema.StatusCompleted,
		Extra:  map[string]any{},
	}
	// Parse has to know what was actually requested so it can discard the
	// surplus: the engine always walks the whole root.
	if len(req.Paths) > 0 {
		out.Extra[targetsKey] = append([]string(nil), req.Paths...)
	}

	// Remove the previous report BEFORE running. Without this, a failed
	// execution leaves last cycle's report in place and Parse would return old
	// findings as if they were new.
	if err := os.Remove(reportFile); err != nil && !os.IsNotExist(err) {
		out.Status = schema.StatusFailed
		return out, fmt.Errorf("clearing the previous report: %w", err)
	}

	args := []string{
		"-d", "memory_limit=256M",
		phar,
		// --report: report-only mode. Without it AMWScan enters interactive mode
		// and may CLEAN or DELETE files — this project's quarantine is
		// reversible and recorded, its own is not.
		"--report",
		"--report-format", "txt",
		"--path-report", base,
		"--no-colors",
		"--silent",
	}
	if req.MaxFileSizeBytes > 0 {
		args = append(args, "--max-filesize", strconv.FormatInt(req.MaxFileSizeBytes, 10))
	}
	args = append(args, env.ExtraArgs...)
	args = append(args, req.Root)

	res := env.Runner.Run(ctx, sexec.Command{
		Engine:  Slug,
		ScanID:  req.ScanID,
		Path:    php,
		Args:    args,
		Dir:     req.Root,
		Timeout: req.Timeout,
	})
	out.RawRef = res.RawRef
	out.FinishedAt = time.Now()

	if res.Abstains() {
		out.Status = res.Status
		return out, res.Err
	}

	// The raw output is the report file. stdout stays empty because of
	// --silent, and mistaking "empty stdout" for "nothing found" would be this
	// adapter's classic bug.
	content, err := os.ReadFile(reportFile) // path derived from the data directory
	switch {
	case err == nil:
		out.Stdout = content
	case os.IsNotExist(err):
		// With no report file there is nothing to interpret. Had the engine
		// run, it would have written at least the header.
		out.Status = schema.StatusFailed
		return out, fmt.Errorf(
			"AMWScan exited with code %d but did not write the report at %s (output: %q)",
			res.ExitCode, reportFile, firstLine(res.Stderr))
	default:
		out.Status = schema.StatusFailed
		return out, fmt.Errorf("reading the AMWScan report: %w", err)
	}

	return out, nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Real format of the AMWScan 0.15.1 txt report:
//
//	Scan date: 2026-07-29 15:59:45
//	File: /path/to/file.php
//	Exploits:
//	 => [!] Signature (d30fc49e) [line 4]
//	    - Malware Signature (hash: d30fc49e)
//	      => backdoor
//
// The hierarchy matters: `File:` opens a block and everything below belongs to
// it until the next `File:`. Treating the lines in isolation would produce
// findings with no file.
var (
	fileRe    = regexp.MustCompile(`^File:\s*(.+?)\s*$`)
	sectionRe = regexp.MustCompile(`^([A-Za-z][A-Za-z ]*):\s*$`)
	findingRe = regexp.MustCompile(`^\s*=>\s*\[[!*]\]\s*(.+?)\s*(?:\(([^)]*)\))?\s*(?:\[line\s+(\d+)\])?\s*$`)
	tagRe     = regexp.MustCompile(`^\s+=>\s*(.+?)\s*$`)
	dateRe    = regexp.MustCompile(`^Scan date:\s*(.+?)\s*$`)
)

// Parse converts the AMWScan txt report into the normalized schema.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := adapter.NewScanReport(Slug, raw)

	// An empty report is far too ambiguous to read as "the site is clean":
	// AMWScan always writes at least the `Scan date:` line. Empty means it
	// never got to writing — abstention.
	text := strings.TrimSpace(string(raw.Stdout))
	if text == "" {
		return rep, errors.New("AMWScan produced no report (empty file)")
	}
	if !strings.Contains(text, "Scan date:") && !strings.Contains(text, "File:") {
		return rep, fmt.Errorf("the AMWScan report does not have the expected format (it starts with %q)",
			firstLine([]byte(text)))
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	// When Scan walked the whole root (a batch too large for one execution per
	// file), the report carries findings for files the orchestrator did NOT ask
	// about. Discarding them here is what preserves the incremental scope: the
	// orchestrator decides the list, always.
	allowed := allowedTargets(raw)

	type pending struct {
		rule  string
		extra string
		line  int64
		tag   string
	}

	var (
		currentFile string
		current     *pending
		unknown     int
	)

	emit := func() {
		if current == nil || currentFile == "" {
			current = nil
			return
		}
		defer func() { current = nil }()

		if allowed != nil && !allowed[currentFile] {
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["outside_requested_scope"]++
			return
		}

		m, known := classify(current.rule, current.tag)
		if !known {
			unknown++
		}
		st, ok := a.stat(currentFile)
		if !ok || st.SHA256 == "" {
			// With no hash there is no way to deduplicate across engines.
			// Skipping beats inventing a key: the file most likely disappeared
			// between the scan and reading the report.
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["vanished_before_hashing"]++
			return
		}

		snippet := current.rule
		if current.extra != "" {
			snippet += " (" + current.extra + ")"
		}
		if current.tag != "" {
			snippet += " => " + current.tag
		}

		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          current.rule,
			RuleRef:       "https://github.com/marcocesarato/PHP-Antimalware-Scanner",
			File: schema.FileRef{
				Path:      currentFile,
				SizeBytes: st.Size,
				SHA256:    st.SHA256,
				MTime:     st.MTime,
				Perms:     st.Perms,
			},
			Category:   m.category,
			Severity:   m.severity,
			Confidence: m.confidence,
			// The AMWScan txt report does not include the code snippet, only the
			// rule and the line. Better that way: malicious content never needs
			// to travel through the system for the user to understand a finding.
			MatchedContent: schema.SanitizeSnippet(snippet),
			MatchedOffset:  current.line,
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		if m := dateRe.FindStringSubmatch(line); m != nil {
			continue
		}
		if m := fileRe.FindStringSubmatch(line); m != nil {
			emit()
			currentFile = m[1]
			continue
		}
		if m := findingRe.FindStringSubmatch(line); m != nil {
			emit()
			p := &pending{rule: strings.TrimSpace(m[1]), extra: strings.TrimSpace(m[2])}
			if m[3] != "" {
				if n, err := strconv.ParseInt(m[3], 10, 64); err == nil {
					p.line = n
				}
			}
			current = p
			continue
		}
		// `Exploits:` / `Functions:` only separate sections.
		if sectionRe.MatchString(line) {
			continue
		}
		// The line "      => backdoor" is the category the engine assigned.
		if m := tagRe.FindStringSubmatch(line); m != nil && current != nil && current.tag == "" {
			current.tag = strings.TrimSpace(m[1])
			continue
		}
	}
	emit()

	if err := sc.Err(); err != nil {
		return rep, fmt.Errorf("reading the AMWScan report: %w", err)
	}

	if unknown > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["unknown_rule"] = unknown
	}
	return rep, nil
}

// allowedTargets returns the set of paths the orchestrator asked for, or nil
// when there is no filter to apply.
//
// nil differs from an empty set: nil means "accept everything the report
// carries" (one execution per file, or reprocessing archived raw output where
// the original list no longer exists).
func allowedTargets(raw adapter.RawOutput) map[string]bool {
	if raw.Extra == nil {
		return nil
	}
	value, ok := raw.Extra[targetsKey]
	if !ok {
		return nil
	}
	list, ok := value.([]string)
	if !ok || len(list) == 0 {
		return nil
	}
	out := make(map[string]bool, len(list))
	for _, p := range list {
		out[p] = true
	}
	return out
}

// statFile reads the hash and metadata of the flagged file.
//
// AMWScan does not report a hash. The orchestrator computes it, because the
// sha256 is the deduplication key across engines and has to be computed the
// same way for all of them — if each adapter used its own engine's hash, two
// engines flagging the same file would become two verdicts.
func statFile(path string) (FileStat, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return FileStat{}, false
	}
	f, err := os.Open(path) // path comes from the engine's report over the configured root
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
