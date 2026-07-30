// Package maldet integrates Linux Malware Detect (`maldet`), a signature scanner
// with a mature hex/MD5 rule set.
//
// It is the only MVP engine SentinelHost cannot install: maldet ships as a system
// package or an installer that wants root, and Principle III forbids depending on
// that. So the adapter probes for it and, when it is absent, abstains with a reason
// the user can act on — the consensus proceeds with the others.
//
// The part that matters most here is what the adapter REFUSES to use. maldet has its
// own quarantine and its own cleaner, and both would violate Principle I: they are
// not reversible, not recorded in our vault, and not something the user can undo from
// the panel. Every invocation therefore disables them explicitly rather than trusting
// the host's maldet configuration.
package maldet

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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
const Slug = "maldet"

// FileStat is the metadata the orchestrator computes about a flagged file.
type FileStat struct {
	SHA256 string
	Size   int64
	Perms  string
	MTime  time.Time
}

// Adapter integrates maldet.
type Adapter struct {
	// stat is injectable so the contract test can exercise the parser with fixtures
	// that cite paths from a real server.
	stat func(string) (FileStat, bool)
}

// New creates the adapter.
func New() *Adapter { return &Adapter{stat: statFile} }

// WithStat swaps the metadata function. Tests only.
func (a *Adapter) WithStat(fn func(string) (FileStat, bool)) *Adapter {
	a.stat = fn
	return a
}

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "maldet (Linux Malware Detect)",
		License:  "GPL-2.0 (invoked as an external process, never linked)",
		Homepage: "https://www.rfxn.com/projects/linux-malware-detect/",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryKnownMalware, schema.CategoryBackdoor, schema.CategoryWebshell,
			schema.CategoryObfuscation, schema.CategoryDropper, schema.CategoryInjection,
			schema.CategorySpamSEO, schema.CategoryPhishing, schema.CategoryOther,
		},
		Cost: adapter.CostHeavy,
		// maldet DOES restrict its walk to a file list, through `-f/--file-list`, and
		// measuring is what settled it, in the validation container:
		//
		//	-a  over 2,999 files   28m36s   (37m42s under nice 19)
		//	-a  over   401 files    3m24s
		//	-f  over     2 files       7s   and the report said TOTAL FILES: 2
		//
		// So it walks the list, not the root.
		//
		// That is roughly half a second of bash-and-perl per file. With ScopeAware false
		// the orchestrator hands maldet the whole root every cycle and pays that
		// half hour to re-scan
		// files nothing touched — which is not merely wasteful, it is the CPU burn that
		// gets a shared-hosting account suspended, by the tool whose Principle IV exists
		// to prevent exactly that. The first version of this adapter declared false with
		// a comment asserting maldet "has no flag that restricts the walk"; `--help`
		// documents one.
		ScopeAware:    true,
		DefaultWeight: config.WeightMaldet,
	}
}

var versionRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

// Probe checks that the maldet binary exists AND runs.
//
// It runs it, rather than only looking for the file: maldet is usually a system
// install whose data directory may be unreadable by an unprivileged account, and in
// that case the binary is present and every scan fails. A probe that only checked for
// the file would mark the engine healthy while it can never produce a finding — the
// silent coverage degradation this project treats as its worst failure mode.
func (a *Adapter) Probe(ctx context.Context, env adapter.Environment) adapter.ProbeResult {
	if env.Runner == nil {
		return adapter.Unavailable("no executor available")
	}
	bin := env.BinaryPath
	if bin == "" {
		bin = "maldet"
	}

	res := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-probe",
		Path:   bin,
		Args:   []string{"--version"},
	})
	output := strings.TrimSpace(string(res.Stdout)) + strings.TrimSpace(string(res.Stderr))

	// The gate that matters most on the environment this project targets.
	//
	// maldet ships with `scan_user_access="0"`, and with that default an unprivileged
	// account gets the version banner plus a refusal — from EVERY subcommand,
	// `--version` included, at exit 0. So "the binary runs" is true and useless here:
	// without this check the engine is reported healthy, with its version read off the
	// banner, on a host where it can never produce a single finding. That is the
	// mbstring mistake again (DECISIONS.md D-011), and only installing the real maldet
	// exposed it.
	if reason := accessGateReason(output); reason != "" {
		return adapter.Unavailable(reason +
			". Until then this engine abstains and the consensus proceeds with the others")
	}

	if res.Status != schema.StatusCompleted || output == "" {
		// maldet cannot be installed without root, so this is not an installable
		// unavailability: the reason has to tell the user what to ask for.
		return adapter.Unavailable(
			"the `maldet` binary was not found or does not run. maldet installs as a system package " +
				"and cannot be installed into a user account, so ask the hosting support for " +
				"`maldet`; without it this engine abstains and the consensus proceeds with the others")
	}

	version := "unknown"
	if m := versionRe.FindStringSubmatch(output); m != nil {
		version = m[1]
	}
	return adapter.ProbeResult{
		Available:  true,
		Version:    "maldet " + version,
		BinaryPath: bin,
	}
}

// Install does not apply: maldet needs root, which Principle III forbids relying on.
func (a *Adapter) Install(context.Context, adapter.Environment) error {
	return fmt.Errorf("%w: maldet installs as a system package and needs root; ask the hosting support for it",
		adapter.ErrNotInstallable)
}

// UpdateSignatures asks maldet to refresh its own rule set.
//
// It commonly fails without root, and that is not an error worth failing a cycle
// over: the scan still runs with whatever signatures the host has. The caller records
// the reason.
func (a *Adapter) UpdateSignatures(ctx context.Context, env adapter.Environment) (time.Time, error) {
	if env.Runner == nil {
		return time.Time{}, errors.New("no executor available")
	}
	if env.Offline {
		return time.Time{}, errors.New("offline mode: maldet's signatures will not be updated")
	}
	bin := env.BinaryPath
	if bin == "" {
		bin = "maldet"
	}

	res := env.Runner.Run(ctx, sexec.Command{
		Engine: Slug + "-update",
		Path:   bin,
		Args:   []string{"--update"},
	})
	if res.Status != schema.StatusCompleted || res.ExitCode != 0 {
		return time.Time{}, fmt.Errorf(
			"maldet could not update its signatures (exit %d): this usually needs root. "+
				"The scan still runs with the signatures the host already has: %s",
			res.ExitCode, firstLine(res.Stderr))
	}
	return time.Now(), nil
}

// scanIDRe pulls the scan id out of maldet's own output, because the report is a
// separate invocation that needs it.
//
// The two spellings are not redundant. A finished SCAN announces itself as
//
//	maldet(91): {scan} scan report saved, to view run: maldet --report 260730-0913.91
//
// and never prints the words "SCAN ID" at all — that line belongs to the REPORT, which
// is the thing we cannot fetch until we have the id. This regex started out matching
// only `SCAN ID:`, which meant the adapter found no id after every successful scan and
// abstained on every cycle: an engine reported as installed, contributing nothing.
// A real 1.6.6 run is what showed it; no reading of the documentation would have.
//
// The id shape (`YYMMDD-HHMM.PID`) is anchored rather than "any token after --report",
// so a changed sentence around it does not turn into a garbage id being requested.
var scanIDRe = regexp.MustCompile(
	`(?i)(?:SCAN ID:?\s*|--report\s+)([0-9]{6}-[0-9]{4}\.[0-9]+)`)

// The two ways maldet refuses to serve an unprivileged account.
//
// Both matter far more than an ordinary error string, because both are the difference
// between "this host has no maldet" and "this host has maldet and the administrator
// has one thing to do". Only the second is something a user can act on, and the two
// remedies are different — which is why they are two patterns and two messages
// rather than one vague "maldet would not run".
//
// Every subcommand hits these gates, `--version` included, and maldet exits 0 while
// printing them. So the version banner is there to be parsed and the engine looks
// perfectly healthy. That is how the first version of this adapter reported maldet
// available on a host where it could not scan a single file.
var (
	// scan_user_access="0" is maldet's shipped default. `scan_user_access=0` also
	// appears alone in the refusal's parenthetical, and `internals/functions` words
	// the same refusal differently from the CLI wrapper.
	userAccessDisabledRe = regexp.MustCompile(
		`(?i)(public scanning is currently disabled|public scanning support not enabled|scan_user_access=0)`)

	// The second gate, and the one nothing in the documentation prepares you for:
	// with access enabled, maldet still refuses until root has created the per-user
	// public paths, either through `maldet --mkpubpaths` or by waiting for cron.pub.
	// A fresh install therefore refuses TWICE for two different reasons.
	pubPathsMissingRe = regexp.MustCompile(`(?i)(paths do not exist|mkpubpaths)`)
)

// accessGateReason explains a refusal by maldet's public-scanning gate, or returns
// "" when the output is not a refusal.
//
// The remedy is part of the message on purpose. A user who cannot install maldet also
// cannot fix its configuration: the only useful thing this project can hand them is
// the exact line to forward to their hosting support.
func accessGateReason(output string) string {
	switch {
	case userAccessDisabledRe.MatchString(output):
		return "maldet is installed but refuses to run for a non-root account: its " +
			"`scan_user_access` is 0, which is the default. Ask the hosting support to set " +
			"`scan_user_access=\"1\"` in /usr/local/maldetect/conf.maldet"
	case pubPathsMissingRe.MatchString(output):
		return "maldet allows non-root scanning but its per-user paths do not exist yet. " +
			"Ask the hosting support to run `maldet --mkpubpaths` as root, or wait for " +
			"maldet's own cron.pub to create them"
	default:
		return ""
	}
}

// Scan runs maldet and then fetches its report.
//
// Two invocations, because that is how maldet works: `-a` scans and prints a scan id,
// and `--report <id>` prints the report. The raw output of this adapter is the
// REPORT, since that is what Parse reads.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	if env.Runner == nil {
		return adapter.RawOutput{Engine: Slug, Status: schema.StatusFailed}, errors.New("no executor available")
	}
	bin := env.BinaryPath
	if bin == "" {
		bin = "maldet"
	}

	out := adapter.RawOutput{
		Engine: Slug, ScanID: req.ScanID, Root: req.Root, Mode: req.Mode,
		StartedAt: time.Now(), PathsRequested: len(req.Paths),
		Status: schema.StatusCompleted,
	}

	// The flags that keep Principle I intact.
	//
	// maldet's own quarantine and cleaner are not reversible, are not recorded in our
	// vault and cannot be undone from the panel. Passing these on every invocation
	// means we never depend on how the host configured maldet: a server with
	// `quarantine_hits=1` in conf.maldet would otherwise move the user's files
	// somewhere we cannot restore from.
	//
	// ONE flag with comma-separated values, which is the syntax maldet documents:
	//
	//	-co, --config-option VAR1=VALUE,VAR2=VALUE,VAR3=VALUE
	//
	// This started out as three repeated `--config-option` flags — an assumption that
	// looked reasonable and was never checked. Running the real 1.6.6 showed the
	// documented form, and repeated flags risk the last one winning: the two that
	// disable the quarantine would have been dropped silently, and maldet would have
	// moved the user's files into its own vault. The exact shape of D-018.
	args := []string{
		"--config-option",
		"quarantine_hits=0,quarantine_clean=0,quarantine_suspend_user=0",
	}
	args = append(args, env.ExtraArgs...)

	// `-f <list>` when the orchestrator named a scope, `-a <root>` when it did not.
	//
	// The measured difference is the whole argument: 401 files through `-a` took 204s;
	// two files through `-f` took 7s and the report said `TOTAL FILES: 2`. On an
	// incremental cycle where 200 of 3,000 files changed, that is ~100s instead of
	// 28m36s, every cycle, forever.
	//
	// An empty path list is NOT the same as "scan everything". It means the walker found
	// nothing changed, and handing maldet the root there would spend 28m36s of a
	// shared host's CPU to confirm it.
	//
	// cleanup starts as a no-op because only the `-f` branch below creates a file to
	// remove; the other two branches leave nothing behind, and a single deferred call
	// keeps the removal in one place rather than on every return path.
	cleanup := func() { /* nothing was written yet */ }
	switch {
	case len(req.Paths) > 0:
		listFile, done, err := adapter.WriteTargetList(env.DataDir, Slug, req.Paths)
		if err != nil {
			out.Status = schema.StatusFailed
			out.FinishedAt = time.Now()
			return out, err
		}
		cleanup = done
		args = append(args, "-f", listFile)
	case req.Mode == schema.ModeFull:
		args = append(args, "-a", req.Root)
	default:
		// Abstain rather than invent a scope. This is reported and counted like any
		// other abstention, which is the point: a caller that asked for an incremental
		// scan and named no files gets told so, instead of quietly triggering a
		// 25-minute full walk or quietly returning "nothing found".
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, errors.New(
			"an incremental scan was requested with no target paths: there is nothing for maldet " +
				"to scan, and scanning the whole root instead would cost 28m36s of CPU nobody asked for")
	}
	defer cleanup()

	scan := env.Runner.Run(ctx, sexec.Command{
		Engine:  Slug,
		ScanID:  req.ScanID,
		Path:    bin,
		Args:    args,
		Dir:     req.Root,
		Timeout: req.Timeout,
	})
	out.RawRef = scan.RawRef

	if scan.Abstains() {
		out.Status = scan.Status
		out.FinishedAt = time.Now()
		return out, scan.Err
	}

	// The scan id is how the report is fetched. Without it there is nothing to read,
	// and guessing would mean reporting on someone else's scan.
	combined := string(scan.Stdout) + string(scan.Stderr)

	// Named before the generic no-scan-id case, because the two are indistinguishable
	// from the outside and only one of them is fixable. A cycle log that says "printed
	// no scan id" sends a sysadmin looking for a parsing bug; one that names
	// `scan_user_access` tells them the single line to change. Probe already blocks
	// this, but Scan cannot rely on that: the host setting can change between the probe
	// and the scan, and this adapter has to stay honest on its own.
	if reason := accessGateReason(combined); reason != "" {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, errors.New(reason)
	}

	m := scanIDRe.FindStringSubmatch(combined)
	if m == nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf(
			"maldet finished with code %d but printed no scan id, so its report cannot be fetched (output: %q)",
			scan.ExitCode, firstLine([]byte(combined)))
	}
	scanID := m[1]

	// `--report <id>` alone does NOT print the report: maldet passes the session file
	// to $EDITOR. On a server with no EDITOR it prints `vi: command not found` and
	// nothing else; on one that has vi it would block forever waiting for input,
	// hanging the cycle until the timeout killed it.
	//
	// The second argument `dump` is what prints to stdout. It is absent from
	// `--help`, and only reading maldet's own internals/functions shows it:
	//
	//	if [ "$2" == "dump" ]; then
	//	    cat $sessdir/session.$rid
	//
	// Without it this adapter would abstain on every single cycle.
	report := env.Runner.Run(ctx, sexec.Command{
		Engine:  Slug + "-report",
		ScanID:  req.ScanID,
		Path:    bin,
		Args:    []string{"--report", scanID, "dump"},
		Dir:     req.Root,
		Timeout: req.Timeout,
	})
	out.FinishedAt = time.Now()
	if report.RawRef != "" {
		out.RawRef = report.RawRef
	}

	if report.Abstains() {
		out.Status = report.Status
		return out, report.Err
	}
	// A scan whose report could not be read is useless: we know it looked at
	// something and nothing about what it found.
	if len(strings.TrimSpace(string(report.Stdout))) == 0 {
		out.Status = schema.StatusFailed
		return out, fmt.Errorf(
			"maldet scan %s completed but its report came back empty, so there is nothing to interpret", scanID)
	}

	out.Stdout = report.Stdout
	out.Stderr = report.Stderr
	out.ExitCode = report.ExitCode
	return out, nil
}

// The report's real format (Linux Malware Detect 1.6.5):
//
//	malware detect scan report for user:
//	SCAN ID: 260723-0300.12345
//	TOTAL FILES: 412
//	TOTAL HITS: 3
//	TOTAL CLEANED: 0
//
//	FILE HIT LIST:
//	{HEX}php.corpus.marker.v1 : /home/user/public_html/x.php
//	{YARA}php_backdoor_generic : /home/user/public_html/init.php
//
// See tests/testdata/raw/maldet/PROVENANCE.md.
var (
	// The signature type can contain digits: `{MD5}` is one of maldet's two
	// exact-match types. An `[A-Za-z]+` class here silently skipped every {MD5} line,
	// and only the real fixture exposed it — the parser looked correct and would have
	// dropped a third of the hits in production.
	hitRe        = regexp.MustCompile(`^\{([A-Za-z0-9]+)\}([^\s:]+)\s*:\s*(.+?)\s*$`)
	totalHitsRe  = regexp.MustCompile(`(?i)^TOTAL HITS:\s*(\d+)`)
	totalFilesRe = regexp.MustCompile(`(?i)^TOTAL FILES:\s*(\d+)`)
	cleanedRe    = regexp.MustCompile(`(?i)^TOTAL CLEANED:\s*(\d+)`)
)

// Parse converts maldet's report into the normalized schema.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := adapter.NewScanReport(Slug, raw)

	text := strings.TrimSpace(string(raw.Stdout))
	if text == "" {
		// maldet always writes at least its header. Empty means it never got to
		// writing — an abstention, never "found nothing".
		return rep, errors.New("maldet produced no report (empty output)")
	}
	// The real 1.6.6 report opens with maldet's banner and then HOST/SCAN ID/…, with
	// no "malware detect scan report" line anywhere. An earlier version of this check
	// looked for that line and would have rejected every genuine report as
	// off-format — the adapter would have abstained forever while looking correct.
	if !looksLikeMaldetReport(text) {
		return rep, fmt.Errorf("the maldet report does not have the expected format (it starts with %q)",
			firstLine([]byte(text)))
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	totals, err := a.scanReportLines(text, raw, detectedAt, &rep)
	if err != nil {
		return rep, err
	}
	if totals.files > 0 {
		rep.Scope.FilesConsidered = totals.files
		rep.Scope.FilesScanned = totals.files
	}

	// `TOTAL HITS` has to match what the list actually contained. A divergence means
	// a truncated report, and a truncated report accepted as good is exactly how an
	// engine that saw 5 things gets recorded as having seen 1 (PROVENANCE.md).
	//
	// The count is against findings + skipped, because a file that vanished before we
	// could hash it was still a hit maldet reported.
	skipped := rep.Scope.SkippedReasonCounts["vanished_before_hashing"]
	if totals.declaredHits >= 0 && totals.declaredHits != len(rep.Findings)+skipped {
		return rep, fmt.Errorf(
			"the maldet report is truncated: it declares TOTAL HITS: %d but lists %d hit(s). "+
				"Accepting it would record an engine that found %d things as having found %d",
			totals.declaredHits, len(rep.Findings)+skipped, totals.declaredHits, len(rep.Findings)+skipped)
	}

	// maldet touching a file itself is a Principle I violation that already happened.
	// The adapter disables its quarantine and cleaner on every invocation, so either
	// signal means the host overrode us — and the user has to be told, loudly, that a
	// file was altered by something they cannot undo from the panel.
	//
	// Returning the findings instead would look more useful and read as a normal
	// cycle. It is the wrong trade: someone has to learn their files were moved
	// before they read a verdict list.
	if totals.cleaned > 0 || totals.maldetQuarantined > 0 {
		return rep, fmt.Errorf(
			"maldet acted on the files itself, outside the reversible vault: TOTAL CLEANED: %d, "+
				"%d hit(s) moved into maldet's own quarantine. This adapter disables both on every "+
				"invocation, so the host's maldet configuration is overriding that. Do not trust this "+
				"cycle's report: the originals are in maldet's quarantine, not in ours",
			totals.cleaned, totals.maldetQuarantined)
	}

	if totals.unknownFamilies > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["unknown_signature_family"] = totals.unknownFamilies
	}
	return rep, nil
}

// looksLikeMaldetReport recognizes the real report's shape.
//
// The genuine 1.6.6 report opens with maldet's banner, then `HOST:`, `SCAN ID:`,
// `PATH:`, `TOTAL FILES:` and `TOTAL HITS:`. Two of those markers together are enough
// to tell it apart from an error message or a truncated pipe, and requiring two keeps
// a stray `PATH:` in unrelated output from passing.
func looksLikeMaldetReport(text string) bool {
	markers := []string{"SCAN ID:", "TOTAL HITS:", "TOTAL FILES:", "Linux Malware Detect", "FILE HIT LIST:"}
	seen := 0
	for _, m := range markers {
		if strings.Contains(text, m) {
			seen++
		}
	}
	return seen >= 2
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

// statFile reads the hash and metadata of the flagged file.
//
// maldet reports no hash. The orchestrator computes the sha256, because it is the
// deduplication key across engines and has to be computed the same way for all of
// them — if each adapter used its own engine's hash, two engines flagging the same
// file would become two verdicts.
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

// reportTotals are the numbers the report declares about itself, as opposed to what the
// hit list actually contains. Keeping the two apart is the point: comparing them is what
// catches a truncated report, and a truncated report accepted as good is how an engine
// that found five things gets recorded as having found one.
type reportTotals struct {
	declaredHits      int
	files             int
	cleaned           int
	unknownFamilies   int
	maldetQuarantined int
}

// scanReportLines walks the report once, appending findings to rep, and returns what the
// report claimed about itself.
//
// It is split out of Parse so each half can be read alone: this one knows maldet's line
// formats, and Parse knows what to do when those numbers disagree with the hit list.
func (a *Adapter) scanReportLines(
	text string,
	raw adapter.RawOutput,
	detectedAt time.Time,
	rep *schema.ScanReport,
) (reportTotals, error) {
	totals := reportTotals{declaredHits: -1, files: -1}
	var inHitList bool

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if m := totalHitsRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totals.declaredHits = n
			}
			continue
		}
		if m := totalFilesRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totals.files = n
			}
			continue
		}
		if m := cleanedRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				totals.cleaned = n
			}
			continue
		}
		if strings.HasPrefix(strings.ToUpper(line), "FILE HIT LIST") {
			inHitList = true
			continue
		}
		if strings.HasPrefix(line, "=====") {
			inHitList = false
			continue
		}

		// Only inside the hit list. maldet's own parser does the same
		// (`awk '/FILE HIT LIST:/{flag=1;next}/^=======/{flag=0}flag'`), and the real
		// 1.6.6 report puts a WARNING block above the list whenever the quarantine is
		// off — which, since this adapter disables it every invocation, is every report
		// this code will ever see. Matching hit-shaped lines outside the list is how text
		// that merely mentions a signature becomes a finding against a file.
		if !inHitList {
			continue
		}
		m := hitRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		sigType, signature, path := m[1], m[2], m[3]

		// A hit maldet quarantined itself reads `{TYPE}sig : /original => /vault/copy`
		// (its internals check `[[ "$hit_line" == *"=>"* ]]`). Two things follow, and
		// both matter: the path we want is the ORIGINAL, before the arrow; and the
		// arrow's presence is proof maldet moved a file despite this adapter disabling
		// its quarantine on every invocation.
		if orig, _, found := strings.Cut(path, "=>"); found {
			path = strings.TrimSpace(orig)
			totals.maldetQuarantined++
		}

		cls, known := classify(signature)
		if !known {
			totals.unknownFamilies++
		}

		st, ok := a.stat(path)
		if !ok || st.SHA256 == "" {
			// With no hash there is no deduplication key across engines. Skipping beats
			// inventing one: the file most likely vanished between the scan and the
			// report, which for maldet is two separate invocations.
			if rep.Scope.SkippedReasonCounts == nil {
				rep.Scope.SkippedReasonCounts = map[string]int{}
			}
			rep.Scope.SkippedReasonCounts["vanished_before_hashing"]++
			continue
		}

		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          signature,
			RuleRef:       "https://www.rfxn.com/projects/linux-malware-detect/",
			File: schema.FileRef{
				Path:      path,
				SizeBytes: st.Size,
				SHA256:    st.SHA256,
				MTime:     st.MTime,
				Perms:     st.Perms,
			},
			Category:   cls.category,
			Severity:   cls.severity,
			Confidence: confidenceForType(sigType),
			// maldet reports no snippet, only the signature that matched. Better that
			// way: malicious content never needs to travel through the system for the
			// user to understand a finding.
			MatchedContent: schema.SanitizeSnippet("{" + sigType + "}" + signature),
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}
	if err := sc.Err(); err != nil {
		return totals, fmt.Errorf("reading the maldet report: %w", err)
	}
	return totals, nil
}
