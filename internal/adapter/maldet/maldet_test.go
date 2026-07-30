package maldet_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/maldet"
	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Everything here runs against the report format recorded in
// tests/testdata/raw/maldet/PROVENANCE.md, from a real Linux Malware Detect 1.6.6 run — not
// against a format I imagined. That is D-022's rule.

const fakeSHA = "2222222222222222222222222222222222222222222222222222222222222222"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "testdata", "raw", "maldet", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return b
}

func fakeStat(string) (maldet.FileStat, bool) {
	return maldet.FileStat{
		SHA256: fakeSHA, Size: 2048, Perms: "0644", MTime: time.Unix(1785000000, 0),
	}, true
}

func raw(stdout []byte, status schema.ScanStatus) adapter.RawOutput {
	return adapter.RawOutput{
		Engine: maldet.Slug, ScanID: "s_test", Root: "/home/user/public_html",
		Mode: schema.ModeIncremental, Stdout: stdout, Status: status,
		StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(),
		PathsRequested: 412,
	}
}

func TestParsesTheRealReportFormat(t *testing.T) {
	a := maldet.New().WithStat(fakeStat)

	rep, err := a.Parse(raw(fixture(t, "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("the report does not satisfy the schema: %v", err)
	}
	if rep.Abstains() {
		t.Fatalf("a success report should not abstain: %q", rep.Status)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(rep.Findings))
	}

	byRule := map[string]schema.Finding{}
	for _, f := range rep.Findings {
		byRule[f.Rule] = f
		if f.File.SHA256 != fakeSHA {
			t.Errorf("%s: the orchestrator should have computed the sha256", f.Rule)
		}
	}

	// The paths have to come from the report, not from anywhere else.
	if got := byRule["php.corpus.marker.v1"].File.Path; got != "/home/user/public_html/wp-content/uploads/2026/07/x.php" {
		t.Errorf("wrong path: %q", got)
	}
	// TOTAL FILES from the report beats the orchestrator's requested count: maldet
	// walks the whole root, so it is the honest number for what was looked at.
	if rep.Scope.FilesScanned != 412 {
		t.Errorf("files scanned: %d, expected the report's TOTAL FILES (412)", rep.Scope.FilesScanned)
	}
}

// TestTheSignatureTypeDecidesTheConfidence is the distinction that must not be lost.
func TestTheSignatureTypeDecidesTheConfidence(t *testing.T) {
	a := maldet.New().WithStat(fakeStat)
	rep, err := a.Parse(raw(fixture(t, "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]schema.Confidence{
		"php.corpus.marker.v1": schema.ConfidenceSignature, // {HEX}
		"php_backdoor_generic": schema.ConfidenceHeuristic, // {YARA}
		"php.corpus.core.v1":   schema.ConfidenceSignature, // {MD5}
	}
	for _, f := range rep.Findings {
		if w, ok := want[f.Rule]; ok && f.Confidence != w {
			t.Errorf("%s: confidence %q, expected %q", f.Rule, f.Confidence, w)
		}
	}

	// Why it matters: maldet weighs 1.0. Treating a {YARA} pattern as proof would put
	// a single heuristic engine one vote away from `confirmed`, which authorizes
	// touching the user's files.
	for _, f := range rep.Findings {
		if f.Rule == "php_backdoor_generic" && f.Confidence == schema.ConfidenceSignature {
			t.Error("a {YARA} pattern was recorded as an exact signature")
		}
	}
}

func TestAnUnknownSignatureTypeGetsTheWeakestConfidence(t *testing.T) {
	// A new prefix must not gain the weight of proof just by being unrecognized.
	a := maldet.New().WithStat(fakeStat)
	input := []byte("SCAN ID:   260730-0835.3276\nTOTAL FILES:   1\nTOTAL HITS:1\n\nFILE HIT LIST:\n{NEWTYPE}some.sig : /site/x.php\n")

	rep, err := a.Parse(raw(input, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.Findings))
	}
	if rep.Findings[0].Confidence != schema.ConfidenceAnomaly {
		t.Errorf("confidence: %q, expected anomaly", rep.Findings[0].Confidence)
	}
}

func TestNoFindingsIsNotAnAbstention(t *testing.T) {
	// maldet always writes its header. TOTAL HITS: 0 means a clean site, not a
	// failure — confusing the two turns a working engine into a fake alarm, and the
	// reverse turns a dead one into a certificate of health.
	a := maldet.New().WithStat(fakeStat)

	rep, err := a.Parse(raw(fixture(t, "success-no-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Abstains() {
		t.Fatal("zero hits must not become an abstention")
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(rep.Findings))
	}
}

// TestATruncatedReportBecomesAnAbstention is the check PROVENANCE.md demands.
func TestATruncatedReportBecomesAnAbstention(t *testing.T) {
	// The fixture declares TOTAL HITS: 5 and lists 1. Accepting it would record an
	// engine that found five things as having found one — a silent loss of four
	// findings, which is the failure mode this project exists to prevent.
	a := maldet.New().WithStat(fakeStat)

	_, err := a.Parse(raw(fixture(t, "corrupted-output.txt"), schema.StatusCompleted))
	if err == nil {
		t.Fatal("a truncated report should have been refused")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("the reason should say the report was truncated, got: %v", err)
	}
}

func TestAnEmptyReportBecomesAnAbstention(t *testing.T) {
	a := maldet.New().WithStat(fakeStat)
	if _, err := a.Parse(raw(fixture(t, "empty-output.txt"), schema.StatusCompleted)); err == nil {
		t.Fatal("an empty report should have been refused by the parser")
	}
}

func TestAnOffFormatReportBecomesAnAbstention(t *testing.T) {
	a := maldet.New().WithStat(fakeStat)
	input := []byte("this is not a maldet report\njust garbage\n")
	if _, err := a.Parse(raw(input, schema.StatusCompleted)); err == nil {
		t.Fatal("an off-format report should have been refused")
	}
}

// TestMaldetCleaningAFileIsReportedLoudly guards Principle I.
func TestMaldetQuarantiningAFileIsReportedLoudly(t *testing.T) {
	// The `=>` in a hit line is how maldet records that it moved the file into its own
	// quarantine (its internals test for exactly that). The adapter disables that on
	// every invocation, so seeing it means the host overrode us and a file now lives
	// somewhere the panel cannot restore from.
	a := maldet.New().WithStat(fakeStat)

	_, err := a.Parse(raw(fixture(t, "maldet-quarantined.txt"), schema.StatusCompleted))
	if err == nil {
		t.Fatal("a hit maldet quarantined itself should not be reported as a normal finding")
	}
	if !strings.Contains(err.Error(), "outside the reversible vault") {
		t.Errorf("the reason should name the Principle I problem, got: %v", err)
	}
}

func TestMaldetCleaningAFileIsReportedLoudly(t *testing.T) {
	// The adapter disables maldet's cleaner on every invocation, so TOTAL CLEANED > 0
	// means the host's configuration overrode us and a file was modified outside the
	// reversible vault. Reporting zero findings from such a cycle would hide that the
	// user's files were altered by something they cannot undo from the panel.
	a := maldet.New().WithStat(fakeStat)
	input := []byte("SCAN ID:   260730-0835.3276\nTOTAL FILES:   1\nTOTAL HITS:0\nTOTAL CLEANED: 2\n")

	_, err := a.Parse(raw(input, schema.StatusCompleted))
	if err == nil {
		t.Fatal("a report saying maldet cleaned files should not be accepted quietly")
	}
	if !strings.Contains(err.Error(), "outside the reversible vault") {
		t.Errorf("the reason should name the Principle I problem, got: %v", err)
	}
}

func TestAnUnknownFamilyIsNotDiscarded(t *testing.T) {
	// Obligation 4 of the contract: the table covers the families seen in practice,
	// and discarding the rest would make findings vanish on every signature update.
	a := maldet.New().WithStat(fakeStat)
	input := []byte("SCAN ID:   260730-0835.3276\nTOTAL FILES:   1\nTOTAL HITS:1\n\nFILE HIT LIST:\n{HEX}php.brandnewfamily.v1 : /site/x.php\n")

	rep, err := a.Parse(raw(input, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("the unknown-family finding was discarded")
	}
	if rep.Findings[0].Category != schema.CategoryOther {
		t.Errorf("category: %q, expected other", rep.Findings[0].Category)
	}
	if rep.Scope.SkippedReasonCounts["unknown_signature_family"] == 0 {
		t.Errorf("the unknown family should be counted: %v", rep.Scope.SkippedReasonCounts)
	}
}

func TestAVanishedFileIsCountedAndDoesNotBreakTheHitTotal(t *testing.T) {
	// maldet scans and reports in two separate invocations, so a file really can
	// disappear in between. It must be counted — and it must still satisfy the
	// TOTAL HITS check, or an honest disappearance would look like a truncated report.
	a := maldet.New().WithStat(func(string) (maldet.FileStat, bool) {
		return maldet.FileStat{}, false
	})

	rep, err := a.Parse(raw(fixture(t, "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("a vanished file should not look like a truncated report: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("a finding with no hash should not enter: %+v", rep.Findings)
	}
	if rep.Scope.SkippedReasonCounts["vanished_before_hashing"] != 3 {
		t.Errorf("the vanished files should be counted: %v", rep.Scope.SkippedReasonCounts)
	}
}

func TestTheCategoryComesFromTheSignatureFamily(t *testing.T) {
	a := maldet.New().WithStat(fakeStat)
	cases := map[string]schema.Category{
		"php.cmdshell.unclassed.359": schema.CategoryWebshell,
		"php.base64.v23eb":           schema.CategoryObfuscation,
		"php.mailer.spam.11":         schema.CategorySpamSEO,
		"php.phishing.paypal.2":      schema.CategoryPhishing,
	}
	for signature, want := range cases {
		input := []byte("SCAN ID:   260730-0835.3276\nTOTAL FILES:   1\nTOTAL HITS:1\n\nFILE HIT LIST:\n{HEX}" +
			signature + " : /site/x.php\n")
		rep, err := a.Parse(raw(input, schema.StatusCompleted))
		if err != nil {
			t.Errorf("%s: %v", signature, err)
			continue
		}
		if len(rep.Findings) != 1 {
			t.Errorf("%s: expected 1 finding", signature)
			continue
		}
		if got := rep.Findings[0].Category; got != want {
			t.Errorf("%s: category %q, expected %q", signature, got, want)
		}
	}
}

func TestTheSnippetCarriesTheSignatureAndNoContent(t *testing.T) {
	// maldet reports no snippet, and that is a feature: malicious content never has
	// to travel through the system for the user to understand a finding.
	a := maldet.New().WithStat(fakeStat)
	rep, err := a.Parse(raw(fixture(t, "success-with-findings.txt"), schema.StatusCompleted))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, f := range rep.Findings {
		if !strings.Contains(f.MatchedContent, f.Rule) {
			t.Errorf("%s: the snippet should name the signature, got %q", f.Rule, f.MatchedContent)
		}
	}
}

// Info and Install ---------------------------------------------------------------

// maldet costs roughly half a second per file — measured, not estimated: `-a` over 401
// files took 204s in the validation container. On a 3,000-file WordPress that is ~25
// minutes of CPU, and an adapter that is not ScopeAware pays it EVERY cycle to re-read
// files nothing touched. That is not waste, it is the CPU burn that gets a shared-hosting
// account suspended — caused by the tool whose Principle IV exists to prevent it.
//
// `-f/--file-list` is what avoids it: a 2-line list took 7s and the report said
// `TOTAL FILES: 2`, so maldet walks the list and not the root. The first version of this
// adapter set ScopeAware false with a comment asserting no such flag existed. `--help`
// documents one.
func TestTheAdapterRestrictsItsWalkToTheRequestedScope(t *testing.T) {
	if !maldet.New().Info().ScopeAware {
		t.Error("maldet honours -f/--file-list, so ScopeAware must be true; " +
			"with false, every incremental cycle re-scans the whole root")
	}
}

// The proof that the scope is actually passed through, rather than declared and then
// ignored — which is the exact shape of AMWScan's `--filter-paths` defect (D-018): a
// flag accepted, the walk unchanged, and the orchestrator none the wiser.
func TestTheRequestedPathsReachMaldetAsAFileListAndNotAsTheRoot(t *testing.T) {
	// The stub records its own argv, so what is asserted is the command line the
	// adapter really built.
	argvFile := filepath.Join(t.TempDir(), "argv")
	// The report call is answered and returned from BEFORE the argv is recorded. The
	// adapter invokes maldet twice, and recording both left the file holding
	// `--report <id> dump` — the second call — so the assertion below was reading the
	// wrong command line entirely.
	bin := stubEngine(t, `
if [ "$1" = "--report" ]; then printf 'REPORT\n'; exit 0; fi
printf '%s\n' "$@" > `+argvFile+`
printf 'maldet(1): {scan} scan report saved, to view run: maldet --report 260730-0927.16\n'
exit 0
`)
	root := t.TempDir()
	dataDir := t.TempDir()
	want := []string{filepath.Join(root, "a.php"), filepath.Join(root, "sub", "b.php")}

	_, err := maldet.New().Scan(context.Background(),
		adapter.Environment{
			Runner:     sexec.New(sexec.Limits{Timeout: 20 * time.Second}, ""),
			BinaryPath: bin,
			DataDir:    dataDir,
		},
		adapter.ScanRequest{ScanID: "s_test", Root: root, Paths: want, Mode: schema.ModeIncremental})
	if err != nil {
		t.Fatalf("scanning with a scope: %v", err)
	}

	argv, readErr := os.ReadFile(argvFile)
	if readErr != nil {
		t.Fatalf("the stub recorded no argv: %v", readErr)
	}
	args := strings.Fields(string(argv))

	// `-a <root>` would mean the whole root is walked no matter what was requested.
	for i, a := range args {
		if a == "-a" || a == "--scan-all" {
			t.Fatalf("the adapter asked maldet to walk the whole root (%q at %d) despite being "+
				"handed %d specific paths", a, i, len(want))
		}
	}

	var listPath string
	for i, a := range args {
		if (a == "-f" || a == "--file-list") && i+1 < len(args) {
			listPath = args[i+1]
		}
	}
	if listPath == "" {
		t.Fatal("no -f/--file-list in the command line, so the scope was never communicated")
	}

	// The list is deleted after the scan, by design: it names every path about to be
	// scanned, which on a compromised site is a map of the interesting files. So it is
	// read back from where the adapter put it, under DataDir and not the system temp.
	if !strings.HasPrefix(listPath, dataDir) {
		t.Errorf("the target list was written to %q, outside the account's own DataDir %q",
			listPath, dataDir)
	}
}

// A trailing newline is not cosmetic here. maldet reads the list with a bash
// `while read`, which drops a final line that has no newline — so the last file of every
// scan would go unexamined while the report still said it scanned them all.
func TestTheTargetListEndsWithANewlineSoTheLastPathIsNotDropped(t *testing.T) {
	captured := filepath.Join(t.TempDir(), "list-copy")
	bin := stubEngine(t, `
for a in "$@"; do
  if [ -f "$a" ] && [ "${a##*.}" = "txt" ]; then cp "$a" `+captured+`; fi
done
printf 'maldet(1): {scan} scan report saved, to view run: maldet --report 260730-0927.16\n'
exit 0
`)
	root := t.TempDir()
	last := filepath.Join(root, "the-last-one.php")
	if _, err := maldet.New().Scan(context.Background(),
		adapter.Environment{
			Runner:     sexec.New(sexec.Limits{Timeout: 20 * time.Second}, ""),
			BinaryPath: bin,
			DataDir:    t.TempDir(),
		},
		adapter.ScanRequest{
			ScanID: "s_test", Root: root, Mode: schema.ModeIncremental,
			Paths: []string{filepath.Join(root, "first.php"), last},
		}); err != nil {
		t.Fatalf("scanning: %v", err)
	}

	body, err := os.ReadFile(captured)
	if err != nil {
		t.Fatalf("the stub never received a target list: %v", err)
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Errorf("the list does not end in a newline, so maldet's `while read` drops %q:\n%q",
			last, string(body))
	}
	if !strings.Contains(string(body), last) {
		t.Errorf("the last path is missing from the list:\n%q", string(body))
	}
}

func TestInstallSaysItCannotAndWhy(t *testing.T) {
	// maldet needs root. Reporting a generic failure would leave the user guessing;
	// naming the reason tells them what to ask the hosting for.
	err := maldet.New().Install(t.Context(), adapter.Environment{})
	if err == nil {
		t.Fatal("Install should refuse: maldet cannot be installed without root")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("the reason should mention root, got: %v", err)
	}
}

// --- The access gate that only the real engine revealed ----------------------
//
// maldet ships with `scan_user_access="0"`. With that default an unprivileged
// account — the only kind this project runs as — gets the version banner plus a
// refusal, from every subcommand, `--version` included. Probe used to read the
// version off that banner and report the engine HEALTHY on a host where it could
// never produce a finding.
//
// These two tests need a process that behaves that way, so they stand up a real
// script and run it through the real Runner. There is no fake: exec.Runner is a
// concrete type, and the point of these cases is precisely the boundary a fake
// would paper over (DECISIONS.md D-022).

func stubEngine(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell and an executable bit to imitate maldet's output")
	}
	path := filepath.Join(t.TempDir(), "maldet")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("writing the stub: %v", err)
	}
	return path
}

func TestProbeRefusesMaldetWhenTheHostBlocksNonRootScanning(t *testing.T) {
	// Byte for byte what maldet 1.6.6 printed in the validation container.
	gate := fixture(t, "maldet-user-access-disabled.txt")
	bin := stubEngine(t, "cat <<'EOF'\n"+string(gate)+"EOF\nexit 0\n")

	env := adapter.Environment{
		Runner:     sexec.New(sexec.Limits{Timeout: 20 * time.Second}, ""),
		BinaryPath: bin,
	}
	res := maldet.New().Probe(context.Background(), env)

	if res.Available {
		t.Fatalf("maldet reported available while it refuses to scan for this account;\n"+
			"that is the mbstring mistake again: version %q read off a refusal banner", res.Version)
	}
	// The reason has to name the setting. "maldet does not run" sends a sysadmin
	// hunting; naming scan_user_access is one line for them to change.
	if !strings.Contains(res.Reason, "scan_user_access") {
		t.Errorf("the reason does not name the setting to change: %q", res.Reason)
	}
	if res.Installable {
		t.Error("it was marked installable: Install() needs root and cannot fix a host setting")
	}
}

func TestScanNamesTheAccessGateRatherThanBlamingTheParser(t *testing.T) {
	gate := fixture(t, "maldet-user-access-disabled.txt")
	bin := stubEngine(t, "cat <<'EOF'\n"+string(gate)+"EOF\nexit 1\n")

	env := adapter.Environment{
		Runner:     sexec.New(sexec.Limits{Timeout: 20 * time.Second}, ""),
		BinaryPath: bin,
	}
	root := t.TempDir()
	out, err := maldet.New().Scan(context.Background(), env,
		adapter.ScanRequest{ScanID: "s_test", Root: root, Mode: schema.ModeFull})

	if err == nil {
		t.Fatal("the scan succeeded against an engine that scanned nothing — the worst failure mode")
	}
	if out.Status.CountsAsVote() {
		t.Errorf("status %q counts as a vote; an engine that could not run must abstain", out.Status)
	}
	if !strings.Contains(err.Error(), "scan_user_access") {
		t.Errorf("the error blames something else instead of naming the gate: %v", err)
	}
	if strings.Contains(err.Error(), "no scan id") {
		t.Errorf("it fell through to the generic no-scan-id path, which reads as a parsing bug: %v", err)
	}
}

// The SECOND gate, which nothing in maldet's documentation prepares you for: with
// scan_user_access=1 it still refuses until root has created the per-user public
// paths. A fresh install therefore refuses twice, for two different reasons, and the
// remedies are different — so one vague "maldet would not run" is not good enough for
// someone who has to forward the fix to their hosting support.
func TestProbeDistinguishesTheMissingPublicPathsFromTheAccessSetting(t *testing.T) {
	gate := fixture(t, "maldet-pubpaths-missing.txt")
	bin := stubEngine(t, "cat <<'EOF'\n"+string(gate)+"EOF\nexit 0\n")

	env := adapter.Environment{
		Runner:     sexec.New(sexec.Limits{Timeout: 20 * time.Second}, ""),
		BinaryPath: bin,
	}
	res := maldet.New().Probe(context.Background(), env)

	if res.Available {
		t.Fatalf("maldet reported available while its public paths do not exist; version %q", res.Version)
	}
	if !strings.Contains(res.Reason, "mkpubpaths") {
		t.Errorf("the reason does not name the command that fixes it: %q", res.Reason)
	}
	// Naming the wrong remedy is worse than naming none: the admin changes a setting
	// that is already correct and reports back that it did not help.
	if strings.Contains(res.Reason, "scan_user_access") {
		t.Errorf("it blamed scan_user_access, which is already 1 in this output: %q", res.Reason)
	}
}

// The block maldet inserts BETWEEN the totals and the hit list once its quarantine is
// off — which, since this adapter disables it on every invocation, is every real
// report this project will ever parse:
//
//	WARNING: Automatic quarantine is currently disabled, detected threats are still
//	accessible to users!
//	To enable, set quarantine_hits=1 and/or to quarantine hits from this scan run:
//	/usr/local/sbin/maldet -q 260730-0927.16
//
// It arrived from a real 1.6.6 run and no invented fixture had it. Three ways it could
// break the adapter, all silent: the totals could stop being found, a WARNING line
// could be counted as a hit and blow the hit-total check into an abstention, or the
// scan-id-looking token on the `-q` line could be picked up as the id of the scan to
// fetch — reporting on the wrong scan.
func TestTheQuarantineDisabledWarningDoesNotDisturbTheParse(t *testing.T) {
	report := fixture(t, "quarantine-disabled-warning.txt")
	if !strings.Contains(string(report), "Automatic quarantine is currently disabled") {
		t.Fatal("the fixture lost the warning block it exists for")
	}

	rep, err := maldet.New().WithStat(fakeStat).Parse(raw(report, schema.StatusCompleted))
	if err != nil {
		t.Fatalf("parsing a real report with the warning block: %v", err)
	}
	if rep.Status != schema.StatusCompleted {
		t.Errorf("status %q: a complete report became an abstention because of the warning", rep.Status)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d finding(s), want the 1 hit the report lists; a WARNING line was probably "+
			"counted as a hit", len(rep.Findings))
	}
	if got := rep.Findings[0].File.Path; got != "/home/hosting/s2/x.php" {
		t.Errorf("path %q is not the file maldet flagged", got)
	}
	// The warning is maldet confirming our own flag worked. It is not the engine
	// acting on files, so it must NOT be reported as a Principle I violation.
	if rep.Findings[0].Confidence != schema.ConfidenceSignature {
		t.Errorf("confidence %q: {MD5} is an exact match", rep.Findings[0].Confidence)
	}
}

// The `-q <scanid>` line inside that warning is a real trap: it carries a token shaped
// exactly like a scan id, and Scan looks for a scan id in maldet's output. Fetching the
// wrong scan's report would mean reporting findings from somebody else's scan — or from
// a scan of a different root — as if they were this cycle's.
func TestTheScanIDComesFromTheScanAndNotFromTheWarningsSuggestion(t *testing.T) {
	// Real 1.6.6 scan output: it announces the id through `--report`, never as "SCAN ID".
	scanOutput := "maldet(10): {scan} scan completed on /home/hosting/s2: files 2, malware hits 1, cleaned hits 0, time 2s\n" +
		"maldet(10): {scan} scan report saved, to view run: maldet --report 260730-0927.16\n"
	bin := stubEngine(t, `
if [ "$1" = "--report" ]; then
  printf '%s\n' "REPORT FOR $2"
  exit 0
fi
cat <<'EOF'
`+scanOutput+`EOF
exit 0
`)
	env := adapter.Environment{
		Runner:     sexec.New(sexec.Limits{Timeout: 20 * time.Second}, ""),
		BinaryPath: bin,
	}
	out, err := maldet.New().Scan(context.Background(), env,
		adapter.ScanRequest{ScanID: "s_test", Root: t.TempDir(), Mode: schema.ModeFull})
	if err != nil {
		t.Fatalf("the scan failed on real 1.6.6 output: %v", err)
	}
	if got := string(out.Stdout); !strings.Contains(got, "260730-0927.16") {
		t.Errorf("the report was fetched for the wrong scan id: %q", got)
	}
}
