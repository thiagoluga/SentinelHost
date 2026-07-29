package exec_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// The tests use the test binary itself as the subprocess (the TestHelperProcess
// pattern), so they depend on no external command — which would otherwise make
// the suite green or red depending on the environment.

func TestMain(m *testing.M) {
	if os.Getenv("SENTINEL_HELPER") == "1" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

func helperMain() {
	switch os.Getenv("SENTINEL_HELPER_MODE") {
	case "echo":
		os.Stdout.WriteString("engine output\n")
		os.Stderr.WriteString("engine warning\n")
		os.Exit(0)
	case "exit3":
		os.Stdout.WriteString("found something\n")
		os.Exit(3)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "flood":
		line := strings.Repeat("A", 1024) + "\n"
		for i := 0; i < 200000; i++ {
			os.Stdout.WriteString(line)
		}
		os.Exit(0)
	default:
		os.Exit(0)
	}
}

func helperCmd(mode string) sexec.Command {
	return sexec.Command{
		Engine: "test-engine",
		ScanID: "s_test",
		Path:   os.Args[0],
		Args:   []string{"-test.run=TestNothingHere"},
		Env:    []string{"SENTINEL_HELPER=1", "SENTINEL_HELPER_MODE=" + mode},
	}
}

// TestNothingHere exists only to give the subprocess a -test.run target that
// runs nothing.
func TestNothingHere(t *testing.T) {}

func TestRunCapturesOutputAndArchivesIt(t *testing.T) {
	rawDir := t.TempDir()
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, rawDir)

	res := r.Run(context.Background(), helperCmd("echo"))

	if res.Status != schema.StatusCompleted {
		t.Fatalf("expected completed, got %q (%v)", res.Status, res.Err)
	}
	if !strings.Contains(string(res.Stdout), "engine output") {
		t.Errorf("stdout lost: %q", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "engine warning") {
		t.Errorf("stderr lost: %q", res.Stderr)
	}

	// Raw output is archived for auditing and for reprocessing via Parse() when
	// the rule→category mapping improves.
	if res.RawRef == "" {
		t.Fatal("empty RawRef: the raw output was not archived")
	}
	blob, err := os.ReadFile(res.RawRef)
	if err != nil {
		t.Fatalf("reading archived output: %v", err)
	}
	if !strings.Contains(string(blob), "engine output") {
		t.Errorf("the raw file does not contain the output: %q", blob)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(res.RawRef), "test-engine.stderr")); err != nil {
		t.Errorf("stderr was not archived: %v", err)
	}
}

func TestNonZeroExitCodeIsNotAFailure(t *testing.T) {
	// Many scanners use a non-zero exit code to mean "I found something".
	// Treating that as a failure would turn every detection into an abstention —
	// the engine that finds the MOST would be the one that votes least.
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, "")

	res := r.Run(context.Background(), helperCmd("exit3"))

	if res.Status != schema.StatusCompleted {
		t.Fatalf("exit code 3 should not become %q", res.Status)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code lost: %d", res.ExitCode)
	}
	if res.Abstains() {
		t.Error("a result with a detection exit code must not abstain")
	}
}

func TestTimeoutBecomesAnAbstention(t *testing.T) {
	r := sexec.New(sexec.Limits{Timeout: 300 * time.Millisecond}, "")

	start := time.Now()
	res := r.Run(context.Background(), helperCmd("sleep"))
	elapsed := time.Since(start)

	if res.Status != schema.StatusTimeout {
		t.Fatalf("expected timeout, got %q", res.Status)
	}
	if !res.Abstains() {
		t.Error("a timeout has to become an abstention, never a clean vote (Principle VI)")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timeout") {
		t.Errorf("the real reason should be in the error, got: %v", res.Err)
	}
	// The process has to be genuinely killed, not merely abandoned.
	if elapsed > 10*time.Second {
		t.Errorf("the subprocess was not killed on timeout: it took %v", elapsed)
	}
}

func TestCancellationBecomesKilled(t *testing.T) {
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, "")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	res := r.Run(ctx, helperCmd("sleep"))
	if res.Status != schema.StatusKilled {
		t.Fatalf("expected killed, got %q (%v)", res.Status, res.Err)
	}
	if !res.Abstains() {
		t.Error("cancellation has to become an abstention")
	}
}

func TestHugeOutputIsTruncated(t *testing.T) {
	// An engine stuck in a loop can dump gigabytes. The orchestrator promises to
	// fit in 128 MB: with no ceiling it dies of OOM before it can report the
	// problem.
	if testing.Short() {
		t.Skip("the huge-output test is slow")
	}
	r := sexec.New(sexec.Limits{Timeout: 60 * time.Second, MaxOutputBytes: 64 << 10}, "")

	res := r.Run(context.Background(), helperCmd("flood"))

	if int64(len(res.Stdout)) > 64<<10 {
		t.Errorf("the capture exceeded the ceiling: %d bytes", len(res.Stdout))
	}
	if !res.Truncated {
		t.Error("truncation should have been signalled")
	}
	// Truncating must neither kill the process nor invalidate the result.
	if res.Status != schema.StatusCompleted {
		t.Errorf("truncating the output must not become a failure, got %q (%v)", res.Status, res.Err)
	}
}

func TestMissingBinaryBecomesAnAbstentionWithAReason(t *testing.T) {
	// FR-001: the user has to see WHY each engine is unavailable, not merely
	// that it "did not run".
	r := sexec.New(sexec.Limits{Timeout: time.Second}, "")

	res := r.Run(context.Background(), sexec.Command{
		Engine: "ghost",
		Path:   "a-binary-that-exists-nowhere",
	})

	if res.Status != schema.StatusFailed {
		t.Fatalf("expected failed, got %q", res.Status)
	}
	if !res.Abstains() {
		t.Error("a missing engine has to abstain")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "not found") {
		t.Errorf("the reason should say the binary does not exist, got: %v", res.Err)
	}
}

func TestEmptyPathDoesNotCrash(t *testing.T) {
	r := sexec.New(sexec.Limits{Timeout: time.Second}, "")
	res := r.Run(context.Background(), sexec.Command{Engine: "empty"})
	if !res.Abstains() {
		t.Error("an empty path has to become an abstention, not a panic")
	}
}

func TestNiceAndIoniceWrapTheCommandOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		// DECISIONS.md D-002: nice/ionice do not exist on Windows; the real
		// target is Linux user space.
		t.Skip("nice/ionice do not exist on Windows")
	}
	r := sexec.New(sexec.Limits{Nice: 19, IoniceClass: 3, Timeout: 30 * time.Second}, "")

	res := r.Run(context.Background(), helperCmd("echo"))

	joined := strings.Join(res.Wrapped, " ")
	// If nice/ionice exist in the environment they have to show up in the final
	// command; if they do not, the scan still runs (an opportunistic feature).
	if _, err := os.Stat("/usr/bin/nice"); err == nil {
		if !strings.Contains(joined, "nice") {
			t.Errorf("nice was not applied: %q", joined)
		}
	}
	if res.Status != schema.StatusCompleted {
		t.Errorf("wrapping with nice must not break execution: %q (%v)", res.Status, res.Err)
	}
}

func TestArchivingDoesNotEscapeTheDirectory(t *testing.T) {
	// The engine slug and scan_id come from configuration; a value containing
	// ../ must not let the archive write outside the data area.
	rawDir := t.TempDir()
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, rawDir)

	c := helperCmd("echo")
	c.Engine = "../../escape"
	c.ScanID = "../also"

	res := r.Run(context.Background(), c)
	if res.RawRef == "" {
		t.Fatal("expected archiving to happen")
	}
	abs, err := filepath.Abs(res.RawRef)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	rootAbs, _ := filepath.Abs(rawDir)
	if !strings.HasPrefix(abs, rootAbs) {
		t.Errorf("archiving escaped the directory: %q outside %q", abs, rootAbs)
	}
}

// Batcher --------------------------------------------------------------------

func TestBatcherSplitsAndPausesBetweenBatches(t *testing.T) {
	b := sexec.NewBatcher(2, 50*time.Millisecond)
	items := []string{"a", "b", "c", "d", "e"}

	var batches [][]string
	start := time.Now()
	err := b.Each(context.Background(), items, func(_ context.Context, batch []string) error {
		batches = append(batches, append([]string(nil), batch...))
		return nil
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(batches) != 3 {
		t.Fatalf("expected 3 batches, got %d: %v", len(batches), batches)
	}
	if len(batches[2]) != 1 {
		t.Errorf("the last batch should hold 1 item, got %v", batches[2])
	}
	// 3 batches = 2 pauses. A third pause would mean sleeping after the last
	// batch, delaying the end of the cycle for nothing.
	if elapsed < 100*time.Millisecond {
		t.Errorf("the pauses between batches did not happen: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("it paused after the last batch: %v", elapsed)
	}
}

func TestBatcherRespectsCancellation(t *testing.T) {
	b := sexec.NewBatcher(1, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := b.Each(ctx, []string{"a", "b", "c"}, func(context.Context, []string) error {
		calls++
		return nil
	})

	if err == nil {
		t.Fatal("expected a cancellation error")
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the pause ignored cancellation: a Ctrl-C would hang")
	}
	if calls != 1 {
		t.Errorf("expected 1 batch processed before cancellation, got %d", calls)
	}
}

func TestBatcherWithAnEmptyList(t *testing.T) {
	b := sexec.NewBatcher(10, time.Second)
	called := false
	err := b.Each(context.Background(), nil, func(context.Context, []string) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if called {
		t.Error("an empty list should produce no batch")
	}
}
