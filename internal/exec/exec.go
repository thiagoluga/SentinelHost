// Package exec runs external engines as subprocesses with the constitution's
// resource limits applied.
//
// This package is Principle IV in code: nice, ionice, per-engine timeout, the
// pause between batches and the capture of raw output all go through here. No
// adapter spawns a process on its own — if it did, the limits would be optional
// in practice.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Limits are the limits applied to every subprocess.
type Limits struct {
	// Nice from 0 to 19. 19 is the lowest priority.
	Nice int
	// IoniceClass 3 = idle.
	IoniceClass int
	// Timeout of ONE execution.
	Timeout time.Duration
	// MaxOutputBytes caps the capture of stdout/stderr. An engine stuck in a
	// loop can dump gigabytes; with no cap, the orchestrator that promises to
	// fit in 128 MB dies of OOM before it can report the problem.
	MaxOutputBytes int64
}

// DefaultMaxOutput is the capture ceiling per stream.
const DefaultMaxOutput int64 = 32 << 20 // 32 MiB

// Runner executes commands with limits and archives the raw output.
type Runner struct {
	limits Limits
	// rawDir is the root of the raw-output archive. Empty disables archiving
	// (used in tests).
	rawDir string
	// lookPath is injectable for tests; in production it is exec.LookPath.
	lookPath func(string) (string, error)
}

// New creates a Runner.
func New(limits Limits, rawDir string) *Runner {
	if limits.MaxOutputBytes <= 0 {
		limits.MaxOutputBytes = DefaultMaxOutput
	}
	return &Runner{limits: limits, rawDir: rawDir, lookPath: exec.LookPath}
}

// Command describes one engine execution.
type Command struct {
	// Engine is the slug, used to name the archived raw output.
	Engine string
	// ScanID groups a cycle's raw outputs together.
	ScanID string
	// Path is the binary. It has to exist; the Runner never goes through a shell.
	Path string
	Args []string
	Dir  string
	// Env extras. Inherits the current environment.
	Env []string
	// Stdin, optional (a newline-separated file list, for example).
	Stdin []byte
	// Timeout overrides the Runner's limit when > 0.
	Timeout time.Duration
}

// Result is the outcome of the execution.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
	MaxRSSMB int
	// Status already translated into the schema's vocabulary: it is what decides
	// whether the engine votes or abstains.
	Status schema.ScanStatus
	// Err is the real reason when Status != completed.
	Err error
	// RawRef points at the archived raw output.
	RawRef string
	// Truncated indicates the output hit the capture ceiling.
	Truncated bool
	// Wrapped shows the final command, with nice/ionice, for the panel and the
	// doctor command.
	Wrapped []string
}

// Abstains answers whether this result should become an abstention.
func (r Result) Abstains() bool { return !r.Status.CountsAsVote() }

// ErrBinaryNotFound signals an engine unavailable in this environment.
var ErrBinaryNotFound = errors.New("binary not found")

// Run executes the command with the limits applied.
//
// It never surfaces an execution error as a panic or as a cycle failure: the
// outcome comes back in Result.Status, and it is up to the caller to turn that
// into an abstention (Principle VI).
func (r *Runner) Run(ctx context.Context, c Command) Result {
	started := time.Now()
	res := Result{Status: schema.StatusCompleted}

	if c.Path == "" {
		res.Status = schema.StatusFailed
		res.Err = fmt.Errorf("%w: empty path for engine %s", ErrBinaryNotFound, c.Engine)
		return res
	}
	bin, err := r.resolve(c.Path)
	if err != nil {
		res.Status = schema.StatusFailed
		res.Err = fmt.Errorf("%w: %s (%v)", ErrBinaryNotFound, c.Path, err)
		return res
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = r.limits.Timeout
	}
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	name, args := r.wrap(bin, c.Args)
	res.Wrapped = append([]string{name}, args...)

	cmd := exec.CommandContext(runCtx, name, args...) // args built by the adapter, never via a shell
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	if len(c.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}

	outBuf := &cappedBuffer{limit: r.limits.MaxOutputBytes}
	errBuf := &cappedBuffer{limit: r.limits.MaxOutputBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	// Its own process group: PHP and shell engines spawn children, and killing
	// only the parent would leave orphans burning the user's account CPU after
	// the timeout — exactly what gets an account suspended for resource abuse.
	setProcessGroup(cmd)

	runErr := cmd.Run()

	res.Duration = time.Since(started)
	res.Stdout = outBuf.Bytes()
	res.Stderr = errBuf.Bytes()
	res.Truncated = outBuf.truncated || errBuf.truncated
	res.MaxRSSMB = maxRSSMB(cmd)
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}

	switch {
	case runErr == nil:
		res.Status = schema.StatusCompleted
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.Status = schema.StatusTimeout
		res.Err = fmt.Errorf("engine %s exceeded the %s timeout", c.Engine, timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		res.Status = schema.StatusKilled
		res.Err = fmt.Errorf("engine %s cancelled: %w", c.Engine, ctx.Err())
	default:
		// Many scanners use a non-zero exit code to mean "I found something".
		// The adapter decides what each code means; here we only record it.
		res.Status = schema.StatusCompleted
		res.Err = runErr
	}

	if ref, err := r.archive(c, res); err != nil {
		// Failing to archive does not invalidate the scan, but the user needs to
		// know they lost that cycle's audit trail.
		res.Err = errors.Join(res.Err, fmt.Errorf("archiving raw output: %w", err))
	} else {
		res.RawRef = ref
	}

	return res
}

// resolve finds the binary, accepting an absolute path or a name on PATH.
func (r *Runner) resolve(path string) (string, error) {
	if strings.ContainsAny(path, `/\`) {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			return "", fmt.Errorf("%s is a directory", path)
		}
		return path, nil
	}
	return r.lookPath(path)
}

// cappedBuffer accumulates up to limit bytes and discards the rest.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	written   int64
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	// Always reports having written everything: returning n < len(p) would make
	// os/exec abort the process with ErrShortWrite, and the output captured so
	// far would be lost along with it.
	if c.written >= c.limit {
		c.truncated = true
		return len(p), nil
	}
	room := c.limit - c.written
	if int64(len(p)) > room {
		c.buf.Write(p[:room])
		c.written = c.limit
		c.truncated = true
		return len(p), nil
	}
	c.buf.Write(p)
	c.written += int64(len(p))
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// archive writes the raw output for auditing and for reprocessing via Parse().
func (r *Runner) archive(c Command, res Result) (string, error) {
	if r.rawDir == "" || c.Engine == "" {
		return "", nil
	}
	scanID := c.ScanID
	if scanID == "" {
		scanID = "adhoc"
	}
	dir := filepath.Join(r.rawDir, sanitizeName(scanID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	base := sanitizeName(c.Engine)
	stdout := filepath.Join(dir, base+".stdout")
	if err := os.WriteFile(stdout, res.Stdout, 0o600); err != nil {
		return "", err
	}
	if len(res.Stderr) > 0 {
		if err := os.WriteFile(filepath.Join(dir, base+".stderr"), res.Stderr, 0o600); err != nil {
			return "", err
		}
	}
	return stdout, nil
}

// sanitizeName stops an unexpected slug or scan_id from escaping the archive
// directory.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "unknown"
	}
	return out
}
