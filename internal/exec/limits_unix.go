//go:build unix

package exec

import (
	"os/exec"
	"strconv"
	"syscall"
)

// wrap prefixes the command with ionice and nice when they exist in the
// environment.
//
// Why the binaries and not a syscall: without root you cannot raise priority
// again afterwards, and Go exposes no way to adjust the child's priority between
// fork and exec. Wrapping with `nice`/`ionice` is the path that works on any
// hosting account — and when they do not exist the scan still runs, just without
// the priority drop. A feature that needs privilege is opportunistic, never
// mandatory (Principle III).
func (r *Runner) wrap(bin string, args []string) (string, []string) {
	name := bin
	final := args

	if r.limits.Nice > 0 {
		if nicePath, err := r.lookPath("nice"); err == nil {
			final = append([]string{"-n", strconv.Itoa(r.limits.Nice), name}, final...)
			name = nicePath
		}
	}

	if r.limits.IoniceClass > 0 {
		if ioPath, err := r.lookPath("ionice"); err == nil {
			// -t: if the kernel or the account does not allow the requested
			// class, ionice carries on instead of aborting the whole scan.
			final = append([]string{"-c", strconv.Itoa(r.limits.IoniceClass), "-t", name}, final...)
			name = ioPath
		}
	}

	return name, final
}

// setProcessGroup puts the child in its own process group.
//
// PHP and shell engines spawn children. Killing only the parent on a timeout
// would leave orphans burning the user's account CPU right after the tool gave
// up — the scenario that gets a hosting account suspended.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// maxRSSMB reads the subprocess's peak memory.
func maxRSSMB(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return 0
	}
	ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0
	}
	// On Linux, Maxrss comes in kilobytes.
	return int(ru.Maxrss / 1024)
}
