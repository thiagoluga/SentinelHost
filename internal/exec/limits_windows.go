//go:build windows

package exec

import "os/exec"

// Windows has no nice/ionice and the production target is Linux user space
// (DECISIONS.md D-002). The executor runs the command without lowering
// priority, so that the test suite and development work on the workstation —
// not for real production use.

func (r *Runner) wrap(bin string, args []string) (string, []string) {
	return bin, args
}

func setProcessGroup(*exec.Cmd) {}

func maxRSSMB(*exec.Cmd) int { return 0 }
