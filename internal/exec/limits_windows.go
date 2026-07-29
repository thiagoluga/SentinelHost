//go:build windows

package exec

import "os/exec"

// No Windows nao existem nice/ionice e o alvo de producao e Linux userland
// (DECISIONS.md D-002). O executor roda o comando sem rebaixar prioridade,
// para que a suite de testes e o desenvolvimento funcionem na estacao de
// trabalho — nao para uso real de producao.

func (r *Runner) wrap(bin string, args []string) (string, []string) {
	return bin, args
}

func setProcessGroup(*exec.Cmd) {}

func maxRSSMB(*exec.Cmd) int { return 0 }
