//go:build unix

package exec

import (
	"os/exec"
	"strconv"
	"syscall"
)

// wrap prefixa o comando com ionice e nice quando eles existem no ambiente.
//
// Por que os binarios e nao uma syscall: sem root nao da para elevar
// prioridade depois, e o Go nao expoe um jeito de ajustar a prioridade do
// filho entre fork e exec. Envolver com `nice`/`ionice` e o caminho que
// funciona em qualquer conta de hospedagem — e quando eles nao existem, o
// scan roda mesmo assim, so que sem a rebaixada de prioridade. Recurso que
// exige privilegio e oportunista, nunca obrigatorio (Principio III).
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
			// -t: se o kernel ou a conta nao permitirem a classe pedida,
			// ionice segue em frente em vez de abortar o scan inteiro.
			final = append([]string{"-c", strconv.Itoa(r.limits.IoniceClass), "-t", name}, final...)
			name = ioPath
		}
	}

	return name, final
}

// setProcessGroup coloca o filho no proprio grupo de processo.
//
// Engines em PHP e shell criam filhos. Matar so o pai no timeout deixaria
// orfaos queimando a CPU da conta do usuario justamente depois de a
// ferramenta ter desistido — o cenario que faz a hospedagem suspender a conta.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// maxRSSMB le o pico de memoria do subprocesso.
func maxRSSMB(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return 0
	}
	ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0
	}
	// No Linux, Maxrss vem em kilobytes.
	return int(ru.Maxrss / 1024)
}
