//go:build windows

package lock

import "os"

// processAlive no Windows: FindProcess so falha se o processo nao existir.
// O alvo de producao e Linux (DECISIONS.md D-002); esta versao existe para a
// suite de testes rodar na estacao de trabalho.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	return err == nil
}
