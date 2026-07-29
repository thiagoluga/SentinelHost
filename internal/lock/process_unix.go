//go:build unix

package lock

import (
	"os"
	"syscall"
)

// processAlive responde se o processo ainda existe.
//
// Sinal 0 nao entrega nada: so pergunta ao kernel se o processo existe e se
// temos permissao de sinaliza-lo. E o jeito padrao de detectar lock orfao sem
// depender de /proc, que nem toda hospedagem expoe.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM significa que o processo existe mas pertence a outro usuario.
	// Num servidor compartilhado o PID pode ter sido reciclado por outra
	// conta; tratar como vivo e o lado seguro: no pior caso a ferramenta
	// espera o proximo ciclo em vez de rodar duas vezes.
	return os.IsPermission(err)
}
