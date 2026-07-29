// Package lock impede que duas instancias do SentinelHost rodem ao mesmo tempo.
//
// O cenario real: o cron dispara um ciclo enquanto o usuario clica em
// "escanear agora" no painel. Dois ciclos concorrentes escreveriam no mesmo
// baseline e poderiam tentar quarentenar o mesmo arquivo duas vezes.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrLocked indica que outra instancia esta rodando.
var ErrLocked = errors.New("outra instancia do SentinelHost ja esta rodando")

// Lock e um lock de arquivo com dono identificado.
type Lock struct {
	path string
	held bool
}

// Info descreve quem detem o lock.
type Info struct {
	PID       int
	StartedAt time.Time
	Host      string
}

// Acquire tenta obter o lock.
//
// Usa O_EXCL, que e atomico ate em NFS moderno — importante porque hospedagem
// compartilhada as vezes monta o home por rede, onde flock nao e confiavel.
func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("criando diretorio do lock: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		host, _ := os.Hostname()
		conteudo := fmt.Sprintf("%d\n%s\n%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339), host)
		if _, werr := f.WriteString(conteudo); werr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("gravando lock: %w", werr)
		}
		if cerr := f.Close(); cerr != nil {
			return nil, fmt.Errorf("fechando lock: %w", cerr)
		}
		return &Lock{path: path, held: true}, nil
	}
	if !os.IsExist(err) {
		return nil, fmt.Errorf("criando lock: %w", err)
	}

	// Lock existe. Ele e de um processo vivo ou e restos de um processo que a
	// hospedagem matou? A segunda situacao e comum e nao pode deixar a
	// ferramenta travada para sempre.
	info, readErr := Read(path)
	if readErr != nil {
		return nil, fmt.Errorf("%w (lock ilegivel em %s: %v)", ErrLocked, path, readErr)
	}
	if processAlive(info.PID) {
		return nil, fmt.Errorf("%w: PID %d desde %s", ErrLocked, info.PID, info.StartedAt.Format(time.RFC3339))
	}

	// Lock orfao: remove e tenta de novo, uma vez so. Se a segunda tentativa
	// falhar, e porque outra instancia ganhou a corrida — e ai ela venceu com
	// justica.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removendo lock orfao: %w", err)
	}
	return Acquire(path)
}

// Read le quem detem o lock.
func Read(path string) (Info, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caminho derivado do diretorio de dados
	if err != nil {
		return Info{}, err
	}
	linhas := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(linhas) < 2 {
		return Info{}, errors.New("formato de lock inesperado")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(linhas[0]))
	if err != nil {
		return Info{}, fmt.Errorf("PID invalido no lock: %w", err)
	}
	info := Info{PID: pid}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(linhas[1])); err == nil {
		info.StartedAt = t
	}
	if len(linhas) > 2 {
		info.Host = strings.TrimSpace(linhas[2])
	}
	return info, nil
}

// Release solta o lock. Chamar duas vezes e seguro.
func (l *Lock) Release() error {
	if l == nil || !l.held {
		return nil
	}
	l.held = false
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("liberando lock: %w", err)
	}
	return nil
}

// Path devolve o caminho do lock.
func (l *Lock) Path() string { return l.path }
