// Package exec executa engines externos como subprocessos com os limites de
// recursos da constituicao aplicados.
//
// Este pacote e o Principio IV em codigo: nice, ionice, timeout por engine,
// pausa entre lotes e captura da saida bruta passam todos por aqui. Nenhum
// adaptador executa processo por conta propria — se executasse, os limites
// seriam opcionais na pratica.
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

// Limits sao os limites aplicados a cada subprocesso.
type Limits struct {
	// Nice de 0 a 19. 19 e a menor prioridade.
	Nice int
	// IoniceClass 3 = idle.
	IoniceClass int
	// Timeout de UMA execucao.
	Timeout time.Duration
	// MaxOutputBytes limita a captura de stdout/stderr. Um engine em loop
	// pode despejar gigabytes; sem limite, o orquestrador que promete caber
	// em 128 MB morre por OOM antes de conseguir reportar o problema.
	MaxOutputBytes int64
}

// DefaultMaxOutput e o teto de captura por fluxo.
const DefaultMaxOutput int64 = 32 << 20 // 32 MiB

// Runner executa comandos com limites e arquiva a saida bruta.
type Runner struct {
	limits Limits
	// rawDir e a raiz do arquivamento de saida bruta. Vazio desliga o
	// arquivamento (usado nos testes).
	rawDir string
	// lookPath e injetavel para teste; em producao e exec.LookPath.
	lookPath func(string) (string, error)
}

// New cria um Runner.
func New(limits Limits, rawDir string) *Runner {
	if limits.MaxOutputBytes <= 0 {
		limits.MaxOutputBytes = DefaultMaxOutput
	}
	return &Runner{limits: limits, rawDir: rawDir, lookPath: exec.LookPath}
}

// Command descreve uma execucao de engine.
type Command struct {
	// Engine e o slug, usado para nomear a saida bruta arquivada.
	Engine string
	// ScanID agrupa as saidas brutas de um ciclo.
	ScanID string
	// Path e o binario. Precisa existir; o Runner nunca passa por shell.
	Path string
	Args []string
	Dir  string
	// Env extra. Herda o ambiente atual.
	Env []string
	// Stdin opcional (lista de arquivos por linha, por exemplo).
	Stdin []byte
	// Timeout sobrepoe o limite do Runner quando > 0.
	Timeout time.Duration
}

// Result e o desfecho da execucao.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
	MaxRSSMB int
	// Status ja traduzido para o vocabulario do esquema: e o que determina se
	// o engine vota ou se abstem.
	Status schema.ScanStatus
	// Err e o motivo real quando Status != completed.
	Err error
	// RawRef aponta para a saida bruta arquivada.
	RawRef string
	// Truncated indica que a saida bateu no teto de captura.
	Truncated bool
	// Wrapped mostra o comando final, com nice/ionice, para o painel e o
	// comando doctor.
	Wrapped []string
}

// Abstains responde se este resultado deve virar abstencao.
func (r Result) Abstains() bool { return !r.Status.CountsAsVote() }

// ErrBinaryNotFound indica engine indisponivel neste ambiente.
var ErrBinaryNotFound = errors.New("binario nao encontrado")

// Run executa o comando aplicando os limites.
//
// Nunca devolve erro de execucao como panico ou como falha do ciclo: o
// desfecho vem em Result.Status, e cabe ao chamador transformar isso em
// abstencao (Principio VI).
func (r *Runner) Run(ctx context.Context, c Command) Result {
	started := time.Now()
	res := Result{Status: schema.StatusCompleted}

	if c.Path == "" {
		res.Status = schema.StatusFailed
		res.Err = fmt.Errorf("%w: caminho vazio para o engine %s", ErrBinaryNotFound, c.Engine)
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

	cmd := exec.CommandContext(runCtx, name, args...) //nolint:gosec // argumentos montados pelo adaptador, nunca por shell
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	if len(c.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}

	outBuf := &cappedBuffer{limit: r.limits.MaxOutputBytes}
	errBuf := &cappedBuffer{limit: r.limits.MaxOutputBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	// Grupo de processo proprio: engines em PHP e shell criam filhos, e matar
	// so o pai deixaria orfaos consumindo CPU da conta do usuario depois do
	// timeout — exatamente o que causa suspensao por abuso de recursos.
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
		res.Err = fmt.Errorf("engine %s excedeu o timeout de %s", c.Engine, timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		res.Status = schema.StatusKilled
		res.Err = fmt.Errorf("engine %s cancelado: %w", c.Engine, ctx.Err())
	default:
		// Muitos scanners usam exit code != 0 para dizer "achei coisa". O
		// adaptador decide o que cada codigo significa; aqui so registramos.
		res.Status = schema.StatusCompleted
		res.Err = runErr
	}

	if ref, err := r.archive(c, res); err != nil {
		// Falhar em arquivar nao invalida o scan, mas o usuario precisa
		// saber que perdeu a trilha de auditoria daquele ciclo.
		res.Err = errors.Join(res.Err, fmt.Errorf("arquivando saida bruta: %w", err))
	} else {
		res.RawRef = ref
	}

	return res
}

// resolve encontra o binario, aceitando caminho absoluto ou nome no PATH.
func (r *Runner) resolve(path string) (string, error) {
	if strings.ContainsAny(path, `/\`) {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			return "", fmt.Errorf("%s e um diretorio", path)
		}
		return path, nil
	}
	return r.lookPath(path)
}

// cappedBuffer acumula ate limit bytes e descarta o resto.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	written   int64
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	// Sempre reporta ter escrito tudo: devolver n < len(p) faria o os/exec
	// abortar o processo com ErrShortWrite, e a saida ja capturada ate ali
	// seria perdida junto.
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

// archive grava a saida bruta para auditoria e reprocessamento por Parse().
func (r *Runner) archive(c Command, res Result) (string, error) {
	if r.rawDir == "" || c.Engine == "" {
		return "", nil
	}
	scanID := c.ScanID
	if scanID == "" {
		scanID = "avulso"
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

// sanitizeName impede que um slug ou scan_id inesperado escape do diretorio de
// arquivamento.
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
		return "desconhecido"
	}
	return out
}
