// Package adapter define o contrato que todo engine precisa cumprir para ser
// plugado no SentinelHost.
//
// O motor de veredito so conhece o esquema normalizado, nunca um engine
// especifico (Principio VI). O adaptador e a unica peca que sabe como um
// engine fala — e a unica que precisa mudar quando um engine muda de formato.
//
// Contrato completo: docs/esquema-e-adaptadores.md secao 2.
package adapter

import (
	"context"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Cost e o custo relativo declarado pelo adaptador, para o agendador
// intercalar engines pesados com leves em vez de enfileirar todos os caros.
type Cost string

const (
	CostLight  Cost = "light"
	CostMedium Cost = "medium"
	CostHeavy  Cost = "heavy"
)

// Info sao a identidade e os metadados do adaptador.
type Info struct {
	Slug string
	Name string
	// License do ENGINE, nao do adaptador. Engines GPL sao invocados
	// exclusivamente como processos externos, nunca linkados, para que o
	// orquestrador mantenha MIT (Principio II).
	License  string
	Homepage string
	// Categories que este engine consegue reportar.
	Categories []schema.Category
	// Kind que este engine produz. O MVP so tem adaptadores de malware.
	Kind schema.Kind
	Cost Cost
	// RequiresNetwork marca engines que dependem de rede (wp-checksums
	// consulta a API do WordPress.org). Numa hospedagem com saida bloqueada,
	// eles se abstem em vez de travar o ciclo.
	RequiresNetwork bool
	// DefaultWeight e o peso sugerido no consenso. A configuracao do usuario
	// sempre vence.
	DefaultWeight float64
}

// Environment e o que o orquestrador oferece ao adaptador.
type Environment struct {
	// DataDir e onde o adaptador pode instalar o engine e guardar regras.
	// Nenhum adaptador escreve fora daqui (obrigacao 1 do contrato).
	DataDir string
	// Runner e o unico caminho para executar processo. Um adaptador que
	// chamasse os/exec direto escaparia dos limites de recursos.
	Runner *exec.Runner
	// BinaryPath forcado pela configuracao do usuario, quando o probe
	// automatico nao acha o engine.
	BinaryPath string
	// ExtraArgs da configuracao.
	ExtraArgs []string
	// Offline desliga qualquer acesso a rede (probe, install, checksums).
	Offline bool
}

// ProbeResult diz se o engine roda NESTE ambiente.
//
// Reason e obrigatorio quando Available e falso: FR-001 exige que o usuario
// veja o motivo da indisponibilidade de cada engine. "Nao disponivel" sem
// motivo transforma um problema resolvivel (instalar o PHP CLI) em mistério.
type ProbeResult struct {
	Available bool
	Reason    string
	Version   string
	// BinaryPath resolvido, para o painel e o comando doctor.
	BinaryPath string
	// SignaturesUpdatedAt quando o engine separa assinaturas da instalacao.
	SignaturesUpdatedAt time.Time
	// Installable indica que Install() pode resolver a indisponibilidade sem
	// root. E o que permite ao painel oferecer o botao "instalar".
	Installable bool
}

// Unavailable monta um ProbeResult indisponivel com motivo.
func Unavailable(reason string) ProbeResult {
	return ProbeResult{Available: false, Reason: reason}
}

// UnavailableInstallable monta um ProbeResult indisponivel que Install()
// consegue resolver.
func UnavailableInstallable(reason string) ProbeResult {
	return ProbeResult{Available: false, Reason: reason, Installable: true}
}

// ScanRequest e o trabalho que o orquestrador manda o adaptador fazer.
//
// A lista de caminhos vem pronta: quem decide o escopo (incremental por
// mtime/baseline, exclusoes, limite de tamanho) e o ORQUESTRADOR. O adaptador
// nunca escolhe o que escanear, senao dois engines varreriam conjuntos
// diferentes e o consenso compararia coisas incomparaveis.
type ScanRequest struct {
	ScanID string
	Root   string
	Paths  []string
	Mode   schema.ScanMode
	// Timeout desta execucao.
	Timeout time.Duration
	// MaxFileSizeBytes: arquivos maiores devem ser pulados pelo engine
	// quando ele suportar a opcao.
	MaxFileSizeBytes int64
}

// RawOutput e a saida bruta do engine, preservada para auditoria e para
// reprocessamento por Parse() quando o mapeamento regra->categoria melhorar.
type RawOutput struct {
	Engine        string
	EngineVersion string
	ScanID        string
	Root          string
	Mode          schema.ScanMode

	Stdout   []byte
	Stderr   []byte
	ExitCode int

	StartedAt  time.Time
	FinishedAt time.Time

	// Status e Err vem do executor: e o que decide voto ou abstencao.
	Status schema.ScanStatus
	Err    error

	// RawRef aponta para a copia arquivada em disco.
	RawRef string
	// PathsRequested e quantos caminhos o orquestrador mandou escanear.
	PathsRequested int
	// Truncated indica que a captura bateu no teto.
	Truncated bool

	// Extra permite ao adaptador levar dados do Scan para o Parse sem
	// reexecutar nada (ex.: o wp-checksums leva a lista de arquivos oficiais).
	Extra map[string]any
}

// FromExecResult converte o resultado do executor em RawOutput.
func FromExecResult(req ScanRequest, engine string, res exec.Result) RawOutput {
	return RawOutput{
		Engine:         engine,
		ScanID:         req.ScanID,
		Root:           req.Root,
		Mode:           req.Mode,
		Stdout:         res.Stdout,
		Stderr:         res.Stderr,
		ExitCode:       res.ExitCode,
		FinishedAt:     time.Now(),
		StartedAt:      time.Now().Add(-res.Duration),
		Status:         res.Status,
		Err:            res.Err,
		RawRef:         res.RawRef,
		PathsRequested: len(req.Paths),
		Truncated:      res.Truncated,
	}
}

// Adapter e o contrato de integracao de um engine.
//
// Scan e Parse sao separados de proposito: permite reprocessar saidas antigas
// quando o mapeamento regra->categoria melhorar, sem rodar o engine de novo.
type Adapter interface {
	// Info devolve identidade e metadados.
	Info() Info

	// Probe detecta se o engine roda neste ambiente.
	Probe(ctx context.Context, env Environment) ProbeResult

	// Install instala ou atualiza o engine no espaco do usuario, sem root,
	// quando suportado. Adaptadores que nao instalam devolvem ErrNotInstallable.
	Install(ctx context.Context, env Environment) error

	// UpdateSignatures atualiza regras/assinaturas quando o engine separa
	// isso da instalacao.
	UpdateSignatures(ctx context.Context, env Environment) (time.Time, error)

	// Scan executa o engine sobre a lista de caminhos recebida.
	Scan(ctx context.Context, env Environment, req ScanRequest) (RawOutput, error)

	// Parse converte a saida bruta para o esquema normalizado.
	Parse(raw RawOutput) (schema.ScanReport, error)
}
