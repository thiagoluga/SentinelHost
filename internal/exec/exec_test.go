package exec_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	sexec "github.com/thiagoluga/SentinelHost/internal/exec"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Os testes usam o proprio binario de teste como subprocesso (padrao
// TestHelperProcess), para nao depender de nenhum comando externo — o que
// tornaria a suite verde ou vermelha conforme o ambiente.

func TestMain(m *testing.M) {
	if os.Getenv("SENTINEL_HELPER") == "1" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

func helperMain() {
	switch os.Getenv("SENTINEL_HELPER_MODE") {
	case "echo":
		os.Stdout.WriteString("saida do engine\n")
		os.Stderr.WriteString("aviso do engine\n")
		os.Exit(0)
	case "exit3":
		os.Stdout.WriteString("achei coisa\n")
		os.Exit(3)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "flood":
		linha := strings.Repeat("A", 1024) + "\n"
		for i := 0; i < 200000; i++ {
			os.Stdout.WriteString(linha)
		}
		os.Exit(0)
	default:
		os.Exit(0)
	}
}

func helperCmd(mode string) sexec.Command {
	return sexec.Command{
		Engine: "engine-de-teste",
		ScanID: "s_teste",
		Path:   os.Args[0],
		Args:   []string{"-test.run=TestNadaAqui"},
		Env:    []string{"SENTINEL_HELPER=1", "SENTINEL_HELPER_MODE=" + mode},
	}
}

// TestNadaAqui existe so para o subprocesso ter um alvo de -test.run que nao
// roda nada.
func TestNadaAqui(t *testing.T) {}

func TestRunCapturaSaidaEArquiva(t *testing.T) {
	rawDir := t.TempDir()
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, rawDir)

	res := r.Run(context.Background(), helperCmd("echo"))

	if res.Status != schema.StatusCompleted {
		t.Fatalf("esperava completed, veio %q (%v)", res.Status, res.Err)
	}
	if !strings.Contains(string(res.Stdout), "saida do engine") {
		t.Errorf("stdout perdido: %q", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "aviso do engine") {
		t.Errorf("stderr perdido: %q", res.Stderr)
	}

	// A saida bruta e arquivada para auditoria e para reprocessamento por
	// Parse() quando o mapeamento regra->categoria melhorar.
	if res.RawRef == "" {
		t.Fatal("RawRef vazio: a saida bruta nao foi arquivada")
	}
	blob, err := os.ReadFile(res.RawRef)
	if err != nil {
		t.Fatalf("lendo saida arquivada: %v", err)
	}
	if !strings.Contains(string(blob), "saida do engine") {
		t.Errorf("arquivo bruto nao tem a saida: %q", blob)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(res.RawRef), "engine-de-teste.stderr")); err != nil {
		t.Errorf("stderr nao foi arquivado: %v", err)
	}
}

func TestExitCodeNaoZeroNaoEFalha(t *testing.T) {
	// Muitos scanners usam exit code != 0 para dizer "achei coisa". Tratar
	// isso como falha transformaria toda deteccao numa abstencao — o engine
	// que MAIS acha seria o que menos vota.
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, "")

	res := r.Run(context.Background(), helperCmd("exit3"))

	if res.Status != schema.StatusCompleted {
		t.Fatalf("exit code 3 nao deveria virar %q", res.Status)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code perdido: %d", res.ExitCode)
	}
	if res.Abstains() {
		t.Error("resultado com exit code de deteccao nao pode abster-se")
	}
}

func TestTimeoutViraAbstencao(t *testing.T) {
	r := sexec.New(sexec.Limits{Timeout: 300 * time.Millisecond}, "")

	inicio := time.Now()
	res := r.Run(context.Background(), helperCmd("sleep"))
	decorrido := time.Since(inicio)

	if res.Status != schema.StatusTimeout {
		t.Fatalf("esperava timeout, veio %q", res.Status)
	}
	if !res.Abstains() {
		t.Error("timeout tem que virar abstencao, nunca voto limpo (Principio VI)")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timeout") {
		t.Errorf("o motivo real deveria estar no erro, veio: %v", res.Err)
	}
	// O processo tem que ser realmente morto, nao so abandonado.
	if decorrido > 10*time.Second {
		t.Errorf("o subprocesso nao foi morto no timeout: levou %v", decorrido)
	}
}

func TestCancelamentoViraKilled(t *testing.T) {
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, "")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	res := r.Run(ctx, helperCmd("sleep"))
	if res.Status != schema.StatusKilled {
		t.Fatalf("esperava killed, veio %q (%v)", res.Status, res.Err)
	}
	if !res.Abstains() {
		t.Error("cancelamento tem que virar abstencao")
	}
}

func TestSaidaGiganteETruncada(t *testing.T) {
	// Um engine em loop pode despejar gigabytes. O orquestrador promete caber
	// em 128 MB: sem teto, ele morre por OOM antes de conseguir reportar o
	// problema.
	if testing.Short() {
		t.Skip("teste de saida gigante e lento")
	}
	r := sexec.New(sexec.Limits{Timeout: 60 * time.Second, MaxOutputBytes: 64 << 10}, "")

	res := r.Run(context.Background(), helperCmd("flood"))

	if int64(len(res.Stdout)) > 64<<10 {
		t.Errorf("captura passou do teto: %d bytes", len(res.Stdout))
	}
	if !res.Truncated {
		t.Error("truncamento deveria ter sido sinalizado")
	}
	// Truncar nao pode matar o processo nem invalidar o resultado.
	if res.Status != schema.StatusCompleted {
		t.Errorf("truncar a saida nao pode virar falha, veio %q (%v)", res.Status, res.Err)
	}
}

func TestBinarioInexistenteViraAbstencaoComMotivo(t *testing.T) {
	// FR-001: o usuario tem que ver o motivo da indisponibilidade de cada
	// engine, nao so que ele "nao rodou".
	r := sexec.New(sexec.Limits{Timeout: time.Second}, "")

	res := r.Run(context.Background(), sexec.Command{
		Engine: "fantasma",
		Path:   "binario-que-nao-existe-em-lugar-nenhum",
	})

	if res.Status != schema.StatusFailed {
		t.Fatalf("esperava failed, veio %q", res.Status)
	}
	if !res.Abstains() {
		t.Error("engine ausente tem que abster-se")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "nao encontrado") {
		t.Errorf("o motivo deveria dizer que o binario nao existe, veio: %v", res.Err)
	}
}

func TestCaminhoVazioNaoDerruba(t *testing.T) {
	r := sexec.New(sexec.Limits{Timeout: time.Second}, "")
	res := r.Run(context.Background(), sexec.Command{Engine: "vazio"})
	if !res.Abstains() {
		t.Error("caminho vazio tem que virar abstencao, nao panico")
	}
}

func TestNiceEIoniceEnvolvemOComandoNoUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		// DECISIONS.md D-002: nice/ionice nao existem no Windows; o alvo real
		// e Linux userland.
		t.Skip("nice/ionice nao existem no Windows")
	}
	r := sexec.New(sexec.Limits{Nice: 19, IoniceClass: 3, Timeout: 30 * time.Second}, "")

	res := r.Run(context.Background(), helperCmd("echo"))

	junto := strings.Join(res.Wrapped, " ")
	// Se nice/ionice existirem no ambiente, tem que aparecer no comando final;
	// se nao existirem, o scan roda mesmo assim (recurso oportunista).
	if _, err := os.Stat("/usr/bin/nice"); err == nil {
		if !strings.Contains(junto, "nice") {
			t.Errorf("nice nao foi aplicado: %q", junto)
		}
	}
	if res.Status != schema.StatusCompleted {
		t.Errorf("envolver com nice nao pode quebrar a execucao: %q (%v)", res.Status, res.Err)
	}
}

func TestArquivamentoNaoEscapaDoDiretorio(t *testing.T) {
	// Slug de engine e scan_id vem de configuracao; um valor com ../ nao pode
	// fazer o arquivamento escrever fora da area de dados.
	rawDir := t.TempDir()
	r := sexec.New(sexec.Limits{Timeout: 30 * time.Second}, rawDir)

	c := helperCmd("echo")
	c.Engine = "../../fuga"
	c.ScanID = "../tambem"

	res := r.Run(context.Background(), c)
	if res.RawRef == "" {
		t.Fatal("esperava arquivamento")
	}
	abs, err := filepath.Abs(res.RawRef)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	raizAbs, _ := filepath.Abs(rawDir)
	if !strings.HasPrefix(abs, raizAbs) {
		t.Errorf("arquivamento escapou do diretorio: %q fora de %q", abs, raizAbs)
	}
}

// Batcher --------------------------------------------------------------------

func TestBatcherDivideEPausaEntreLotes(t *testing.T) {
	b := sexec.NewBatcher(2, 50*time.Millisecond)
	itens := []string{"a", "b", "c", "d", "e"}

	var lotes [][]string
	inicio := time.Now()
	err := b.Each(context.Background(), itens, func(_ context.Context, lote []string) error {
		lotes = append(lotes, append([]string(nil), lote...))
		return nil
	})
	decorrido := time.Since(inicio)

	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if len(lotes) != 3 {
		t.Fatalf("esperava 3 lotes, veio %d: %v", len(lotes), lotes)
	}
	if len(lotes[2]) != 1 {
		t.Errorf("ultimo lote deveria ter 1 item, veio %v", lotes[2])
	}
	// 3 lotes = 2 pausas. Uma terceira pausa significaria dormir depois do
	// ultimo lote, atrasando o fim do ciclo a toa.
	if decorrido < 100*time.Millisecond {
		t.Errorf("as pausas entre lotes nao aconteceram: %v", decorrido)
	}
	if decorrido > 200*time.Millisecond {
		t.Errorf("pausou depois do ultimo lote: %v", decorrido)
	}
}

func TestBatcherRespeitaCancelamento(t *testing.T) {
	b := sexec.NewBatcher(1, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	chamadas := 0
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	inicio := time.Now()
	err := b.Each(ctx, []string{"a", "b", "c"}, func(context.Context, []string) error {
		chamadas++
		return nil
	})

	if err == nil {
		t.Fatal("esperava erro de cancelamento")
	}
	if time.Since(inicio) > 5*time.Second {
		t.Error("a pausa ignorou o cancelamento: um Ctrl-C ficaria pendurado")
	}
	if chamadas != 1 {
		t.Errorf("esperava 1 lote processado antes do cancelamento, veio %d", chamadas)
	}
}

func TestBatcherComListaVazia(t *testing.T) {
	b := sexec.NewBatcher(10, time.Second)
	chamou := false
	err := b.Each(context.Background(), nil, func(context.Context, []string) error {
		chamou = true
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if chamou {
		t.Error("lista vazia nao deveria gerar lote")
	}
}
