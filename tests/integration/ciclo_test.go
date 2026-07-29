package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/lock"
)

// SC-002 -------------------------------------------------------------------------

// TestSC002CicloIncrementalGrande mede o ciclo incremental num site de 20 mil
// arquivos com 1% de mudanca.
//
// A spec exige menos de 5 minutos dentro dos limites padrao. O que domina esse
// tempo e a varredura + o hash dos arquivos que mudaram; a execucao dos engines
// externos fica fora (D-011), e por isso o teste mede o custo que o
// SentinelHost tem controle sobre.
func TestSC002CicloIncrementalGrande(t *testing.T) {
	if testing.Short() {
		t.Skip("SC-002 monta 20 mil arquivos; pulado em -short")
	}

	root := t.TempDir()
	const total = 20000
	const mudados = total / 100 // 1%

	criarSite(t, root, total)

	cfg := config.Default()
	cfg.General.Roots = []string{root}
	cfg.General.DataDir = filepath.Join(t.TempDir(), "dados")

	baselinePath := filepath.Join(cfg.General.DataDir, "baseline.json")
	if err := os.MkdirAll(cfg.General.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Ciclo 1: baseline completo. Nao entra na medicao do SC-002 — o criterio
	// e sobre o ciclo INCREMENTAL.
	bl := baseline.New(cfg.General.Roots)
	res, err := baseline.Walk(context.Background(), opcoes(cfg, root))
	if err != nil {
		t.Fatalf("walk inicial: %v", err)
	}
	if len(res.Entries) < total {
		t.Fatalf("esperava ao menos %d arquivos, veio %d", total, len(res.Entries))
	}
	inicioBaseline := time.Now()
	entradas := baseline.HashEntries(context.Background(), res.Entries, res.SkippedCounts)
	bl.Update(entradas, nil)
	if err := bl.Save(baselinePath); err != nil {
		t.Fatalf("salvando baseline: %v", err)
	}
	t.Logf("baseline completo de %d arquivos: %s", len(entradas), time.Since(inicioBaseline).Round(time.Millisecond))

	// Modifica 1% dos arquivos.
	for i := 0; i < mudados; i++ {
		p := filepath.Join(root, fmt.Sprintf("dir%02d", i%50), fmt.Sprintf("arq%05d.php", i))
		if err := os.WriteFile(p, []byte(fmt.Sprintf("<?php // alterado %d\n", i)), 0o644); err != nil {
			t.Fatalf("modificando %s: %v", p, err)
		}
	}

	// Ciclo 2: incremental. E este que o SC-002 mede.
	inicio := time.Now()

	bl2, err := baseline.Load(baselinePath, cfg.General.Roots)
	if err != nil {
		t.Fatalf("carregando baseline: %v", err)
	}
	res2, err := baseline.Walk(context.Background(), opcoes(cfg, root))
	if err != nil {
		t.Fatalf("walk incremental: %v", err)
	}
	// So o que mudou no par tamanho+mtime e lido do disco. E o passo que torna
	// o ciclo incremental barato o bastante para rodar de hora em hora.
	precisaHash := bl2.NeedsHash(res2.Entries)
	hasheadas := baseline.HashEntries(context.Background(), precisaHash, res2.SkippedCounts)

	novos := map[string]baseline.Entry{}
	for _, e := range hasheadas {
		novos[e.Path] = e
	}
	atual := make([]baseline.Entry, 0, len(res2.Entries))
	for _, e := range res2.Entries {
		if h, ok := novos[e.Path]; ok {
			atual = append(atual, h)
			continue
		}
		if ant, ok := bl2.Get(e.Path); ok {
			e.SHA256 = ant.SHA256
		}
		atual = append(atual, e)
	}
	d := bl2.Compare(atual)
	alvos := d.Targets()

	decorrido := time.Since(inicio)

	t.Logf("SC-002: ciclo incremental de %d arquivos (%d modificados) em %s",
		len(res2.Entries), len(alvos), decorrido.Round(time.Millisecond))
	t.Logf("        arquivos relidos do disco: %d (%.2f%% do total)",
		len(precisaHash), float64(len(precisaHash))/float64(len(res2.Entries))*100)

	if len(alvos) != mudados {
		t.Errorf("o incremental deveria escanear exatamente os %d modificados, veio %d", mudados, len(alvos))
	}
	if d.Unchanged != len(res2.Entries)-mudados {
		t.Errorf("inalterados: %d, esperado %d", d.Unchanged, len(res2.Entries)-mudados)
	}
	// O ganho do incremental esta aqui: reler 1% do site em vez de 100%.
	if len(precisaHash) > mudados*2 {
		t.Errorf("o incremental releu %d arquivos para %d modificados: o filtro barato nao esta funcionando",
			len(precisaHash), mudados)
	}
	if decorrido > 5*time.Minute {
		t.Errorf("SC-002 reprovado: ciclo incremental levou %s, limite 5 minutos", decorrido)
	}
}

func opcoes(cfg *config.Config, root string) baseline.WalkOptions {
	return baseline.WalkOptions{
		Root:             root,
		Exclude:          cfg.Limits.Exclude,
		MaxDepth:         cfg.Limits.MaxDepth,
		MaxFileSizeBytes: int64(cfg.Limits.MaxFileSizeMB) << 20,
		MaxFiles:         cfg.Limits.MaxFilesPerCycle,
	}
}

func criarSite(t *testing.T, root string, n int) {
	t.Helper()
	for d := 0; d < 50; d++ {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("dir%02d", d)), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	conteudo := []byte("<?php\n// arquivo de teste do SentinelHost\nfunction x() { return 1; }\n")
	for i := 0; i < n; i++ {
		p := filepath.Join(root, fmt.Sprintf("dir%02d", i%50), fmt.Sprintf("arq%05d.php", i))
		if err := os.WriteFile(p, conteudo, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

// Lock de instancia unica ---------------------------------------------------------

// TestLockImpedeCiclosConcorrentes cobre o edge case da spec: cron e painel
// disparando um scan ao mesmo tempo.
func TestLockImpedeCiclosConcorrentes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelhost.lock")

	primeiro, err := lock.Acquire(path)
	if err != nil {
		t.Fatalf("primeiro lock: %v", err)
	}
	defer func() { _ = primeiro.Release() }()

	const tentativas = 20
	resultados := make(chan error, tentativas)
	for i := 0; i < tentativas; i++ {
		go func() {
			l, err := lock.Acquire(path)
			if err == nil {
				_ = l.Release()
			}
			resultados <- err
		}()
	}

	sucessos := 0
	for i := 0; i < tentativas; i++ {
		if err := <-resultados; err == nil {
			sucessos++
		}
	}
	// Dois ciclos concorrentes escreveriam no mesmo baseline e poderiam
	// tentar quarentenar o mesmo arquivo duas vezes.
	if sucessos != 0 {
		t.Errorf("%d processo(s) conseguiram o lock enquanto ele estava tomado", sucessos)
	}
}
