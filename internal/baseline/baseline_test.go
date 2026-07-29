package baseline_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
)

func criarArvore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	arquivos := map[string]string{
		"index.php":                          "<?php echo 'oi';",
		"wp-content/themes/tema/footer.php":  "<?php // footer",
		"wp-content/cache/x.php":             "<?php // cache",
		"wp-content/uploads/2026/foto.jpg":   "binario-falso",
		"wp-content/uploads/2026/script.php": "<?php // suspeito",
		"a/b/c/d/e/f/fundo.php":              "<?php // fundo",
	}
	for rel, conteudo := range arquivos {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(abs, []byte(conteudo), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

func caminhos(entries []baseline.Entry) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		out[filepath.ToSlash(e.Path)] = true
	}
	return out
}

func TestWalkAplicaExclusoes(t *testing.T) {
	root := criarArvore(t)

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root:     root,
		Exclude:  []string{"**/wp-content/cache/**", "**/*.jpg"},
		MaxDepth: 20,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	got := caminhos(res.Entries)
	for p := range got {
		if filepath.Ext(p) == ".jpg" {
			t.Errorf("arquivo excluido por extensao apareceu: %s", p)
		}
		if contains(p, "/cache/") {
			t.Errorf("diretorio excluido apareceu: %s", p)
		}
	}
	if res.SkippedCounts["excluded"] == 0 {
		t.Error("as exclusoes deveriam ser contabilizadas, nao silenciosas")
	}
}

func TestWalkContabilizaArquivoGrandeEmVezDeIgnorar(t *testing.T) {
	// Pular em silencio faria a cobertura parecer completa.
	root := t.TempDir()
	grande := filepath.Join(root, "grande.php")
	if err := os.WriteFile(grande, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	pequeno := filepath.Join(root, "pequeno.php")
	if err := os.WriteFile(pequeno, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 10, MaxFileSizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("esperava 1 arquivo, veio %d", len(res.Entries))
	}
	if res.SkippedCounts["too_large"] != 1 {
		t.Errorf("o arquivo grande deveria ser contabilizado: %v", res.SkippedCounts)
	}
}

func TestWalkRespeitaProfundidadeMaxima(t *testing.T) {
	root := criarArvore(t)

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 2,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, e := range res.Entries {
		if contains(filepath.ToSlash(e.Path), "/a/b/c/") {
			t.Errorf("arquivo alem da profundidade apareceu: %s", e.Path)
		}
	}
	if res.SkippedCounts["too_deep"] == 0 {
		t.Error("a profundidade excedida deveria ser contabilizada")
	}
}

func TestWalkNuncaSegueSymlink(t *testing.T) {
	// Um link para fora da raiz faria o scanner entrar na conta de outra
	// pessoa num servidor compartilhado.
	if runtime.GOOS == "windows" {
		t.Skip("criar symlink no Windows exige privilegio; o alvo real e Linux (D-002)")
	}
	root := t.TempDir()
	fora := t.TempDir()
	if err := os.WriteFile(filepath.Join(fora, "segredo.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(fora, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{Root: root, MaxDepth: 10})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, e := range res.Entries {
		if contains(e.Path, "segredo.php") {
			t.Fatalf("o walker seguiu o symlink e saiu da raiz: %s", e.Path)
		}
	}
	if res.SkippedCounts["symlink"] == 0 {
		t.Error("o symlink deveria ser contabilizado")
	}
}

func TestWalkTruncaEmMaxFiles(t *testing.T) {
	root := criarArvore(t)
	res, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: root, MaxDepth: 20, MaxFiles: 2,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Errorf("esperava 2 entradas, veio %d", len(res.Entries))
	}
	if !res.Truncated {
		t.Error("o truncamento deveria ser sinalizado para o ciclo virar partial")
	}
}

func TestWalkRecusaRaizInexistente(t *testing.T) {
	_, err := baseline.Walk(context.Background(), baseline.WalkOptions{
		Root: filepath.Join(t.TempDir(), "nao-existe"), MaxDepth: 5,
	})
	if err == nil {
		t.Fatal("raiz inexistente deveria ser erro")
	}
}

// Baseline --------------------------------------------------------------------

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{
		{Path: "/site/a.php", Size: 10, MTime: 100, SHA256: "aa", Perms: "0644"},
		{Path: "/site/b.php", Size: 20, MTime: 200, SHA256: "bb", Perms: "0644"},
	}, nil)

	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	back, err := baseline.Load(path, []string{"/site"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if back.Len() != 2 {
		t.Fatalf("esperava 2 arquivos, veio %d", back.Len())
	}
	e, ok := back.Get("/site/a.php")
	if !ok || e.SHA256 != "aa" {
		t.Errorf("entrada perdida: %+v", e)
	}
}

func TestBaselineAusenteNaoEErro(t *testing.T) {
	// A primeira execucao nao tem baseline, e isso e normal.
	b, err := baseline.Load(filepath.Join(t.TempDir(), "nao-existe.json"), []string{"/site"})
	if err != nil {
		t.Fatalf("baseline ausente nao deveria ser erro: %v", err)
	}
	if b.Len() != 0 {
		t.Errorf("esperava baseline vazio, veio %d", b.Len())
	}
}

func TestBaselineCorrompidoRecomecaEmVezDeTravar(t *testing.T) {
	// Recomecar custa um scan completo; travar custa a protecao inteira.
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{isso nao e json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, err := baseline.Load(path, []string{"/site"})
	if err == nil {
		t.Error("o problema deveria ser reportado ao chamador")
	}
	if b == nil || b.Len() != 0 {
		t.Fatal("deveria devolver um baseline vazio utilizavel")
	}
}

func TestCompareDetectaNovoModificadoERemovido(t *testing.T) {
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{
		{Path: "/site/igual.php", Size: 10, MTime: 100, SHA256: "aa"},
		{Path: "/site/mudou.php", Size: 20, MTime: 200, SHA256: "bb"},
		{Path: "/site/sumiu.php", Size: 30, MTime: 300, SHA256: "cc"},
	}, nil)

	d := b.Compare([]baseline.Entry{
		{Path: "/site/igual.php", Size: 10, MTime: 100, SHA256: "aa"},
		{Path: "/site/mudou.php", Size: 25, MTime: 250, SHA256: "bb-novo"},
		{Path: "/site/novo.php", Size: 5, MTime: 400, SHA256: "dd"},
	})

	if d.Unchanged != 1 {
		t.Errorf("esperava 1 inalterado, veio %d", d.Unchanged)
	}
	if len(d.Modified) != 1 || d.Modified[0].Path != "/site/mudou.php" {
		t.Errorf("modificados errados: %+v", d.Modified)
	}
	if len(d.New) != 1 || d.New[0].Path != "/site/novo.php" {
		t.Errorf("novos errados: %+v", d.New)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "/site/sumiu.php" {
		t.Errorf("removidos errados: %+v", d.Removed)
	}
	if len(d.Targets()) != 2 {
		t.Errorf("o ciclo deveria escanear 2 arquivos, veio %d", len(d.Targets()))
	}
}

func TestArquivoComMesmoTamanhoEMtimeMasHashDiferenteEModificado(t *testing.T) {
	// `touch` para restaurar o mtime e a primeira coisa que um atacante faz.
	// Quando o hash ja foi calculado, ele vence o par tamanho+mtime.
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{{Path: "/site/x.php", Size: 100, MTime: 500, SHA256: "original"}}, nil)

	d := b.Compare([]baseline.Entry{{Path: "/site/x.php", Size: 100, MTime: 500, SHA256: "adulterado"}})

	if len(d.Modified) != 1 {
		t.Fatalf("hash diferente deveria marcar como modificado, veio %+v", d)
	}
}

func TestNeedsHashSoPegaOQueMudouNoParBarato(t *testing.T) {
	// E o passo que torna o ciclo incremental barato.
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{
		{Path: "/site/a.php", Size: 10, MTime: 100, SHA256: "aa"},
		{Path: "/site/b.php", Size: 20, MTime: 200, SHA256: "bb"},
	}, nil)

	precisa := b.NeedsHash([]baseline.Entry{
		{Path: "/site/a.php", Size: 10, MTime: 100},
		{Path: "/site/b.php", Size: 21, MTime: 200},
		{Path: "/site/c.php", Size: 5, MTime: 300},
	})

	if len(precisa) != 2 {
		t.Fatalf("esperava 2 arquivos para hashear, veio %d: %+v", len(precisa), precisa)
	}
}

func TestUpdateNaoGravaEntradaSemHash(t *testing.T) {
	// Gravar sem hash faria o ciclo seguinte achar que ja conhece o arquivo.
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{{Path: "/site/novo.php", Size: 10, MTime: 100}}, nil)

	if b.Len() != 0 {
		t.Errorf("entrada sem hash nao deveria entrar no baseline: %d", b.Len())
	}
}

func TestUpdatePreservaHashConhecidoQuandoNaoRecalculado(t *testing.T) {
	b := baseline.New([]string{"/site"})
	b.Update([]baseline.Entry{{Path: "/site/x.php", Size: 10, MTime: 100, SHA256: "aa"}}, nil)
	// Novo ciclo: mesmo arquivo, sem recalcular o hash porque nada mudou.
	b.Update([]baseline.Entry{{Path: "/site/x.php", Size: 10, MTime: 100}}, nil)

	e, ok := b.Get("/site/x.php")
	if !ok || e.SHA256 != "aa" {
		t.Errorf("o hash conhecido foi perdido: %+v", e)
	}
}

func TestHashEntriesDescartaIlegivel(t *testing.T) {
	// Hash vazio viraria chave de deduplicacao invalida no consenso.
	root := t.TempDir()
	bom := filepath.Join(root, "bom.php")
	if err := os.WriteFile(bom, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	skipped := map[string]int{}
	out := baseline.HashEntries(context.Background(), []baseline.Entry{
		{Path: bom},
		{Path: filepath.Join(root, "nao-existe.php")},
	}, skipped)

	if len(out) != 1 {
		t.Fatalf("esperava 1 entrada, veio %d", len(out))
	}
	if out[0].SHA256 == "" {
		t.Error("hash nao foi calculado")
	}
	if skipped["unreadable"] != 1 {
		t.Errorf("o ilegivel deveria ser contabilizado: %v", skipped)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
