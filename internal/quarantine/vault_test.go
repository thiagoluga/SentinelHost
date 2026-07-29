package quarantine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/quarantine"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

type ambiente struct {
	vault *quarantine.Vault
	store *store.Store
	site  string
	cofre string
}

func montar(t *testing.T) ambiente {
	t.Helper()
	base := t.TempDir()
	site := filepath.Join(base, "public_html")
	cofre := filepath.Join(base, "quarantine")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	st, err := store.Open(context.Background(), filepath.Join(base, "estado.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Default().Quarantine
	return ambiente{
		vault: quarantine.New(cofre, cfg, st),
		store: st,
		site:  site,
		cofre: cofre,
	}
}

func criarArquivo(t *testing.T, dir, nome, conteudo string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, nome)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(conteudo), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	sha, err := baseline.HashFile(path)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return path, sha
}

// SC-003: round-trip byte a byte ------------------------------------------------

func TestRoundTripDevolveOArquivoByteAByte(t *testing.T) {
	// SC-003: 100% dos testes de quarentenar -> restaurar -> comparar hash
	// tem que passar. E a promessa que torna a automacao aceitavel.
	env := montar(t)
	ctx := context.Background()

	conteudos := []string{
		"<?php echo 'pequeno';",
		strings.Repeat("A", 1<<20),                         // 1 MiB
		"linha1\nlinha2\r\nbinario:\x00\x01\x02\xff\xfe\n", // binario e CRLF
		"",                              // arquivo vazio
		"acentuação e emoji: ção 🎯 ção", // UTF-8 multibyte
	}

	for i, conteudo := range conteudos {
		nome := filepath.Join("wp-content", "uploads", "amostra"+string(rune('a'+i))+".php")
		path, shaOriginal := criarArquivo(t, env.site, nome, conteudo)

		item, err := env.vault.Quarantine(ctx, "v_1", path, shaOriginal)
		if err != nil {
			t.Fatalf("Quarantine(%d): %v", i, err)
		}

		// O original saiu do lugar.
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("caso %d: o arquivo original ainda esta no lugar", i)
		}

		restaurado, err := env.vault.Restore(ctx, item.Ref)
		if err != nil {
			t.Fatalf("Restore(%d): %v", i, err)
		}
		if restaurado.Status != store.QuarantineRestored {
			t.Errorf("caso %d: status apos restore: %q", i, restaurado.Status)
		}

		shaFinal, err := baseline.HashFile(path)
		if err != nil {
			t.Fatalf("hash apos restore (%d): %v", i, err)
		}
		if shaFinal != shaOriginal {
			t.Errorf("caso %d: o arquivo NAO voltou byte a byte: %s -> %s", i, shaOriginal, shaFinal)
		}

		volta, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("lendo restaurado (%d): %v", i, err)
		}
		if string(volta) != conteudo {
			t.Errorf("caso %d: conteudo diferente apos restauracao", i)
		}
	}
}

func TestRestaurePreservaPermissoes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissoes POSIX nao se aplicam no Windows (D-002)")
	}
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	item, err := env.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if _, err := env.vault.Restore(ctx, item.Ref); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("permissao nao foi restaurada: esperado 0640, veio %v", info.Mode().Perm())
	}
}

// FR-018: re-hash antes de agir ------------------------------------------------

func TestRecusaQuarentenarSeOArquivoMudouDesdeOScan(t *testing.T) {
	// Edge case explicito da spec: arquivo que muda entre o scan e a acao.
	// Nesses minutos o proprio usuario pode ter limpado o arquivo.
	env := montar(t)
	ctx := context.Background()

	path, shaAntigo := criarArquivo(t, env.site, "x.php", "<?php // versao suja")
	// O usuario corrige o arquivo antes de a acao rodar.
	if err := os.WriteFile(path, []byte("<?php // versao limpa"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := env.vault.Quarantine(ctx, "v_1", path, shaAntigo)
	if !errors.Is(err, quarantine.ErrHashMismatch) {
		t.Fatalf("esperava ErrHashMismatch, veio %v", err)
	}
	// E, principalmente: o arquivo continua no lugar.
	if _, err := os.Stat(path); err != nil {
		t.Error("o arquivo do usuario foi mexido apesar do hash divergente")
	}
	conteudo, _ := os.ReadFile(path)
	if string(conteudo) != "<?php // versao limpa" {
		t.Error("o conteudo corrigido pelo usuario foi alterado")
	}
}

func TestArquivoQueSumiuAntesDaAcaoNaoDerruba(t *testing.T) {
	env := montar(t)
	ctx := context.Background()

	_, err := env.vault.Quarantine(ctx, "v_1", filepath.Join(env.site, "nao-existe.php"), "")
	if err == nil {
		t.Fatal("esperava erro")
	}
	if errors.Is(err, quarantine.ErrHashMismatch) {
		t.Error("arquivo ausente nao e o mesmo que arquivo alterado")
	}
}

// Neutralizacao -----------------------------------------------------------------

func TestArquivoNoCofreEhNeutralizado(t *testing.T) {
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "backdoor.php", "<?php // amostra")
	item, err := env.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	// Extensao neutralizada: se o cofre acabar dentro de um diretorio servido
	// pela web, o arquivo nao pode ser executado pelo servidor.
	if filepath.Ext(item.VaultPath) != ".quarantined" {
		t.Errorf("a extensao nao foi neutralizada: %s", item.VaultPath)
	}
	if strings.HasSuffix(item.VaultPath, ".php") {
		t.Errorf("o arquivo no cofre ainda tem extensao executavel: %s", item.VaultPath)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(item.VaultPath)
		if err != nil {
			t.Fatalf("stat do cofre: %v", err)
		}
		if info.Mode().Perm()&0o111 != 0 {
			t.Errorf("o arquivo no cofre manteve permissao de execucao: %v", info.Mode().Perm())
		}
	}
}

func TestMetadadosDeRestauracaoSaoRegistrados(t *testing.T) {
	// Sem estes metadados o arquivo no cofre e lixo indecifravel.
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "wp-content/x.php", "<?php")
	item, err := env.vault.Quarantine(ctx, "v_42", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	gravado, err := env.store.GetQuarantineItem(ctx, item.Ref)
	if err != nil {
		t.Fatalf("GetQuarantineItem: %v", err)
	}
	if gravado.OriginalPath != path {
		t.Errorf("caminho original perdido: %q", gravado.OriginalPath)
	}
	if gravado.SHA256 != sha {
		t.Errorf("hash perdido: %q", gravado.SHA256)
	}
	if gravado.VerdictID != "v_42" {
		t.Errorf("veredito de origem perdido: %q", gravado.VerdictID)
	}
	if gravado.Perms == "" {
		t.Error("permissoes originais nao foram registradas")
	}
	if gravado.RetentionUntil.IsZero() {
		t.Error("a retencao nao foi calculada")
	}
}

// Falhas do cofre ---------------------------------------------------------------

func TestCofreSemPermissaoNaoApagaOArquivoDoUsuario(t *testing.T) {
	// Este e O teste que impede a ferramenta de destruir um site: se o cofre
	// nao aceita a copia, o original NAO pode ser removido.
	if runtime.GOOS == "windows" {
		t.Skip("permissoes POSIX nao se aplicam no Windows (D-002)")
	}
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php // conteudo importante")

	// Cofre existente porem sem permissao de escrita.
	if err := os.MkdirAll(env.cofre, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(env.cofre, 0o700) })

	_, err := env.vault.Quarantine(ctx, "v_1", path, sha)
	if err == nil {
		t.Fatal("esperava falha com cofre sem permissao")
	}
	if !errors.Is(err, quarantine.ErrVaultUnwritable) {
		t.Errorf("esperava ErrVaultUnwritable, veio %v", err)
	}

	// O arquivo do usuario continua intacto.
	if _, err := os.Stat(path); err != nil {
		t.Fatal("o arquivo do usuario foi removido apesar da falha no cofre")
	}
	shaFinal, _ := baseline.HashFile(path)
	if shaFinal != sha {
		t.Error("o arquivo do usuario foi alterado")
	}
}

func TestRestoreNaoSobrescreveArquivoExistente(t *testing.T) {
	// Se ha arquivo no caminho original, ele pode ser a versao limpa que o
	// usuario ja repos.
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php // sujo")
	item, err := env.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if err := os.WriteFile(path, []byte("<?php // reposto pelo usuario"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = env.vault.Restore(ctx, item.Ref)
	if !errors.Is(err, quarantine.ErrRestoreTargetExists) {
		t.Fatalf("esperava ErrRestoreTargetExists, veio %v", err)
	}
	conteudo, _ := os.ReadFile(path)
	if string(conteudo) != "<?php // reposto pelo usuario" {
		t.Error("o arquivo reposto pelo usuario foi sobrescrito")
	}
}

func TestRestoreDetectaCofreCorrompido(t *testing.T) {
	// Restaurar um arquivo diferente do que foi quarentenado seria pior que
	// nao restaurar.
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php // original")
	item, err := env.vault.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if err := os.Chmod(item.VaultPath, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.WriteFile(item.VaultPath, []byte("conteudo trocado"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = env.vault.Restore(ctx, item.Ref)
	if !errors.Is(err, quarantine.ErrVaultCorrupted) {
		t.Fatalf("esperava ErrVaultCorrupted, veio %v", err)
	}
}

func TestRestaurarDuasVezesFalha(t *testing.T) {
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php")
	item, _ := env.vault.Quarantine(ctx, "v_1", path, sha)
	if _, err := env.vault.Restore(ctx, item.Ref); err != nil {
		t.Fatalf("primeira restauracao: %v", err)
	}
	if _, err := env.vault.Restore(ctx, item.Ref); !errors.Is(err, quarantine.ErrNotInVault) {
		t.Errorf("esperava ErrNotInVault, veio %v", err)
	}
}

// Retencao e purga ---------------------------------------------------------------

func TestPurgaRecusaItemDentroDaRetencao(t *testing.T) {
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php")
	item, _ := env.vault.Quarantine(ctx, "v_1", path, sha)

	if err := env.vault.Purge(ctx, item.Ref, false); err == nil {
		t.Fatal("purga dentro da retencao deveria ser recusada")
	}
	if _, err := os.Stat(item.VaultPath); err != nil {
		t.Error("a copia no cofre foi removida apesar da recusa")
	}
}

func TestPurgaManualIgnoraRetencao(t *testing.T) {
	// A constituicao permite purga definitiva por acao manual do usuario.
	env := montar(t)
	ctx := context.Background()

	path, sha := criarArquivo(t, env.site, "x.php", "<?php")
	item, _ := env.vault.Quarantine(ctx, "v_1", path, sha)

	if err := env.vault.Purge(ctx, item.Ref, true); err != nil {
		t.Fatalf("Purge(force): %v", err)
	}
	if _, err := os.Stat(item.VaultPath); !os.IsNotExist(err) {
		t.Error("a copia deveria ter sido removida")
	}
	gravado, _ := env.store.GetQuarantineItem(ctx, item.Ref)
	if gravado.Status != store.QuarantinePurged {
		t.Errorf("status: %q", gravado.Status)
	}
}

func TestPurgeExpiredSoPegaOsVencidos(t *testing.T) {
	env := montar(t)
	ctx := context.Background()

	pathVelho, shaVelho := criarArquivo(t, env.site, "velho.php", "<?php // velho")
	pathNovo, shaNovo := criarArquivo(t, env.site, "novo.php", "<?php // novo")

	// O item velho foi quarentenado ha 60 dias (retencao padrao: 30).
	passado := time.Now().AddDate(0, 0, -60)
	velho := quarantine.New(env.cofre, config.Default().Quarantine, env.store).
		WithClock(func() time.Time { return passado })
	itemVelho, err := velho.Quarantine(ctx, "v_1", pathVelho, shaVelho)
	if err != nil {
		t.Fatalf("Quarantine(velho): %v", err)
	}
	itemNovo, err := env.vault.Quarantine(ctx, "v_2", pathNovo, shaNovo)
	if err != nil {
		t.Fatalf("Quarantine(novo): %v", err)
	}

	n, err := env.vault.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("esperava 1 item purgado, veio %d", n)
	}

	venc, _ := env.store.GetQuarantineItem(ctx, itemVelho.Ref)
	if venc.Status != store.QuarantinePurged {
		t.Errorf("o item vencido deveria ter sido purgado, esta %q", venc.Status)
	}
	recente, _ := env.store.GetQuarantineItem(ctx, itemNovo.Ref)
	if recente.Status != store.QuarantineActive {
		t.Errorf("o item recente nao pode ser purgado, esta %q", recente.Status)
	}
	if _, err := os.Stat(itemNovo.VaultPath); err != nil {
		t.Error("a copia do item recente foi removida")
	}
}

func TestRetencaoZeroNuncaExpira(t *testing.T) {
	// Melhor ocupar disco que apagar arquivo por engano.
	env := montar(t)
	ctx := context.Background()

	cfg := config.Default().Quarantine
	cfg.RetentionDays = 0
	v := quarantine.New(env.cofre, cfg, env.store)

	path, sha := criarArquivo(t, env.site, "x.php", "<?php")
	item, err := v.Quarantine(ctx, "v_1", path, sha)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if !item.RetentionUntil.IsZero() {
		t.Error("com retencao 0 o item nao deveria ter data de expiracao")
	}

	n, err := v.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("item sem expiracao nao pode ser purgado automaticamente, veio %d", n)
	}
}

// Verificacao de integridade -------------------------------------------------------

func TestVerifyDetectaCopiaCorrompida(t *testing.T) {
	// A promessa de reversibilidade so vale se puder ser conferida antes da
	// hora em que o usuario precisa restaurar.
	env := montar(t)
	ctx := context.Background()

	pathOK, shaOK := criarArquivo(t, env.site, "ok.php", "<?php // ok")
	pathRuim, shaRuim := criarArquivo(t, env.site, "ruim.php", "<?php // ruim")
	if _, err := env.vault.Quarantine(ctx, "v_1", pathOK, shaOK); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	itemRuim, err := env.vault.Quarantine(ctx, "v_2", pathRuim, shaRuim)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	_ = os.Chmod(itemRuim.VaultPath, 0o600)
	if err := os.WriteFile(itemRuim.VaultPath, []byte("corrompido"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	problemas, err := env.vault.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(problemas) != 1 {
		t.Fatalf("esperava 1 problema, veio %d: %v", len(problemas), problemas)
	}
	if !strings.Contains(problemas[0], itemRuim.Ref) {
		t.Errorf("o problema deveria citar o item: %q", problemas[0])
	}
}

func TestLevelAllowsActionSoConfirmed(t *testing.T) {
	if !quarantine.LevelAllowsAction(schema.LevelConfirmed) {
		t.Error("confirmed deveria autorizar acao")
	}
	for _, l := range []schema.Level{schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean, ""} {
		if quarantine.LevelAllowsAction(l) {
			t.Errorf("nivel %q nao pode autorizar acao automatica", l)
		}
	}
}
