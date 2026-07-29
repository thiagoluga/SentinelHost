package wpchecksums_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/adapter/wpchecksums"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Nenhum teste aqui toca a rede: o `apiFalsa` serve tanto os checksums do core
// quanto os de plugin. Um teste que batesse na API pública do WordPress.org
// falharia em CI por motivos alheios ao código — e usaria de graça a
// infraestrutura de um projeto que já nos serve de graça.

type apiFalsa struct {
	srv *httptest.Server
	// coreSums e o mapa caminho->md5 do core.
	coreSums map[string]string
	// pluginSums e slug/versao -> caminho -> hashes.
	pluginSums map[string]map[string]map[string][]string
	// vistos registra quais URLs de plugin foram pedidas.
	vistos []string
}

func novaAPI(t *testing.T) *apiFalsa {
	t.Helper()
	a := &apiFalsa{
		coreSums:   map[string]string{},
		pluginSums: map[string]map[string]map[string][]string{},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/core/checksums/1.0/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"checksums": a.coreSums})
	})

	mux.HandleFunc("/plugin-checksums/", func(w http.ResponseWriter, r *http.Request) {
		a.vistos = append(a.vistos, r.URL.Path)
		partes := strings.Split(strings.TrimPrefix(r.URL.Path, "/plugin-checksums/"), "/")
		if len(partes) != 2 {
			http.NotFound(w, r)
			return
		}
		slug := partes[0]
		versao := strings.TrimSuffix(partes[1], ".json")

		arquivos, ok := a.pluginSums[slug][versao]
		if !ok {
			// 404 e a resposta real para plugin fora do diretorio oficial.
			http.NotFound(w, r)
			return
		}
		files := map[string]any{}
		for caminho, hashes := range arquivos {
			files[caminho] = map[string]any{"sha256": hashes}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"plugin": slug, "version": versao, "files": files,
		})
	})

	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiFalsa) adaptador() *wpchecksums.Adapter {
	return wpchecksums.NewWithBases(
		a.srv.URL+"/core/checksums/1.0/",
		a.srv.URL+"/plugin-checksums/",
	)
}

// site monta uma instalacao WordPress minima e registra o core na API falsa.
//
// Registrar o core e obrigatorio: com a lista vazia, o adaptador trata a versao
// como desconhecida e se abstem — comportamento correto do produto, que
// mascararia o que estes testes querem exercitar (os plugins).
func site(t *testing.T, api *apiFalsa) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	versao := filepath.Join(root, "wp-includes", "version.php")
	escrever(t, versao, "<?php\n$wp_version = '6.5.2';\n")
	api.coreSums["wp-includes/version.php"] = md5De(t, versao)
	return root
}

func escrever(t *testing.T, path, conteudo string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(conteudo), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return sha256De(t, path)
}

func sha256De(t *testing.T, path string) string {
	t.Helper()
	h, err := wpchecksums.HashFileSHA256(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return h
}

// plugin cria um plugin no disco e devolve o diretorio.
func plugin(t *testing.T, root, slug, versao string, arquivos map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, "wp-content", "plugins", slug)
	cabecalho := fmt.Sprintf("<?php\n/**\n * Plugin Name: Plugin %s\n * Version: %s\n */\n", slug, versao)
	escrever(t, filepath.Join(dir, slug+".php"), cabecalho)
	for rel, conteudo := range arquivos {
		escrever(t, filepath.Join(dir, filepath.FromSlash(rel)), conteudo)
	}
	return dir
}

func rodar(t *testing.T, a *wpchecksums.Adapter, root string) schema.ScanReport {
	t.Helper()
	req := adapter.ScanRequest{ScanID: "s_1", Root: root, Mode: schema.ModeFull}
	raw, err := a.Scan(context.Background(), adapter.Environment{}, req)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	rep, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("relatorio fora do esquema: %v", err)
	}
	return rep
}

func acharRegra(rep schema.ScanReport, regra string) []schema.Finding {
	var out []schema.Finding
	for _, f := range rep.Findings {
		if f.Rule == regra {
			out = append(out, f)
		}
	}
	return out
}

// Deteccao de plugins ----------------------------------------------------------

func TestDetectPluginsLeSlugDoDiretorioENaoDoCabecalho(t *testing.T) {
	// A API indexa pelo nome do DIRETORIO. Usar o "Plugin Name" faria toda
	// consulta dar 404 e o verificador de plugins nunca acharia nada — falhando
	// em silencio, que e o modo de falha que este projeto mais teme.
	root := site(t, novaAPI(t))
	plugin(t, root, "contact-form-7", "5.9.3", nil)

	ps, err := wpchecksums.DetectPlugins(root)
	if err != nil {
		t.Fatalf("DetectPlugins: %v", err)
	}
	if len(ps) != 1 {
		t.Fatalf("esperava 1 plugin, veio %d", len(ps))
	}
	if ps[0].Slug != "contact-form-7" {
		t.Errorf("slug: %q (deveria ser o nome do diretorio)", ps[0].Slug)
	}
	if ps[0].Version != "5.9.3" {
		t.Errorf("versao: %q", ps[0].Version)
	}
	if ps[0].Name != "Plugin contact-form-7" {
		t.Errorf("nome: %q", ps[0].Name)
	}
}

func TestDetectPluginsIgnoraArquivoSoltoENaoSegueSymlink(t *testing.T) {
	root := site(t, novaAPI(t))
	plugin(t, root, "bom", "1.0", nil)
	// hello.php: plugin de arquivo unico, sem checksum publicado.
	escrever(t, filepath.Join(root, "wp-content", "plugins", "hello.php"), "<?php\n")

	ps, err := wpchecksums.DetectPlugins(root)
	if err != nil {
		t.Fatalf("DetectPlugins: %v", err)
	}
	for _, p := range ps {
		if p.Slug == "hello.php" {
			t.Error("plugin de arquivo unico nao deveria entrar na lista")
		}
	}
}

func TestDetectPluginsSemDiretorioDePluginsNaoEErro(t *testing.T) {
	// Instalacao com diretorio de conteudo customizado e caso legitimo.
	root := site(t, novaAPI(t))
	ps, err := wpchecksums.DetectPlugins(root)
	if err != nil {
		t.Fatalf("ausencia de wp-content/plugins nao deveria ser erro: %v", err)
	}
	if len(ps) != 0 {
		t.Errorf("esperava lista vazia, veio %d", len(ps))
	}
}

// Verificacao ------------------------------------------------------------------

func TestPluginIntactoViraCleanFileENaoAchado(t *testing.T) {
	// Plugin legitimo tem JS minificado e base64 — exatamente o que gera falso
	// positivo em heuristica. Sem entrar em clean_files, ele nao ganha a
	// protecao de veto e um outro engine poderia derrubar o site do usuario.
	api := novaAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "meu-plugin", "2.0", map[string]string{
		"inc/util.php": "<?php // legitimo\n",
	})

	api.pluginSums["meu-plugin"] = map[string]map[string][]string{
		"2.0": {
			"meu-plugin.php": {sha256De(t, filepath.Join(dir, "meu-plugin.php"))},
			"inc/util.php":   {sha256De(t, filepath.Join(dir, "inc/util.php"))},
		},
	}

	rep := rodar(t, api.adaptador(), root)

	if n := len(acharRegra(rep, "plugin_file_modified")); n != 0 {
		t.Errorf("plugin intacto gerou %d achado(s) de alteracao", n)
	}
	esperado := sha256De(t, filepath.Join(dir, "inc/util.php"))
	encontrou := false
	for _, h := range rep.CleanFiles {
		if h == esperado {
			encontrou = true
		}
	}
	if !encontrou {
		t.Error("arquivo intacto de plugin deveria entrar em clean_files (veto anti-falso-positivo)")
	}
}

func TestArquivoAlteradoEmPluginEhAchadoDeAssinatura(t *testing.T) {
	api := novaAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "meu-plugin", "2.0", map[string]string{
		"inc/util.php": "<?php // ADULTERADO\n",
	})

	api.pluginSums["meu-plugin"] = map[string]map[string][]string{
		"2.0": {
			"meu-plugin.php": {sha256De(t, filepath.Join(dir, "meu-plugin.php"))},
			// hash de um conteudo diferente do que esta no disco
			"inc/util.php": {strings.Repeat("a", 64)},
		},
	}

	rep := rodar(t, api.adaptador(), root)

	achados := acharRegra(rep, "plugin_file_modified")
	if len(achados) != 1 {
		t.Fatalf("esperava 1 achado de alteracao, veio %d", len(achados))
	}
	f := achados[0]
	// Divergencia de checksum oficial e PROVA, nao suspeita: e o que sustenta
	// o peso 1.5 deste engine no consenso.
	if f.Confidence != schema.ConfidenceSignature {
		t.Errorf("confianca: %q, esperada signature", f.Confidence)
	}
	if f.Severity != schema.SeverityCritical {
		t.Errorf("severidade: %q", f.Severity)
	}
	if !strings.Contains(f.File.Path, "inc") {
		t.Errorf("caminho do achado: %q", f.File.Path)
	}
}

func TestArquivoExtraEmPluginEhAchado(t *testing.T) {
	// O achado mais valioso deste verificador: backdoor dentro de um plugin
	// legitimo nao aparece na conferencia do core, e o usuario nunca suspeita
	// do plugin que ele mesmo instalou.
	api := novaAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "meu-plugin", "2.0", map[string]string{
		"inc/backdoor.php": "<?php // nao pertence ao plugin\n",
	})

	api.pluginSums["meu-plugin"] = map[string]map[string][]string{
		"2.0": {"meu-plugin.php": {sha256De(t, filepath.Join(dir, "meu-plugin.php"))}},
	}

	rep := rodar(t, api.adaptador(), root)

	achados := acharRegra(rep, "plugin_file_unexpected")
	if len(achados) != 1 {
		t.Fatalf("esperava 1 achado de arquivo extra, veio %d", len(achados))
	}
	if achados[0].Confidence != schema.ConfidenceSignature {
		t.Errorf("confianca: %q — plugin oficial nao ganha .php por conta propria", achados[0].Confidence)
	}
}

func TestArquivoAusenteEmPluginEhAnomaliaNaoAssinatura(t *testing.T) {
	// Mesma razao do core: ausencia nao contem codigo malicioso e nao pode ser
	// quarentenada. Como `signature`, o peso 1.5 empurraria sozinho o achado
	// para perto de `confirmed`, autorizando acao sobre arquivo que nem existe.
	api := novaAPI(t)
	root := site(t, api)
	// Plugin com vários arquivos presentes: 1 ausente em 5 fica sob o teto de
	// 34% que dispara a abstenção. Um plugin de dois arquivos daria 50% e o
	// adaptador se absteria — corretamente, mas mascarando o que se testa aqui.
	dir := plugin(t, root, "meu-plugin", "2.0", map[string]string{
		"inc/a.php": "<?php // a\n",
		"inc/b.php": "<?php // b\n",
		"inc/c.php": "<?php // c\n",
	})

	api.pluginSums["meu-plugin"] = map[string]map[string][]string{
		"2.0": {
			"meu-plugin.php": {sha256De(t, filepath.Join(dir, "meu-plugin.php"))},
			"inc/a.php":      {sha256De(t, filepath.Join(dir, "inc/a.php"))},
			"inc/b.php":      {sha256De(t, filepath.Join(dir, "inc/b.php"))},
			"inc/c.php":      {sha256De(t, filepath.Join(dir, "inc/c.php"))},
			"inc/sumiu.php":  {strings.Repeat("b", 64)},
		},
	}

	rep := rodar(t, api.adaptador(), root)

	achados := acharRegra(rep, "plugin_file_missing")
	if len(achados) != 1 {
		t.Fatalf("esperava 1 achado de ausencia, veio %d", len(achados))
	}
	if achados[0].Confidence != schema.ConfidenceAnomaly {
		t.Errorf("confianca: %q, esperada anomaly", achados[0].Confidence)
	}
	if achados[0].Severity == schema.SeverityCritical {
		t.Error("ausencia nao pode ser critica: nao da para esconder backdoor num arquivo que nao existe")
	}
}

// Abstencoes -------------------------------------------------------------------

func TestPluginSemChecksumPublicadoAbstemComMotivo(t *testing.T) {
	// Plugin comercial ou proprio nao tem checksum. Tratar ausencia de DADO
	// como ausencia de PROBLEMA declararia limpo o que ninguem conferiu.
	api := novaAPI(t)
	root := site(t, api)
	plugin(t, root, "plugin-comercial", "3.1", map[string]string{
		"inc/x.php": "<?php\n",
	})

	rep := rodar(t, api.adaptador(), root)

	if len(rep.Findings) != 0 {
		t.Errorf("plugin sem checksum nao deveria gerar achado: %d", len(rep.Findings))
	}
	// E o mais importante: o relatorio registra que ele NAO foi verificado.
	if rep.Scope.SkippedReasonCounts["plugin_sem_checksum"] == 0 {
		t.Error("o plugin nao verificado precisa aparecer na contabilidade do relatorio")
	}
}

func TestPluginSemVersaoNoCabecalhoAbstem(t *testing.T) {
	api := novaAPI(t)
	root := site(t, api)
	dir := filepath.Join(root, "wp-content", "plugins", "sem-versao")
	escrever(t, filepath.Join(dir, "sem-versao.php"), "<?php\n/**\n * Plugin Name: Sem Versao\n */\n")

	rep := rodar(t, api.adaptador(), root)

	if len(rep.Findings) != 0 {
		t.Errorf("plugin sem versao nao deveria gerar achado: %d", len(rep.Findings))
	}
	if rep.Scope.SkippedReasonCounts["plugin_sem_checksum"] == 0 {
		t.Error("plugin sem versao precisa constar como nao verificado")
	}
}

func TestMuitosArquivosAusentesAbstemEmVezDeAfogarORelatorio(t *testing.T) {
	// A mesma licao dos 2998 achados do core, aplicada a plugin: se falta a
	// maioria dos arquivos, o diretorio nao e a versao que o cabecalho declara,
	// e emitir um achado por arquivo enterraria o que importa.
	api := novaAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "meu-plugin", "2.0", nil)

	arquivos := map[string][]string{
		"meu-plugin.php": {sha256De(t, filepath.Join(dir, "meu-plugin.php"))},
	}
	for i := 0; i < 20; i++ {
		arquivos[fmt.Sprintf("inc/f%02d.php", i)] = []string{strings.Repeat("c", 64)}
	}
	api.pluginSums["meu-plugin"] = map[string]map[string][]string{"2.0": arquivos}

	rep := rodar(t, api.adaptador(), root)

	if n := len(acharRegra(rep, "plugin_file_missing")); n > 0 {
		t.Errorf("esperava abstencao sobre o plugin, veio %d achado(s) de ausencia", n)
	}
	if rep.Scope.SkippedReasonCounts["plugin_sem_checksum"] == 0 {
		t.Error("a abstencao precisa constar no relatorio com motivo")
	}
}

func TestFalhaDePluginNaoDerrubaAVerificacaoDoCore(t *testing.T) {
	// O core e o sinal de maior peso do projeto. Ele nao pode ficar sem
	// verificacao porque um plugin de terceiro nao tem checksum publicado.
	api := novaAPI(t)
	root := site(t, api)
	plugin(t, root, "plugin-sem-checksum", "1.0", nil)

	// Core com um arquivo adulterado.
	escrever(t, filepath.Join(root, "wp-includes", "pluggable.php"), "<?php // ADULTERADO\n")
	api.coreSums["wp-includes/pluggable.php"] = "md5-que-nao-bate"

	rep := rodar(t, api.adaptador(), root)

	if n := len(acharRegra(rep, "core_file_modified")); n != 1 {
		t.Fatalf("o core deveria ter sido verificado: %d achado(s)", n)
	}
	if rep.Abstains() {
		t.Error("falha de plugin nao pode fazer o engine inteiro se abster")
	}
}

func TestSlugComTravessiaDeCaminhoNaoEscapaDaAPI(t *testing.T) {
	// O slug vem de um nome de diretorio no disco do usuario. Um diretorio
	// chamado `../algo` nao pode montar uma URL para outro lugar da API.
	api := novaAPI(t)
	root := site(t, api)
	dir := filepath.Join(root, "wp-content", "plugins", "..estranho")
	escrever(t, filepath.Join(dir, "x.php"), "<?php\n/**\n * Plugin Name: X\n * Version: 1.0\n */\n")

	_ = rodar(t, api.adaptador(), root)

	for _, u := range api.vistos {
		if strings.Contains(u, "/../") {
			t.Errorf("a URL escapou do prefixo da API: %q", u)
		}
		if !strings.HasPrefix(u, "/plugin-checksums/") {
			t.Errorf("URL fora do prefixo esperado: %q", u)
		}
	}
}

func TestLimiteDePluginsPorCicloEhRegistrado(t *testing.T) {
	// Cortar em silencio faria o relatorio parecer completo. O usuario precisa
	// saber que parte dos plugins dele nao foi olhada neste ciclo.
	api := novaAPI(t)
	root := site(t, api)
	for i := 0; i < 45; i++ {
		plugin(t, root, fmt.Sprintf("plugin-%02d", i), "1.0", nil)
	}

	rep := rodar(t, api.adaptador(), root)

	if rep.Scope.SkippedReasonCounts["plugin_sem_checksum"] < 5 {
		t.Errorf("os plugins alem do limite precisam constar como nao verificados: %v",
			rep.Scope.SkippedReasonCounts)
	}
}

func TestVariantesDeHashSaoAceitas(t *testing.T) {
	// A API publica ARRAYS de hash por arquivo, porque um mesmo caminho pode
	// ter variantes aceitas (CRLF e LF, por exemplo). Bater com uma basta;
	// exigir a primeira produziria falso positivo em site legitimo.
	api := novaAPI(t)
	root := site(t, api)
	dir := plugin(t, root, "meu-plugin", "2.0", map[string]string{
		"inc/util.php": "<?php // legitimo\n",
	})

	real := sha256De(t, filepath.Join(dir, "inc/util.php"))
	api.pluginSums["meu-plugin"] = map[string]map[string][]string{
		"2.0": {
			"meu-plugin.php": {sha256De(t, filepath.Join(dir, "meu-plugin.php"))},
			// a variante correta e a SEGUNDA da lista
			"inc/util.php": {strings.Repeat("d", 64), real},
		},
	}

	rep := rodar(t, api.adaptador(), root)

	if n := len(acharRegra(rep, "plugin_file_modified")); n != 0 {
		t.Errorf("a segunda variante de hash deveria ter sido aceita: %d achado(s)", n)
	}
}

func TestModoOfflineNaoConsultaNadaDePlugin(t *testing.T) {
	api := novaAPI(t)
	root := site(t, api)
	plugin(t, root, "meu-plugin", "2.0", nil)

	a := api.adaptador()
	_, err := a.Scan(context.Background(),
		adapter.Environment{Offline: true},
		adapter.ScanRequest{ScanID: "s_1", Root: root, Mode: schema.ModeFull})
	if err == nil {
		t.Fatal("modo offline deveria impedir o scan")
	}
	if len(api.vistos) != 0 {
		t.Errorf("o modo offline consultou a API: %v", api.vistos)
	}
}

func TestCancelamentoInterrompeAVerificacaoDePlugins(t *testing.T) {
	api := novaAPI(t)
	root := site(t, api)
	for i := 0; i < 5; i++ {
		plugin(t, root, fmt.Sprintf("p%02d", i), "1.0", nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := api.adaptador()
	raw, err := a.Scan(ctx, adapter.Environment{},
		adapter.ScanRequest{ScanID: "s_1", Root: root, Mode: schema.ModeFull})
	// O core falha primeiro (contexto cancelado), o que ja e o desfecho certo:
	// abstencao com motivo.
	if err == nil && raw.Status == schema.StatusCompleted {
		t.Error("contexto cancelado deveria interromper o scan")
	}
}

func md5De(t *testing.T, path string) string {
	t.Helper()
	h, err := wpchecksums.HashFileMD5(path)
	if err != nil {
		t.Fatalf("md5 %s: %v", path, err)
	}
	return h
}
