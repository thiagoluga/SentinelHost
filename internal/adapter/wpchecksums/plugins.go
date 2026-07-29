package wpchecksums

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Integridade de PLUGINS, a segunda metade do FR-005 ("core e, quando
// disponível, plugins").
//
// Plugin abandonado é o vetor de invasão mais comum em WordPress, e um plugin
// legítimo com um arquivo alterado é o esconderijo preferido de backdoor: ele
// não aparece na verificação do core e o usuário nunca suspeita de um plugin
// que ele mesmo instalou.
//
// A API é diferente da do core, e a diferença importa:
//   - o core tem UMA lista para a instalação inteira;
//   - cada plugin tem a sua, publicada por versão, e **só se ele veio do
//     diretório oficial**. Plugin comercial ou próprio não tem checksum
//     nenhum — e nesse caso o adaptador se abstém sobre ele em vez de tratar
//     ausência de dado como ausência de problema.

// PluginsAPIBase publica checksums por plugin e versão.
const PluginsAPIBase = "https://downloads.wordpress.org/plugin-checksums/"

// maxPlugins limita quantos plugins são verificados num ciclo.
//
// Cada plugin custa uma requisição HTTP. Um site com 80 plugins geraria 80
// requisições por ciclo — carga desnecessária na API pública de um projeto
// que nos serve de graça, e tempo de ciclo que o Princípio IV não autoriza.
const maxPlugins = 40

// maxMissingRatioPlugin é o teto de arquivos ausentes antes de o adaptador
// concluir que aquele diretório não é a versão que ele pensa que é.
//
// Mais frouxo que o do core (10%) de propósito: plugin costuma ter poucos
// arquivos, e um único ausente em cinco já daria 20% sem significar nada.
const maxMissingRatioPlugin = 0.34

var (
	// Cabeçalhos de plugin do WordPress. `(?i)` porque o padrão do WordPress é
	// tolerante a maiúsculas e plugins reais abusam disso.
	pluginNameRe    = regexp.MustCompile(`(?i)^[ \t/*#@]*Plugin Name:\s*(.+)$`)
	pluginVersionRe = regexp.MustCompile(`(?i)^[ \t/*#@]*Version:\s*(.+)$`)
)

// PluginInstall é um plugin encontrado no disco.
type PluginInstall struct {
	// Slug é o nome do diretório, que é o que a API indexa.
	Slug string `json:"slug"`
	// Dir é o caminho absoluto do diretório do plugin.
	Dir string `json:"dir"`
	// Name é o cabeçalho "Plugin Name", só para exibição.
	Name string `json:"name"`
	// Version é o cabeçalho "Version". Vazio impede a verificação: sem versão
	// não há checksum a consultar.
	Version string `json:"version"`
}

// DetectPlugins lista os plugins instalados na raiz.
//
// O slug é o nome do DIRETÓRIO, não o do cabeçalho: é assim que a API indexa,
// e é o que o WordPress usa para identificar o plugin.
func DetectPlugins(root string) ([]PluginInstall, error) {
	base := filepath.Join(root, "wp-content", "plugins")
	entradas, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Site sem wp-content/plugins não é erro: pode ser uma instalação
			// com diretório de conteúdo customizado.
			return nil, nil
		}
		return nil, fmt.Errorf("lendo %s: %w", base, err)
	}

	var out []PluginInstall
	for _, e := range entradas {
		if !e.IsDir() {
			// Plugin de arquivo único (hello.php) não tem checksum publicado.
			continue
		}
		// Symlink nunca é seguido, aqui como no walker: um link em
		// wp-content/plugins poderia apontar para fora da raiz autorizada.
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		dir := filepath.Join(base, e.Name())
		p := PluginInstall{Slug: e.Name(), Dir: dir}
		if nome, versao := lerCabecalhoPlugin(dir); versao != "" {
			p.Name, p.Version = nome, versao
		}
		out = append(out, p)
	}

	// Ordem estável: o relatório de dois ciclos não pode divergir por ordem de
	// leitura de diretório.
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// lerCabecalhoPlugin procura "Plugin Name" e "Version" nos arquivos PHP do
// primeiro nível do diretório.
//
// O WordPress lê só os 8 KiB iniciais do arquivo principal, e o cabeçalho fica
// sempre no topo — ler o arquivo inteiro seria desperdício num diretório que
// pode ter megabytes de código.
func lerCabecalhoPlugin(dir string) (nome, versao string) {
	entradas, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}

	// O arquivo principal costuma ter o nome do diretório; tenta esse antes de
	// varrer os demais, porque é o caso esmagadoramente comum.
	candidatos := make([]string, 0, len(entradas))
	principal := filepath.Base(dir) + ".php"
	for _, e := range entradas {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".php") {
			continue
		}
		if e.Name() == principal {
			candidatos = append([]string{e.Name()}, candidatos...)
			continue
		}
		candidatos = append(candidatos, e.Name())
	}

	for _, arq := range candidatos {
		n, v := cabecalhoDe(filepath.Join(dir, arq))
		if v != "" {
			return n, v
		}
	}
	return "", ""
}

func cabecalhoDe(path string) (nome, versao string) {
	f, err := os.Open(path) // caminho derivado da raiz configurada
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(io.LimitReader(f, 8<<10))
	for sc.Scan() {
		linha := sc.Text()
		if nome == "" {
			if m := pluginNameRe.FindStringSubmatch(linha); m != nil {
				nome = strings.TrimSpace(m[1])
			}
		}
		if versao == "" {
			if m := pluginVersionRe.FindStringSubmatch(linha); m != nil {
				versao = strings.TrimSpace(m[1])
			}
		}
		if nome != "" && versao != "" {
			break
		}
	}
	// Nome sem versão é inútil para checksum, e versão sem nome é suspeita de
	// falso positivo do regex (um `Version:` solto em comentário de código).
	if versao == "" || nome == "" {
		return "", ""
	}
	return nome, versao
}

// pluginInventory calcula os hashes dos arquivos de um plugin.
//
// Diferente do core, aqui o inventário parte da lista da API e não da varredura
// do diretório: o que interessa é comparar o que a API conhece com o que está
// no disco.
func pluginInventory(dir string, checksums map[string]pluginFileSums) (map[string]LocalFile, []string) {
	locais := make(map[string]LocalFile, len(checksums))
	var ausentes []string

	for rel := range checksums {
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			ausentes = append(ausentes, rel)
			continue
		}
		md5sum, sha, err := hashFile(abs)
		if err != nil {
			// Ilegível não é ausente nem alterado. Afirmar qualquer coisa
			// sobre um arquivo que não conseguimos ler seria chute.
			continue
		}
		locais[rel] = LocalFile{
			RelPath: rel,
			AbsPath: abs,
			MD5:     md5sum,
			SHA256:  sha,
			Size:    info.Size(),
			Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
			MTime:   info.ModTime().Unix(),
		}
	}
	sort.Strings(ausentes)
	return locais, ausentes
}

// extraPluginFiles procura arquivos executáveis que a API não conhece.
//
// É o achado mais valioso deste verificador: um `.php` a mais dentro de um
// plugin oficial não tem explicação inocente. Diferente do core, aqui a
// tolerância é zero — plugin não ganha arquivo por conta própria.
func extraPluginFiles(dir string, checksums map[string]pluginFileSums, maxDepth int) []LocalFile {
	var out []LocalFile

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if depthOf(dir, path) > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		slashRel := filepath.ToSlash(rel)
		if _, conhecido := checksums[slashRel]; conhecido {
			return nil
		}
		if !isExecutableExt(slashRel) {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		md5sum, sha, hashErr := hashFile(path)
		if hashErr != nil {
			return nil
		}
		out = append(out, LocalFile{
			RelPath: slashRel,
			AbsPath: path,
			MD5:     md5sum,
			SHA256:  sha,
			Size:    info.Size(),
			Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
			MTime:   info.ModTime().Unix(),
		})
		return nil
	})

	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out
}
