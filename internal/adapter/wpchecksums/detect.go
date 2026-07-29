// Package wpchecksums implementa o adaptador nativo de integridade do
// WordPress: compara os arquivos do core com os checksums oficiais publicados
// pelo WordPress.org.
//
// E o unico engine do MVP que vota POSITIVAMENTE em legitimidade. Esse voto
// vira veto no motor de veredito: arquivo identico ao checksum oficial nunca e
// quarentenado, independente de quantos engines o apontem (DECISIONS.md D-005).
package wpchecksums

import (
	"bufio"
	"crypto/md5" // a API do WordPress.org publica MD5; nao e uso criptografico
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Slug do engine.
const Slug = "wp-checksums"

// ErrNotWordPress indica que a raiz nao e uma instalacao WordPress.
//
// Site que nao e WordPress (Laravel, Joomla, estatico) e caso normal, nao
// falha: o adaptador se abstem sem penalizar o score dos demais engines.
var ErrNotWordPress = errors.New("nao parece uma instalacao WordPress")

// versionRe extrai a versao de wp-includes/version.php.
var versionRe = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)

// Install e o que foi detectado sobre a instalacao.
type Install struct {
	Root    string
	Version string
	Locale  string
}

// Detect procura uma instalacao WordPress na raiz.
func Detect(root string) (Install, error) {
	versionFile := filepath.Join(root, "wp-includes", "version.php")
	f, err := os.Open(versionFile) // caminho derivado da raiz configurada pelo usuario
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Install{}, fmt.Errorf("%w: %s nao existe", ErrNotWordPress, versionFile)
		}
		return Install{}, fmt.Errorf("%w: nao foi possivel ler %s: %v", ErrNotWordPress, versionFile, err)
	}
	defer func() { _ = f.Close() }()

	// version.php e pequeno; ler linha a linha evita carregar um arquivo
	// gigante se alguem apontar a raiz para o lugar errado.
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for sc.Scan() {
		if m := versionRe.FindStringSubmatch(sc.Text()); m != nil {
			return Install{Root: root, Version: m[1], Locale: "en_US"}, nil
		}
	}
	if err := sc.Err(); err != nil {
		return Install{}, fmt.Errorf("%w: lendo %s: %v", ErrNotWordPress, versionFile, err)
	}
	return Install{}, fmt.Errorf("%w: %s nao declara $wp_version", ErrNotWordPress, versionFile)
}

// LocalFile e o estado de um arquivo do core no disco.
type LocalFile struct {
	// RelPath e relativo a raiz, sempre com barra normal (o formato usado
	// pela API do WordPress.org).
	RelPath string `json:"rel_path"`
	AbsPath string `json:"abs_path"`
	MD5     string `json:"md5"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Perms   string `json:"perms"`
	MTime   int64  `json:"mtime"`
}

// inventory calcula MD5 e SHA-256 dos arquivos do core listados nos checksums.
//
// So os arquivos que a API conhece sao lidos: varrer a instalacao inteira aqui
// duplicaria o trabalho do walker do orquestrador e gastaria CPU da conta do
// usuario a toa.
func inventory(root string, checksums map[string]string) (map[string]LocalFile, []string) {
	out := make(map[string]LocalFile, len(checksums))
	var missing []string

	for rel := range checksums {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			// Arquivo do core que deveria existir e nao existe e um achado,
			// nao um erro de leitura.
			missing = append(missing, rel)
			continue
		}
		md5sum, sha, err := hashFile(abs)
		if err != nil {
			// Ilegivel nao e o mesmo que ausente nem que adulterado. Fica de
			// fora do inventario e nao vira achado: afirmar qualquer coisa
			// sobre um arquivo que nao conseguimos ler seria chute.
			continue
		}
		out[rel] = LocalFile{
			RelPath: rel,
			AbsPath: abs,
			MD5:     md5sum,
			SHA256:  sha,
			Size:    info.Size(),
			Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
			MTime:   info.ModTime().Unix(),
		}
	}
	return out, missing
}

// hashFile calcula MD5 (para comparar com a API) e SHA-256 (chave do esquema)
// numa unica leitura do arquivo.
func hashFile(path string) (string, string, error) {
	f, err := os.Open(path) // caminho derivado da raiz configurada
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()

	m := md5.New() // formato imposto pela API do WordPress.org
	s := sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

// extraFiles procura arquivos dentro de wp-admin/ e wp-includes/ que a API nao
// conhece. O core oficial nao tem arquivos a mais; um .php novo ali e um dos
// sinais mais confiaveis de comprometimento.
func extraFiles(root string, checksums map[string]string, maxDepth int) []LocalFile {
	var out []LocalFile
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // diretorio ilegivel nao derruba a varredura
			}
			if d.IsDir() {
				if depthOf(root, path) > maxDepth {
					return fs.SkipDir
				}
				return nil
			}
			// Symlink nunca e seguido: um link para fora da raiz faria o
			// scanner sair do diretorio que o usuario autorizou.
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			slashRel := filepath.ToSlash(rel)
			if _, known := checksums[slashRel]; known {
				return nil
			}
			// So codigo executavel interessa: um .txt extra em wp-includes e
			// desleixo, um .php extra e porta dos fundos.
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
	}
	return out
}

func depthOf(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/")
}

func isExecutableExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc":
		return true
	}
	return false
}
