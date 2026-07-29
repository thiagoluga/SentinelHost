// Package baseline percorre as raizes configuradas, mantem o mapa de hashes
// usado pelos ciclos incrementais e decide o que precisa ser reescaneado.
package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
)

// WalkOptions parametriza a varredura.
type WalkOptions struct {
	// Root e a raiz autorizada. Nada fora dela e varrido, nunca.
	Root string
	// Exclude sao globs.
	Exclude []string
	// MaxDepth limita a profundidade a partir da raiz.
	MaxDepth int
	// MaxFileSizeBytes: arquivos maiores sao pulados e CONTABILIZADOS.
	MaxFileSizeBytes int64
	// MaxFiles corta a varredura, sinalizando truncamento.
	MaxFiles int
}

// Entry e um arquivo encontrado.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	SHA256 string `json:"sha256"`
	Perms  string `json:"perms"`
}

// WalkResult e o resultado da varredura.
type WalkResult struct {
	Entries []Entry
	// SkippedCounts explica o que ficou de fora e por que. Nunca se pula
	// arquivo em silencio: o usuario precisa saber que 12 arquivos nao foram
	// olhados por serem grandes demais, senao a cobertura parece completa.
	SkippedCounts map[string]int
	// Truncated indica que MaxFiles foi atingido. O ciclo vira `partial`.
	Truncated bool
	// Considered e quantas entradas foram avaliadas (antes das exclusoes).
	Considered int
}

// ErrRootUnsafe indica raiz invalida.
var ErrRootUnsafe = errors.New("raiz invalida para varredura")

// Walk percorre a raiz aplicando exclusoes e limites.
//
// Symlinks NUNCA sao seguidos. Um link para fora da raiz faria o scanner sair
// do diretorio que o usuario autorizou — e, num servidor compartilhado, entrar
// na conta de outra pessoa.
func Walk(ctx context.Context, opts WalkOptions) (WalkResult, error) {
	res := WalkResult{SkippedCounts: map[string]int{}}

	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrRootUnsafe, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrRootUnsafe, err)
	}
	if !info.IsDir() {
		return res, fmt.Errorf("%w: %s nao e um diretorio", ErrRootUnsafe, root)
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// Diretorio ou arquivo ilegivel nao derruba a varredura: numa
			// hospedagem compartilhada e normal haver pastas sem permissao.
			res.SkippedCounts["unreadable"]++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path == root {
				return nil
			}
			if depth(root, path) > opts.MaxDepth {
				res.SkippedCounts["too_deep"]++
				return fs.SkipDir
			}
			if pathmatch.MatchAny(opts.Exclude, path) {
				res.SkippedCounts["excluded"]++
				return fs.SkipDir
			}
			return nil
		}

		res.Considered++

		// Symlink: contabiliza e segue adiante sem abrir.
		if d.Type()&fs.ModeSymlink != 0 {
			res.SkippedCounts["symlink"]++
			return nil
		}
		if !d.Type().IsRegular() {
			res.SkippedCounts["not_regular"]++
			return nil
		}
		if pathmatch.MatchAny(opts.Exclude, path) {
			res.SkippedCounts["excluded"]++
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			res.SkippedCounts["unreadable"]++
			return nil
		}
		if opts.MaxFileSizeBytes > 0 && fi.Size() > opts.MaxFileSizeBytes {
			res.SkippedCounts["too_large"]++
			return nil
		}
		if opts.MaxFiles > 0 && len(res.Entries) >= opts.MaxFiles {
			res.Truncated = true
			return filepath.SkipAll
		}

		res.Entries = append(res.Entries, Entry{
			Path:  path,
			Size:  fi.Size(),
			MTime: fi.ModTime().Unix(),
			Perms: fmt.Sprintf("%04o", fi.Mode().Perm()),
		})
		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, walkErr
	}
	return res, nil
}

func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return 0
	}
	return strings.Count(rel, "/") + 1
}

// HashFile calcula o sha256 de um arquivo.
func HashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // caminho vem da varredura da raiz configurada
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashEntries preenche o sha256 das entradas.
//
// Entrada ilegivel e removida do resultado e contabilizada, em vez de entrar
// com hash vazio: um hash vazio viraria uma chave de deduplicacao invalida no
// consenso.
func HashEntries(ctx context.Context, entries []Entry, skipped map[string]int) []Entry {
	out := entries[:0]
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		sum, err := HashFile(e.Path)
		if err != nil {
			if skipped != nil {
				skipped["unreadable"]++
			}
			continue
		}
		e.SHA256 = sum
		out = append(out, e)
	}
	return out
}
