package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Baseline e o mapa caminho->estado usado pelos ciclos incrementais.
type Baseline struct {
	Version   int              `json:"version"`
	UpdatedAt time.Time        `json:"updated_at"`
	Roots     []string         `json:"roots"`
	Files     map[string]Entry `json:"files"`
}

// New cria um baseline vazio.
func New(roots []string) *Baseline {
	return &Baseline{Version: 1, Roots: roots, Files: map[string]Entry{}}
}

// Load le o baseline do disco. Ausente devolve um baseline vazio, nao erro: a
// primeira execucao nao tem baseline, e isso e normal.
func Load(path string, roots []string) (*Baseline, error) {
	data, err := os.ReadFile(path) // caminho derivado do diretorio de dados
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(roots), nil
		}
		return New(roots), fmt.Errorf("lendo baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		// Baseline corrompido nao pode travar a protecao. Recomecar do zero
		// custa um scan completo; travar custa a protecao inteira.
		return New(roots), fmt.Errorf("baseline corrompido, recomecando do zero: %w", err)
	}
	if b.Files == nil {
		b.Files = map[string]Entry{}
	}
	return &b, nil
}

// Save grava o baseline de forma atomica.
//
// Atomico porque a hospedagem mata processos longos: uma escrita interrompida
// deixaria um baseline truncado, e um baseline truncado faz o ciclo seguinte
// reescanear o site inteiro achando que tudo mudou.
func (b *Baseline) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("criando diretorio do baseline: %w", err)
	}
	b.UpdatedAt = time.Now()

	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("serializando baseline: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*.json")
	if err != nil {
		return fmt.Errorf("criando arquivo temporario: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gravando baseline: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sincronizando baseline: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fechando baseline: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("ajustando permissao do baseline: %w", err)
	}
	return os.Rename(tmpName, path)
}

// Diff e o resultado da comparacao entre o disco e o baseline.
type Diff struct {
	// New sao arquivos que nao existiam.
	New []Entry
	// Modified sao arquivos cujo conteudo mudou.
	Modified []Entry
	// Unchanged e a contagem dos que ficaram iguais.
	Unchanged int
	// Removed sao os caminhos que sumiram desde o ultimo ciclo.
	Removed []string
}

// Targets devolve os caminhos que precisam ser escaneados neste ciclo.
func (d Diff) Targets() []string {
	out := make([]string, 0, len(d.New)+len(d.Modified))
	for _, e := range d.New {
		out = append(out, e.Path)
	}
	for _, e := range d.Modified {
		out = append(out, e.Path)
	}
	return out
}

// Compare descobre o que mudou desde o ultimo ciclo.
//
// A comparacao usa tamanho e mtime como filtro barato e o sha256 como
// desempate. Confiar so em mtime seria ingenuo: `touch` e a primeira coisa que
// um atacante faz para esconder a alteracao. Confiar so em hash custaria ler o
// site inteiro a cada hora, o que a conta de hospedagem nao aguenta.
func (b *Baseline) Compare(atual []Entry) Diff {
	var d Diff
	vistos := make(map[string]bool, len(atual))

	for _, e := range atual {
		vistos[e.Path] = true
		anterior, existia := b.Files[e.Path]
		switch {
		case !existia:
			d.New = append(d.New, e)
		case e.SHA256 != "" && anterior.SHA256 != "" && e.SHA256 != anterior.SHA256:
			d.Modified = append(d.Modified, e)
		case e.SHA256 == "" && (e.Size != anterior.Size || e.MTime != anterior.MTime):
			// Ainda sem hash calculado: o par tamanho+mtime e o filtro barato
			// que decide QUEM merece ser hasheado.
			d.Modified = append(d.Modified, e)
		default:
			d.Unchanged++
		}
	}

	for path := range b.Files {
		if !vistos[path] {
			d.Removed = append(d.Removed, path)
		}
	}
	return d
}

// NeedsHash devolve as entradas cujo par tamanho+mtime mudou.
//
// E o passo que torna o ciclo incremental barato: so estes arquivos precisam
// ser lidos do disco para calcular hash.
func (b *Baseline) NeedsHash(atual []Entry) []Entry {
	var out []Entry
	for _, e := range atual {
		anterior, existia := b.Files[e.Path]
		if !existia || anterior.Size != e.Size || anterior.MTime != e.MTime || anterior.SHA256 == "" {
			out = append(out, e)
		}
	}
	return out
}

// Update aplica o estado atual ao baseline.
func (b *Baseline) Update(atual []Entry, removidos []string) {
	if b.Files == nil {
		b.Files = map[string]Entry{}
	}
	for _, e := range atual {
		if e.SHA256 == "" {
			// Entrada sem hash e um estado intermediario; grava-la faria o
			// ciclo seguinte achar que ja conhece o arquivo.
			if anterior, ok := b.Files[e.Path]; ok {
				e.SHA256 = anterior.SHA256
			} else {
				continue
			}
		}
		b.Files[e.Path] = e
	}
	for _, p := range removidos {
		delete(b.Files, p)
	}
}

// Get devolve a entrada conhecida de um caminho.
func (b *Baseline) Get(path string) (Entry, bool) {
	e, ok := b.Files[path]
	return e, ok
}

// Len devolve quantos arquivos o baseline conhece.
func (b *Baseline) Len() int { return len(b.Files) }
