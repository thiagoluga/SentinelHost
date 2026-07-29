package adapter

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrNotInstallable e devolvido por adaptadores de engines que o usuario
// precisa instalar por fora (maldet, por exemplo, depende do que a hospedagem
// oferece).
var ErrNotInstallable = errors.New("este engine nao pode ser instalado pelo SentinelHost neste ambiente")

// Registry guarda os adaptadores conhecidos.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry cria um registro vazio.
func NewRegistry() *Registry {
	return &Registry{adapters: map[string]Adapter{}}
}

// Register adiciona um adaptador. Slug duplicado e erro de programacao, nao
// de configuracao: dois adaptadores com o mesmo slug votariam duas vezes no
// mesmo veredito.
func (r *Registry) Register(a Adapter) error {
	info := a.Info()
	if info.Slug == "" {
		return errors.New("adaptador sem slug")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.adapters[info.Slug]; dup {
		return fmt.Errorf("adaptador %q ja registrado", info.Slug)
	}
	r.adapters[info.Slug] = a
	return nil
}

// MustRegister registra e entra em panico em caso de erro. Usado so na
// inicializacao, onde a falha e sempre um bug do proprio projeto.
func (r *Registry) MustRegister(a Adapter) {
	if err := r.Register(a); err != nil {
		panic(err)
	}
}

// Get busca um adaptador pelo slug.
func (r *Registry) Get(slug string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[slug]
	return a, ok
}

// Slugs devolve os slugs registrados, em ordem estavel.
//
// Ordem estavel importa: o relatorio de um ciclo nao pode listar os engines
// numa ordem diferente a cada execucao, senao comparar dois relatorios vira
// exercicio de paciencia.
func (r *Registry) Slugs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.adapters))
	for slug := range r.adapters {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

// All devolve os adaptadores em ordem de slug.
func (r *Registry) All() []Adapter {
	slugs := r.Slugs()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Adapter, 0, len(slugs))
	for _, s := range slugs {
		out = append(out, r.adapters[s])
	}
	return out
}

// Len devolve quantos adaptadores estao registrados.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.adapters)
}
