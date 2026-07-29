package adapter

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrNotInstallable is returned by adapters for engines the user has to install
// separately (maldet, for instance, depends on what the host provides).
var ErrNotInstallable = errors.New("SentinelHost cannot install this engine in this environment")

// Registry holds the known adapters.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{adapters: map[string]Adapter{}}
}

// Register adds an adapter. A duplicate slug is a programming error, not a
// configuration one: two adapters with the same slug would vote twice on the
// same verdict.
func (r *Registry) Register(a Adapter) error {
	info := a.Info()
	if info.Slug == "" {
		return errors.New("adapter with no slug")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.adapters[info.Slug]; dup {
		return fmt.Errorf("adapter %q is already registered", info.Slug)
	}
	r.adapters[info.Slug] = a
	return nil
}

// MustRegister registers and panics on error. Used only during initialization,
// where a failure is always a bug in the project itself.
func (r *Registry) MustRegister(a Adapter) {
	if err := r.Register(a); err != nil {
		panic(err)
	}
}

// Get looks an adapter up by slug.
func (r *Registry) Get(slug string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[slug]
	return a, ok
}

// Slugs returns the registered slugs in a stable order.
//
// Stable order matters: a cycle's report must not list the engines in a different
// order every run, otherwise comparing two reports becomes an exercise in
// patience.
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

// All returns the adapters ordered by slug.
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

// Len returns how many adapters are registered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.adapters)
}
