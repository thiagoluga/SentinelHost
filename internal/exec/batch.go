package exec

import (
	"context"
	"time"
)

// Batcher divide uma lista de arquivos em lotes e pausa entre eles.
//
// A pausa e o que diferencia um scanner tolerado de um scanner que faz a
// hospedagem suspender a conta: sem ela, um ciclo com 20 mil arquivos mantem
// a CPU ocupada de ponta a ponta, e o painel de recursos da hospedagem so
// enxerga uso continuo.
type Batcher struct {
	Size  int
	Pause time.Duration
}

// NewBatcher cria um Batcher com valores minimos seguros.
func NewBatcher(size int, pause time.Duration) *Batcher {
	if size <= 0 {
		size = 200
	}
	if pause < 0 {
		pause = 0
	}
	return &Batcher{Size: size, Pause: pause}
}

// Each chama fn para cada lote, pausando entre eles.
//
// A pausa acontece ENTRE lotes, nunca depois do ultimo: um ciclo nao deve
// terminar dormindo a toa.
func (b *Batcher) Each(ctx context.Context, items []string, fn func(context.Context, []string) error) error {
	for i := 0; i < len(items); i += b.Size {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(i+b.Size, len(items))

		if err := fn(ctx, items[i:end]); err != nil {
			return err
		}

		if end < len(items) && b.Pause > 0 {
			if err := sleepCtx(ctx, b.Pause); err != nil {
				return err
			}
		}
	}
	return nil
}

// Batches devolve os lotes sem executar nada (util para relatorio e teste).
func (b *Batcher) Batches(items []string) [][]string {
	var out [][]string
	for i := 0; i < len(items); i += b.Size {
		out = append(out, items[i:min(i+b.Size, len(items))])
	}
	return out
}

// sleepCtx dorme respeitando o cancelamento. Uma pausa que ignora o contexto
// faria o comando `scan` demorar a responder a um Ctrl-C.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
