# Contribuindo com o SentinelHost

## Antes de qualquer coisa: leia a constituição

[`.specify/memory/constitution.md`](.specify/memory/constitution.md) define sete
princípios inegociáveis. **Pull requests que violem um princípio são rejeitados**
ou precisam vir acompanhados de emenda aprovada à constituição (com registro de
motivação, análise de impacto nas specs existentes e incremento de versão
semântica).

Os erros mais comuns que a constituição impede:

- Adicionar uma ação destrutiva "só nesse caso" (Princípio I).
- Embutir assinaturas ou heurísticas próprias no orquestrador (Princípio II).
- Depender de root, systemd ou de um daemon sempre vivo (Princípio III).
- Remover um limite de recurso "porque estava lento" (Princípio IV).
- Produzir um veredito que o usuário não consegue explicar (Princípio V).
- Fazer o motor de veredito conhecer um engine específico (Princípio VI).
- Introduzir CGO, build step de frontend ou segundo arquivo de config
  (Princípio VII).

## Desenvolvimento é spec-driven

Toda feature nasce de `spec.md` → `plan.md` → `tasks.md` dentro de `specs/`.
Não abra PR de código para algo que não está numa spec. Se a spec estiver
ambígua, registre a interpretação escolhida em [`DECISIONS.md`](DECISIONS.md).

## Testes obrigatórios

- **Contrato por adaptador**: cada adaptador tem fixtures de saída **bruta** do
  engine em `tests/testdata/raw/<engine>/` e um teste que verifica o `Parse`
  contra o esquema normalizado. Fixtures vêm de execuções reais, versionadas.
- **Corpus de consenso**: amostras em `tests/testdata/corpus/`. **Somente
  webshells sintéticas e inertes** — nunca malware vivo ou executável. Cada
  amostra tem um `.md` ao lado documentando o que ela simula e por que é
  inofensiva.
- **Round-trip de quarentena**: quarentenar → restaurar → comparar hash. Tem
  que ser byte a byte idêntico.

```bash
make test        # tudo
make lint        # golangci-lint
make build       # binário estático local
make release     # linux/amd64 + linux/arm64
```

## Novos adaptadores

1. Implemente a interface `adapter.Adapter` em `internal/adapter/<slug>/`.
2. Mantenha a tabela regra→(`category`, `severity`, `confidence`) **explícita e
   versionada** junto do adaptador. Regra desconhecida vira
   `other`/`medium`/`heuristic` — nunca é descartada.
3. Nunca escreva fora do diretório de trabalho do SentinelHost. Quem move
   arquivo é o orquestrador, jamais o adaptador.
4. Falha, pânico ou timeout do adaptador tem que virar
   `ScanReport{status: failed}` e abstenção — nunca derrubar o ciclo.
5. Se o engine for GPL, ele só pode ser invocado por subprocess. Nada de linkar.
6. Registre o adaptador em `internal/adapter/registry.go` e adicione fixtures.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/). Commits pequenos,
um por tarefa da spec quando possível:

```text
feat(verdict): motor de consenso ponderado (T014)
fix(quarantine): re-hash antes de mover (FR-018)
```
