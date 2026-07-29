# SUMMARY — feature 001-orquestrador-mvp

Estado da implementação do MVP do SentinelHost, com o que ficou pendente e como
rodar.

---

## O que foi implementado

Todas as 40 tarefas de [`specs/001-orquestrador-mvp/tasks.md`](specs/001-orquestrador-mvp/tasks.md)
foram executadas. Resumo por fase:

### Fase 1–2 — Setup e fundação

| Tarefa | Onde |
|---|---|
| T001 Módulo Go, estrutura, Makefile estático, golangci-lint | `go.mod`, `Makefile`, `.golangci.yml` |
| T002 MIT, README, CONTRIBUTING | raiz |
| T003 CI (lint + test + build amd64/arm64) | `.github/workflows/ci.yml` |
| T004 Esquema normalizado versionado | `internal/schema/` |
| T005 JSON Schema dos 3 objetos + contrato de webhooks | `specs/001-orquestrador-mvp/contracts/` |
| T006 TOML único com defaults seguros | `internal/config/` |
| T007 SQLite sem CGO, migrações, DAOs | `internal/store/` |
| T008 Executor com limites de recurso | `internal/exec/` |
| T009 Interface `Adapter` + registro + blindagem | `internal/adapter/` |
| T010 Corpus sintético inerte + fixtures por engine | `tests/testdata/` |

### Fase 3 — US1: scan multi-engine com veredito por consenso

| Tarefa | Onde |
|---|---|
| T011 Adaptador `wp-checksums` (nativo) | `internal/adapter/wpchecksums/` |
| T012 Adaptador `amwscan` | `internal/adapter/amwscan/` |
| T013 Adaptador `php-malware-finder` | `internal/adapter/pmf/` |
| T014 Motor de consenso | `internal/verdict/` |
| T015 `sentinelhost scan` (texto + JSON, exit codes) | `cmd/sentinelhost/scan.go` |
| T016 Testes de contrato sobre as fixtures | `tests/contract/` |
| T017 SC-001 sobre o corpus | `tests/integration/consenso_test.go` |

### Fase 4 — US2: quarentena reversível

| Tarefa | Onde |
|---|---|
| T018 Cofre com re-hash antes de agir | `internal/quarantine/` |
| T019 Restore byte a byte, whitelist, purga por retenção | `internal/quarantine/`, `internal/verdict/` |
| T020 Integração veredito → ação | `internal/cycle/persist.go` |
| T021 CLI `quarantine list\|restore\|purge\|verify` | `cmd/sentinelhost/quarantine.go` |
| T022 Round-trip SC-003 + disco cheio/sem permissão | `internal/quarantine/vault_test.go` |

### Fase 5 — US3: monitoramento contínuo

| Tarefa | Onde |
|---|---|
| T023 Walker com exclusões, symlinks e limites | `internal/baseline/walk.go` |
| T024 Ciclo incremental por diff de baseline | `internal/baseline/`, `internal/cycle/` |
| T025 Daemon, lock de instância única, retomada após kill | `internal/sched/`, `internal/lock/` |
| T026 `sentinelhost cron-line` | `cmd/sentinelhost/misc.go` |
| T027 SC-002 + concorrência do lock | `tests/integration/ciclo_test.go` |

### Fase 6 — US4: alertas

| Tarefa | Onde |
|---|---|
| T028 SMTP configurável, templates pt-BR, envio de teste | `internal/alert/email/` |
| T029 Digest periódico agregado do SQLite | `internal/alert/digest.go` |
| T030 Webhooks HMAC-SHA256 com backoff e histórico | `internal/alert/webhook/` |
| T031 Despacho de eventos | `internal/alert/dispatcher.go` |
| T032 Testes com servidor HTTP de teste | `tests/integration/alertas_test.go` |

### Fase 7 — US5: painel web

| Tarefa | Onde |
|---|---|
| T033 API JSON sobre store/config, escuta em 127.0.0.1 | `internal/web/api.go` |
| T034 Senha no primeiro acesso, argon2id, sessão, rate-limit | `internal/web/auth.go` |
| T035 Porte do mockup para as 7 áreas, consumindo a API real | `internal/web/assets/` |
| T036 Config bidirecional (FR-014) | `internal/web/patch.go` |
| T037 e2e do painel | `tests/integration/painel_test.go` |

### Fase 8 — Polish

| Tarefa | Onde |
|---|---|
| T038 quickstart | `specs/001-orquestrador-mvp/quickstart.md` |
| T039 Log estruturado consultável + `sentinelhost doctor` | `internal/store/events.go`, `cmd/sentinelhost/misc.go` |
| T040 Binários linux/amd64 e linux/arm64 + checksums | `dist/` (ver ressalva abaixo) |

---

## Success Criteria

| Critério | Estado | Medido |
|---|---|---|
| **SC-001** — ≥95% do corpus em `confirmed`/`likely`, zero falso positivo `confirmed` em arquivo oficial | ✅ | 10/10 amostras de conteúdo malicioso (100%); 12/12 detectadas em `suspicious`+; zero falso positivo. O arquivo do core apontado por 2 engines com assinatura sai `clean` por veto, com os votos vencidos ainda visíveis. |
| **SC-002** — ciclo incremental de 20k arquivos com 1% de mudança < 5 min | ✅ | **2,5 s**. Releu do disco exatamente 200 dos 20.000 arquivos (1,00%). |
| **SC-003** — 100% dos round-trips de quarentena byte a byte | ✅ | Testado com binário, CRLF, arquivo vazio, 1 MiB e UTF-8 multibyte. Permissões originais também restauradas. |
| **SC-004** — usuário leigo configura alerta e decide um achado em <5 min pelo painel | ⚠️ parcial | O **fluxo funcional** está coberto de ponta a ponta por teste (`TestSC004FluxoCompletoDoPainel`). A parte de **usabilidade real** (tempo, sem documentação) exige validação com pessoa real — ver pendências. |
| **SC-005** — alerta de `confirmed` entregue em ≤60 s | ✅ por construção | O despacho acontece de forma síncrona dentro do ciclo, logo após o veredito; o timeout de cada entrega é 10 s. Não foi medido sob carga real. |
| **SC-006** — roda em conta cPanel real sem root, dentro dos limites | ⚠️ pendente | Binários estáticos linux/amd64 e arm64 gerados e verificados (ELF sem interpretador dinâmico). **Falta a validação numa conta cPanel real** — ver pendências. |

---

## O que ficou pendente

Nada foi silenciosamente omitido. Esta é a lista completa:

### 1. Validação em conta cPanel real (SC-006, parte da T040)

Os binários estáticos foram gerados e conferidos, mas **não foram executados
numa hospedagem compartilhada real**. Isso exige uma conta cPanel, que este
ambiente não tem. O que falta verificar lá:

- consumo de CPU/memória sob os limites padrão durante um ciclo completo;
- comportamento do `nice`/`ionice` com as políticas da hospedagem;
- que o processo não seja morto pelo limite de processos da conta;
- que a linha de cron gerada funcione no gerenciador do cPanel.

### 2. Adaptador do `maldet`

Não implementado — **nenhuma tarefa de T001 a T040 o pede**. O `plan.md` o
descreve como "opcional, quando ambiente permite". O peso (1,0) e a fixture de
saída bruta com o `PROCEDENCIA.md` já estão versionados para quando o adaptador
chegar; o engine vem **desabilitado por padrão**, porque habilitar um engine sem
adaptador o faria constar como abstenção em todo ciclo — um alarme permanente
sobre algo que o usuário não tem como resolver.

### 3. Caminhos de `Install()` e `Scan()` dos engines reais

Os testes automatizados cobrem `Probe()` e `Parse()`, mas **não baixam o phar do
AMWScan nem executam o binário `yara`** (`DECISIONS.md` D-011): um teste que
depende de rede e de binário externo falha em CI e na hospedagem do usuário por
motivos que não têm nada a ver com o código. Esses caminhos precisam de
validação manual:

```bash
sentinelhost engines --install amwscan
sentinelhost engines --install php-malware-finder
sentinelhost scan
```

### 4. Usabilidade do painel (parte do SC-004)

O teste e2e roda pela API HTTP, sem navegador (`DECISIONS.md` D-017). Não cobre
renderização, layout, acessibilidade nem o critério de tempo com um usuário
real. O painel foi verificado manualmente durante o desenvolvimento (primeiro
acesso, autenticação, carga das 7 áreas com dados reais da API), mas o SC-004
completo continua sendo validação com pessoa.

### 5. Publicação do release v0.1.0

Binários e `dist/SHA256SUMS` estão gerados, mas **o release não foi publicado no
GitHub** e não há changelog. Publicar é uma ação externa que depende de decisão
sua.

### 6. Fora do escopo por instrução

- **Feature 002** (scanner de vulnerabilidades): não implementada. O esquema já
  carrega o campo `kind` e o bloco `component` para não obrigar uma quebra de
  versão depois (`DECISIONS.md` D-013).
- `wordfence-cli`, `clamav` e Telegram: pós-MVP pela própria spec.

---

## Decisões registradas

17 pontos onde a spec deixava margem estão em [`DECISIONS.md`](DECISIONS.md),
cada um com o princípio da constituição que o sustenta. As que mais afetam o
comportamento:

- **D-003/D-004** — score é soma sobre teto, não média. Com média, cada engine
  que se abstém diluiria o score, transformando falha técnica em voto de
  inocência.
- **D-005** — checksum oficial é **veto** aplicado depois do cálculo, não voto
  negativo. Um voto poderia ser superado; a regra do esquema é "nunca,
  independente de votos".
- **D-006** — whitelist bloqueia a **ação** e mantém o nível, para o arquivo
  continuar visível no relatório.
- **D-016** — denominador do SC-001 são as amostras de conteúdo malicioso;
  anomalia isolada não escala para `likely` e tem teste travando isso.
- **D-017** — e2e do painel por HTTP em vez de `chromedp`.

---

## Como rodar

Guia completo em [`specs/001-orquestrador-mvp/quickstart.md`](specs/001-orquestrador-mvp/quickstart.md).
O essencial:

```bash
sentinelhost config init --root ~/public_html
sentinelhost doctor          # mostra POR QUE cada engine está ou não disponível
sentinelhost scan            # exit 0 = nada; 1 = achou; 2 = erro; 3 = já rodando
sentinelhost cron-line       # linha pronta para o cPanel
sentinelhost serve           # painel em 127.0.0.1:8787
```

### Desenvolvimento

```bash
make test
make lint
make build
make release                 # linux/amd64 + linux/arm64 + SHA256SUMS
```

O teste do SC-002 monta 20 mil arquivos e leva ~2 min. Para pular:

```bash
go test ./... -short
```

### Estado da suíte

```text
ok  internal/adapter      internal/baseline    internal/config
ok  internal/exec         internal/lock        internal/pathmatch
ok  internal/quarantine   internal/schema      internal/store
ok  internal/verdict      tests/contract       tests/integration
```

Todos verdes. `go vet ./...` limpo.

---

## Ambiente de desenvolvimento

Durante a implementação o Windows Defender colocou em quarentena o arquivo
`docs/esquema-e-adaptadores.md` (heurística disparada pelo exemplo de
`matched_content` na seção 1.1). O arquivo foi recuperado íntegro. Para clonar
este repositório no Windows pode ser necessária uma exclusão de antivírus para
a pasta — o corpus sintético é inerte por construção
(`tests/testdata/corpus/AMOSTRAS.md`), mas heurística acerta no formato, não na
intenção.
