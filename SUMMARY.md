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

Nada foi silenciosamente omitido. Esta é a lista completa.

### Fechado depois da validação com engines reais

| Item | Estado |
|---|---|
| Linhas de comando dos adaptadores | ✅ validadas contra AMWScan 0.15.1 e yara 4.2.3 reais |
| `Probe()` confirmando que o engine roda | ✅ executa o engine, não só confere versão e arquivo |
| Manutenção periódica no modo `cron` | ✅ `internal/housekeeping`, chamada por `scan`, `daemon` e painel |
| Retenção de log e de saída bruta | ✅ aplicada de fato (antes era só configuração decorativa) |
| Corrida de dados na config do painel | ✅ `RWMutex` + `Clone()` profundo + teste de concorrência para o `-race` |
| Flood de achados de core ausente | ✅ abstenção acima de 10%, `anomaly` abaixo |
| Engine executado uma vez por lote | ✅ `Info().ScopeAware` — ver abaixo |

#### O achado de desempenho

Medido num WordPress 6.5.2 real (3008 arquivos), antes e depois:

| | Antes | Depois |
|---|---|---|
| **Ciclo completo** | **21m45s** | **24,9s** |
| `amwscan` | 13m54s | 3,3s |
| `wp-checksums` | 7m02s | 6,2s |
| `php-malware-finder` | 11s | 8,7s |

O orquestrador executava cada engine **uma vez por lote**. Com lotes de 200 e
3008 arquivos são ~16 invocações, e engines que não sabem limitar a varredura
leem a raiz inteira em cada uma. Não era só desperdício: o `wp-checksums`
reportava **16 achados** para o mesmo arquivo alterado, um por lote.

21 minutos de CPU a 200% por ciclo é exatamente o que faz uma hospedagem
suspender a conta — uma violação direta do Princípio IV pela própria
ferramenta. Só a execução real expôs isso; nenhum teste unitário mediria.

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

### 3. Cobertura real do php-malware-finder

Os testes automatizados cobrem `Probe()` e `Parse()`; os caminhos de `Install()`
e `Scan()` são validados no container (`make validar-engines`, item abaixo).

O que **continua sem validação real** é a detecção do php-malware-finder: o
corpus sintético é inerte demais para casar com as regras reais do `php.yar` —
o `yara` executado diretamente sobre o corpus casa **zero** regras. O adaptador
está correto (o container confirma flags, execução e parsing), mas o engine não
está sendo exercitado com nada que ele reconheça. Validar isso exigiria
amostras que a constituição proíbe no repositório.

### 4. Usabilidade do painel (parte do SC-004)

O teste e2e roda pela API HTTP, sem navegador (`DECISIONS.md` D-017). Não cobre
renderização, layout, acessibilidade nem o critério de tempo com um usuário
real. O painel foi verificado manualmente durante o desenvolvimento (primeiro
acesso, autenticação, carga das 7 áreas com dados reais da API), mas o SC-004
completo continua sendo validação com pessoa.

### 4b. Integração com Slack e Discord

A US4 diz que os webhooks servem para "integrar com Slack/Discord/n8n ou
sistemas próprios". Isso vale para **n8n, Zapier e endpoints próprios**, que
aceitam qualquer JSON — mas **não** para Slack e Discord.

Os *incoming webhooks* dos dois não aceitam payload arbitrário: o Slack espera
`{"text": …}` ou blocos, o Discord espera `{"content": …}` ou `embeds`. Nosso
envelope (`{schema_version, event, delivery_id, instance, data}`) é rejeitado
ou vira mensagem vazia.

Fechar isso exigiria um campo `format` por webhook (`raw`/`slack`/`discord`)
com um formatador por destino — e a assinatura HMAC continuaria valendo só para
`raw`, já que nenhum dos dois verifica assinatura. **Não está em nenhuma spec
nem tarefa**; é escopo novo. Registrado aqui para não ser anunciado como pronto.

O Telegram é declarado pós-MVP na própria spec (`spec.md:292`).

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

Todos verdes. `go vet ./...` limpo. CI (lint + test + build amd64/arm64) verde.

### Valide os engines reais antes de confiar num scan

```bash
make validar-engines
```

Sobe um Debian com PHP CLI e `yara`, usuário sem root, baixa um WordPress
6.5.2 real, planta duas adulterações no core, instala os engines e compara o
que o orquestrador vê com o que cada engine vê sozinho.

**Isso não é opcional.** A suíte automatizada não executa os engines (D-011), e
por isso as linhas de comando dos adaptadores nunca tinham sido exercitadas. O
container encontrou **oito** defeitos que nenhum teste unitário pegaria:

| Defeito | Como aparecia |
|---|---|
| URL do release do AMWScan | 404 na instalação — visível |
| `--format json` (não existe; é `--report-format txt`, e escreve em arquivo) | parser inteiro construído sobre um formato fictício |
| `@arquivo` no yara (é `--scan-list`) | linha de comando inválida |
| `--filter-paths` com vários caminhos (semântica de E) | **engine verde, relatório limpo, site infectado** |
| `mbstring` ausente | engine marcado como saudável sem nunca poder rodar |
| 2998 achados `likely` de core ausente | ruído afogando os achados reais |
| Engine invocado uma vez por lote | 21m45s por ciclo e 16× achados duplicados |
| `--config` ignorado depois de argumento posicional | `restore` falhava ou agia na instância errada |

Quatro deles teriam causado dano real: três produziriam "0 achados" com
aparência de saúde — e um scanner que reporta site limpo sem ter escaneado é
pior que scanner nenhum, porque produz confiança falsa —, e o sétimo poderia
derrubar a conta por consumo de CPU.

#### O que a validação prova hoje

```text
✓ o orquestrador viu o que o AMWScan viu sozinho (2 vs 2)
✓ wp-checksums executou sobre um WordPress real
✓ a adulteração do core foi detectada (peso 1.50)
✓ um voto forte sozinho parou em likely (não escalou para confirmed)
✓ dois votos (checksum + heurística) chegaram a confirmed
✓ o arquivo foi movido para o cofre (não está mais no lugar)
✓ cofre íntegro (hashes conferem)
✓ restauração byte a byte funcionou numa conta sem privilégio
✓ pico de memória do orquestrador: 51 MB (limite prometido: 128 MB)
```

O escalonamento do consenso é exercitado com engines de verdade: um arquivo com
só o voto do checksum para em `likely`; outro com checksum **e** heurística
chega a `confirmed` e dispara a quarentena reversível.

### Rode os testes no Linux, não só na estação de trabalho

O primeiro CI reprovou e expôs **dois defeitos que o Windows escondia**, ambos
já corrigidos:

1. **A quarentena era irrecuperável no Linux.** O cofre aplicava `chmod 000`, e
   `Restore` e `quarantine verify` precisam *ler* a cópia — os dois falhavam com
   "permission denied". Isso derrubava o Princípio I inteiro. O Windows ignora
   permissões POSIX e permite ler um arquivo "0000", então toda a suíte passava
   local. Agora é `0400`, e o teste de neutralização lê o arquivo de fato.
2. **O `.gitignore` engolia o programa.** O padrão `sentinelhost` sem barra
   inicial casa qualquer arquivo *ou diretório* com esse nome em qualquer nível,
   e o primeiro alvo era `cmd/sentinelhost/`. O primeiro push publicou um
   repositório sem o pacote `main`, e só o build no CI percebeu.

A lição vale para quem for contribuir: este projeto tem semântica de sistema de
arquivos POSIX no núcleo, e uma suíte verde no Windows não é evidência de nada
nessa área.

---

## Ambiente de desenvolvimento

Durante a implementação o Windows Defender colocou em quarentena o arquivo
`docs/esquema-e-adaptadores.md` (heurística disparada pelo exemplo de
`matched_content` na seção 1.1). O arquivo foi recuperado íntegro. Para clonar
este repositório no Windows pode ser necessária uma exclusão de antivírus para
a pasta — o corpus sintético é inerte por construção
(`tests/testdata/corpus/AMOSTRAS.md`), mas heurística acerta no formato, não na
intenção.
