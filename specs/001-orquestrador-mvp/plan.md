# Implementation Plan: Orquestrador multi-engine com veredito por consenso (MVP)

**Branch**: `001-orquestrador-mvp` | **Date**: 2026-07-23 | **Spec**: specs/001-orquestrador-mvp/spec.md

**Input**: Feature specification from `/specs/001-orquestrador-mvp/spec.md`

## Summary

Construir o SentinelHost: um binário Go único que (1) sonda e orquestra engines
open source de detecção de malware como subprocessos com limites de recursos,
(2) normaliza as saídas para um esquema versionado, (3) consolida achados num
veredito por consenso ponderado, (4) quarentena reversivelmente vereditos
confirmados, (5) alerta por e-mail SMTP e webhooks assinados e (6) serve um
painel web embutido (referência visual: docs/painel-mockup.html). Tudo operável
sem root numa conta de hospedagem compartilhada.

## Technical Context

**Language/Version**: Go 1.24 (binário estático, CGO_ENABLED=0)

**Primary Dependencies**:
- stdlib para HTTP (net/http), embed (painel), os/exec (subprocessos)
- modernc.org/sqlite (SQLite puro Go, sem CGO) — estado e histórico
- BurntSushi/toml — arquivo de configuração
- wneessen/go-mail — envio SMTP
- hillu/go-yara é EVITADO (CGO); regras YARA rodam via binário `yara`
  externo quando presente (adaptador php-malware-finder)
- Painel: HTML/CSS/JS vanilla embutido via go:embed (sem framework JS,
  sem build step) — evolução direta do mockup

**Storage**: SQLite (vereditos, quarentena, histórico, entregas de alerta) +
arquivo TOML (configuração) + diretório de dados (~/.sentinelhost/): baseline,
cofre de quarentena, saídas brutas, logs

**Testing**: go test; testes de contrato por adaptador com amostras de saída
bruta versionadas em testdata/; corpus de integração com webshells sintéticas
(nunca malware vivo); teste round-trip de quarentena

**Target Platform**: Linux x86_64 e arm64, userland sem root (contas cPanel);
dev/CI em qualquer SO via containers

**Project Type**: CLI + daemon com painel web embutido (projeto único)

**Performance Goals**: ciclo incremental de site com 20k arquivos e 1% de
mudança < 5 min dentro dos limites padrão; baseline completo de 100k arquivos
< 30 min em CPU limitada

**Constraints**: nice 19 + pausas entre lotes por padrão; memória < 128 MB no
orquestrador (engines têm seus próprios limites/timeouts); nenhuma dependência
de sistema obrigatória; painel escuta 127.0.0.1 por padrão

**Scale/Scope**: MVP para 1 conta/1 raiz por instância; multi-site na mesma
conta via múltiplas raízes na config (pós-MVP: painel multi-instância)

## Constitution Check

| Princípio | Como o plano cumpre |
|---|---|
| I Reversibilidade | Cofre de quarentena + metadados em SQLite; purga só por retenção/manual; round-trip testado |
| II Orquestrar | Zero assinatura própria; engines via os/exec; licença MIT viável (nada GPL linkado — YARA via binário externo) |
| III Sem root | Binário estático userland; dados em ~/.sentinelhost; modo somente-cron |
| IV Cidadão educado | Executor central de subprocess aplica nice/ionice/timeout/batch-pause a todo engine |
| V Consenso transparente | Verdict guarda votos/pesos/regras; UI e CLI exibem; modo observação |
| VI Esquema-contrato | Pacote schema versionado; Parse separado de Scan; raw output arquivado |
| VII Simplicidade | 1 binário, 1 TOML, SQLite, painel embutido; sem build step JS |

Sem violações. Complexity Tracking vazio.

## Project Structure

### Documentation (this feature)

```text
specs/001-orquestrador-mvp/
├── spec.md
├── plan.md              # este arquivo
├── data-model.md        # → docs/esquema-e-adaptadores.md (fonte) + DDL SQLite
├── quickstart.md        # instalação em 1 comando + primeiro scan
├── contracts/           # JSON Schema do esquema normalizado + payloads de webhook
└── tasks.md
```

### Source Code (repository root)

```text
cmd/sentinelhost/        # main: subcomandos scan|serve|daemon|quarantine|config
internal/
├── schema/              # tipos Finding/ScanReport/Verdict + versionamento
├── adapter/             # interface Adapter + registro
│   ├── wpchecksums/     # nativo: API checksums WordPress.org
│   ├── amwscan/         # phar via PHP CLI
│   ├── pmf/             # php-malware-finder via binário yara
│   └── maldet/          # opcional, quando ambiente permite
├── exec/                # executor de subprocess: nice, timeout, batch-pause, captura raw
├── verdict/             # motor de consenso: pesos, limiares, whitelist, proteção checksum
├── baseline/            # hashes incrementais, walker com exclusões e limites
├── quarantine/          # cofre, neutralização, restore, retenção
├── alert/
│   ├── email/           # SMTP, templates pt-BR, digest
│   └── webhook/         # HMAC, retries com backoff, histórico
├── sched/               # daemon, ciclos, lock de instância, watchdog cron
├── store/               # SQLite (modernc), migrações
├── config/              # TOML load/save/validate (fonte da verdade do painel)
└── web/                 # painel: handlers JSON + go:embed dos assets
    └── assets/          # HTML/CSS/JS (evolução do docs/painel-mockup.html)
tests/
├── contract/            # por adaptador, com testdata/ de saídas brutas
├── integration/         # corpus sintético, round-trip de quarentena, e2e do ciclo
└── testdata/corpus/     # WordPress limpo (parcial) + webshells sintéticas inertes
```

**Structure Decision**: projeto único Go (opção 1) — CLI, daemon e painel no
mesmo binário, painel embutido sem frontend separado, conforme Princípio VII.

## Decisões técnicas registradas

1. **YARA sem CGO**: php-malware-finder requer YARA. Linkar libyara quebraria o
   binário estático e a licença. Decisão: o adaptador sonda o binário `yara`
   no PATH ou o instala no espaço do usuário; sem `yara`, o engine fica
   indisponível com motivo claro (consenso segue com os demais).
2. **Painel sem framework**: o mockup aprovado é vanilla; o painel de produção
   evolui dele com fetch() para a API JSON local. Elimina Node/build do repo.
3. **Autenticação do painel**: senha única definida no primeiro acesso, hash
   argon2id no SQLite, sessão por cookie; TLS fica a cargo de túnel SSH ou
   proxy da hospedagem (documentado no quickstart).
4. **Eventos de webhook**: `verdict.confirmed`, `verdict.likely`,
   `verdict.suspicious`, `quarantine.action`, `scan.completed`,
   `engine.failed` — payload = objeto normalizado correspondente + metadados
   de entrega. Contrato em contracts/webhooks.md.
5. **Digest**: agregação lida do SQLite no horário configurado — nenhum estado
   extra em memória; perder o processo não perde o digest.
