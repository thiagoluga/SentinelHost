# Tasks: Orquestrador multi-engine com veredito por consenso (MVP)

**Input**: Design documents from `/specs/001-orquestrador-mvp/`

**Prerequisites**: plan.md, spec.md, docs/esquema-e-adaptadores.md

**Tests**: incluídos — a spec exige testes de contrato, corpus sintético e
round-trip de quarentena (SC-001, SC-003).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: pode rodar em paralelo (arquivos diferentes, sem dependências)
- **[Story]**: US1 scan+veredito · US2 quarentena · US3 contínuo · US4 alertas · US5 painel

## Phase 1: Setup

- [ ] T001 Inicializar módulo Go (`go mod init github.com/<org>/sentinelhost`), estrutura de diretórios do plan.md, Makefile (build estático CGO_ENABLED=0) e golangci-lint
- [ ] T002 [P] Licença MIT, README com posicionamento (orquestrador, não engine) e CONTRIBUTING referenciando a constituição
- [ ] T003 [P] CI (GitHub Actions): lint + test + build linux/amd64 e linux/arm64

## Phase 2: Foundational (bloqueia todas as user stories)

- [ ] T004 `internal/schema`: tipos Finding, ScanReport, Verdict, enums e validação — porta fiel de docs/esquema-e-adaptadores.md, com `schema_version`
- [ ] T005 [P] `specs/001-orquestrador-mvp/contracts/`: JSON Schema dos três objetos + contrato dos payloads de webhook (webhooks.md)
- [ ] T006 `internal/config`: load/save/validate do TOML único com defaults seguros (nice 19, incremental 1h, observação ON nos primeiros 7 dias)
- [ ] T007 `internal/store`: SQLite via modernc.org/sqlite, migrações, DAOs de verdicts/quarantine/deliveries/log estruturado
- [ ] T008 `internal/exec`: executor de subprocess com nice/ionice, timeout, pausa entre lotes, captura e arquivamento de saída bruta
- [ ] T009 `internal/adapter`: interface Adapter (Info/Probe/Install/UpdateSignatures/Scan/Parse), registro de adaptadores e ProbeResult com motivo de indisponibilidade
- [ ] T010 [P] `tests/testdata/corpus/`: WordPress limpo parcial + 12 webshells sintéticas INERTES (documentadas, não executáveis) + fixtures de saída bruta por engine

**Checkpoint**: fundação pronta — user stories podem seguir em paralelo

## Phase 3: US1 — Scan multi-engine com veredito por consenso (P1) 🎯 MVP

- [ ] T011 [US1] Adaptador `wpchecksums`: detectar instalação WP, consultar API de checksums do WordPress.org, emitir Findings `core_integrity` e lista de "arquivos oficiais idênticos" para proteção anti-falso-positivo
- [ ] T012 [P] [US1] Adaptador `amwscan`: probe do PHP CLI, instalação do phar no espaço do usuário, execução via internal/exec, Parse do relatório + tabela regra→categoria
- [ ] T013 [P] [US1] Adaptador `pmf` (php-malware-finder): probe/instalação do binário yara e das regras, execução, Parse da saída YARA
- [ ] T014 [US1] `internal/verdict`: consolidação por sha256, score ponderado, níveis configuráveis, whitelist, proteção por checksum oficial, abstenções
- [ ] T015 [US1] `cmd/sentinelhost scan`: comando one-shot — probe, execução dos engines disponíveis, vereditos, relatório em texto e JSON, exit codes
- [ ] T016 [P] [US1] Testes de contrato dos 3 adaptadores sobre as fixtures de T010
- [ ] T017 [US1] Teste de integração SC-001: corpus sintético → ≥95% detectado, zero falso positivo `confirmed` em arquivo oficial

**Checkpoint**: `sentinelhost scan` já entrega valor sozinho (MVP mínimo)

## Phase 4: US2 — Quarentena reversível (P1)

- [ ] T018 [US2] `internal/quarantine`: cofre em ~/.sentinelhost/quarantine, mover+chmod 000+extensão neutralizada, metadados completos no store, re-hash imediatamente antes de agir (FR-018)
- [ ] T019 [US2] Restore byte a byte com permissões originais; ignorar (uma vez) e whitelist (permanente); rotina de purga por retenção
- [ ] T020 [US2] Integração veredito→ação: `confirmed` quarentena automática respeitando modo observação; oferta de restauração do arquivo oficial limpo quando core WP
- [ ] T021 [US2] CLI `sentinelhost quarantine list|restore|purge`
- [ ] T022 [P] [US2] Teste round-trip SC-003 (quarentenar→restaurar→hash igual) + testes de disco cheio/sem permissão no cofre

## Phase 5: US3 — Monitoramento contínuo (P2)

- [ ] T023 [US3] `internal/baseline`: walker com exclusões, symlinks nunca seguidos, limite de profundidade; hash sha256 e persistência
- [ ] T024 [US3] Ciclo incremental: diff por mtime/tamanho/hash → lista de alvos para os engines; scan completo em agenda separada
- [ ] T025 [US3] `internal/sched` + `sentinelhost daemon`: loop de ciclos, lock de instância única, retomada limpa após kill (watchdog via cron), inotify oportunista
- [ ] T026 [US3] Modo somente-cron: `sentinelhost cron-line` gera a linha pronta para o cPanel
- [ ] T027 [P] [US3] Teste SC-002: 20k arquivos, 1% modificado → ciclo < 5 min com limites padrão; teste de concorrência (lock)

## Phase 6: US4 — Alertas por e-mail e webhooks (P2)

- [ ] T028 [US4] `internal/alert/email`: SMTP configurável (host/porta/TLS/auth/From), templates pt-BR (alerta imediato por nível, falha de engine), envio de teste com erro real
- [ ] T029 [US4] Digest periódico agregado do SQLite no horário configurado
- [ ] T030 [P] [US4] `internal/alert/webhook`: POST JSON assinado HMAC-SHA256 (X-Sentinel-Signature), filtro de eventos por webhook, retries backoff (5x), histórico de entregas, envio de teste
- [ ] T031 [US4] Despacho de eventos: veredito/quarentena/scan/falha → canais habilitados em ≤ 60 s (SC-005)
- [ ] T032 [P] [US4] Testes com SMTP fake e servidor HTTP de teste: conteúdo, assinatura, retries, timeout

## Phase 7: US5 — Painel web embutido (P3)

- [ ] T033 [US5] `internal/web`: API JSON (status, findings, verdicts, quarantine, engines, config, alert-test) sobre store/config; escuta 127.0.0.1 por padrão
- [ ] T034 [US5] Autenticação: senha no primeiro acesso, argon2id, sessão por cookie, rate-limit de login
- [ ] T035 [US5] Portar docs/painel-mockup.html para internal/web/assets com fetch() na API real — as 7 áreas: visão geral (com gráfico), achados, quarentena, engines, agendamento, alertas (e-mail/webhook/teste), configurações (limiares, retenção, whitelist)
- [ ] T036 [US5] Config bidirecional (FR-014): salvar no painel grava o TOML e aplica no próximo ciclo; mudança manual no TOML reflete no painel
- [ ] T037 [P] [US5] Teste e2e do painel (chromedp): login, decidir um achado pendente, configurar e-mail, disparar teste de webhook (SC-004)

## Phase 8: Polish & Release

- [ ] T038 [P] quickstart.md: instalação em 1 comando (curl | sh no espaço do usuário), primeiro scan, túnel SSH para o painel, modo cron cPanel
- [ ] T039 [P] Log estruturado consultável no painel (FR-015) e comando `sentinelhost doctor` (diagnóstico de ambiente/engines)
- [ ] T040 Release v0.1.0: binários linux/amd64+arm64, checksums, changelog; validação manual numa conta cPanel real (SC-006)

## Dependencies

- Phase 2 bloqueia todas as US; T004 bloqueia T005/T009/T014
- US1 (T011–T017) bloqueia US2 (precisa de vereditos) e US3 (precisa dos engines)
- US4 depende de T007 (store) e dos eventos de US1/US2; US5 depende de tudo que exibe
- T035 depende do mockup aprovado (docs/painel-mockup.html) e de T033/T034
