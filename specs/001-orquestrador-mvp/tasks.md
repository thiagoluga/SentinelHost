# Tasks: A multi-engine orchestrator with a consensus verdict (MVP)

**Input**: Design documents from `/specs/001-orquestrador-mvp/`

**Prerequisites**: plan.md, spec.md, docs/schema-and-adapters.md

**Tests**: included — the spec requires contract tests, a synthetic corpus and a
quarantine round trip (SC-001, SC-003).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependencies)
- **[Story]**: US1 scan+verdict · US2 quarantine · US3 continuous · US4 alerts · US5 panel

## Phase 1: Setup

- [ ] T001 Initialize the Go module (`go mod init github.com/<org>/sentinelhost`), the directory structure from plan.md, a Makefile (a static build, CGO_ENABLED=0) and golangci-lint
- [ ] T002 [P] The MIT license, a README with the positioning (an orchestrator, not an engine) and a CONTRIBUTING referencing the constitution
- [ ] T003 [P] CI (GitHub Actions): lint + test + build for linux/amd64 and linux/arm64

## Phase 2: Foundational (blocks every user story)

- [ ] T004 `internal/schema`: the Finding, ScanReport and Verdict types, the enums and validation — a faithful port of docs/schema-and-adapters.md, with `schema_version`
- [ ] T005 [P] `specs/001-orquestrador-mvp/contracts/`: the JSON Schema of the three objects + the contract of the webhook payloads (webhooks.md)
- [ ] T006 `internal/config`: load/save/validate of the single TOML with safe defaults (nice 19, incremental 1h, observation ON for the first 7 days)
- [ ] T007 `internal/store`: SQLite through modernc.org/sqlite, migrations, DAOs for verdicts/quarantine/deliveries/the structured log
- [ ] T008 `internal/exec`: a subprocess executor with nice/ionice, a timeout, a pause between batches, capture and archiving of the raw output
- [ ] T009 `internal/adapter`: the Adapter interface (Info/Probe/Install/UpdateSignatures/Scan/Parse), the adapter registry and a ProbeResult with the reason for unavailability
- [ ] T010 [P] `tests/testdata/corpus/`: a partial clean WordPress + 12 INERT synthetic webshells (documented, not executable) + raw-output fixtures per engine

**Checkpoint**: the foundation is ready — the user stories can proceed in parallel

## Phase 3: US1 — A multi-engine scan with a consensus verdict (P1) 🎯 MVP

- [ ] T011 [US1] The `wpchecksums` adapter: detect the WP installation, query the WordPress.org checksums API, emit `core_integrity` Findings and the list of "identical official files" for the anti-false-positive protection
- [ ] T012 [P] [US1] The `amwscan` adapter: probe the PHP CLI, install the phar in the user's space, run it through internal/exec, Parse the report + the rule→category table
- [ ] T013 [P] [US1] The `pmf` adapter (php-malware-finder): probe/install the yara binary and the rules, run it, Parse the YARA output
- [ ] T014 [US1] `internal/verdict`: consolidation by sha256, a weighted score, configurable levels, the whitelist, the official-checksum protection, abstentions
- [ ] T015 [US1] `cmd/sentinelhost scan`: the one-shot command — probe, run the available engines, verdicts, a report in text and JSON, exit codes
- [ ] T016 [P] [US1] Contract tests for the 3 adapters over T010's fixtures
- [ ] T017 [US1] The SC-001 integration test: the synthetic corpus → ≥95% detected, zero `confirmed` false positives on an official file

**Checkpoint**: `sentinelhost scan` already delivers value on its own (the minimum MVP)

## Phase 4: US2 — A reversible quarantine (P1)

- [ ] T018 [US2] `internal/quarantine`: the vault in ~/.sentinelhost/quarantine, move + restrict the permissions + a neutralized extension, complete metadata in the store, a re-hash immediately before acting (FR-018)
- [ ] T019 [US2] A byte-for-byte restore with the original permissions; ignore (once) and whitelist (permanent); the retention purge routine
- [ ] T020 [US2] The verdict→action integration: `confirmed` gets an automatic quarantine honouring observation mode; the offer to restore the clean official file when it is the WP core
- [ ] T021 [US2] The `sentinelhost quarantine list|restore|purge` CLI
- [ ] T022 [P] [US2] The SC-003 round-trip test (quarantine→restore→identical hash) + full-disk / no-permission tests on the vault

## Phase 5: US3 — Continuous monitoring (P2)

- [ ] T023 [US3] `internal/baseline`: a walker with exclusions, symlinks never followed, a depth limit; the sha256 hash and its persistence
- [ ] T024 [US3] The incremental cycle: a diff by mtime/size/hash → the target list for the engines; a full scan on a separate schedule
- [ ] T025 [US3] `internal/sched` + `sentinelhost daemon`: the cycle loop, the single-instance lock, a clean resume after a kill (a watchdog through cron), opportunistic inotify
- [ ] T026 [US3] Cron-only mode: `sentinelhost cron-line` produces the line ready for cPanel
- [ ] T027 [P] [US3] The SC-002 test: 20k files, 1% modified → a cycle under 5 min with the default limits; a concurrency test (the lock)

## Phase 6: US4 — E-mail and webhook alerts (P2)

- [ ] T028 [US4] `internal/alert/email`: configurable SMTP (host/port/TLS/auth/From), templates (an immediate alert per level, an engine failure), a test send with the real error
- [ ] T029 [US4] A periodic digest aggregated from SQLite at the configured time
- [ ] T030 [P] [US4] `internal/alert/webhook`: a JSON POST signed with HMAC-SHA256 (X-Sentinel-Signature), an event filter per webhook, retries with backoff (5x), a delivery history, a test send
- [ ] T031 [US4] Event dispatch: verdict/quarantine/scan/failure → the enabled channels within 60 s (SC-005)
- [ ] T032 [P] [US4] Tests with a fake SMTP and a test HTTP server: the content, the signature, the retries, the timeout

## Phase 7: US5 — The embedded web panel (P3)

- [ ] T033 [US5] `internal/web`: a JSON API (status, findings, verdicts, quarantine, engines, config, alert-test) over the store/config; listening on 127.0.0.1 by default
- [ ] T034 [US5] Authentication: a password on first access, argon2id, a cookie session, login rate limiting
- [ ] T035 [US5] Port docs/painel-mockup.html into internal/web/assets with fetch() against the real API — the 7 areas: the overview (with a chart), findings, quarantine, engines, the schedule, alerts (e-mail/webhook/test), settings (thresholds, retention, whitelist)
- [ ] T036 [US5] Bidirectional config (FR-014): saving in the panel writes the TOML and applies from the next cycle; a manual change in the TOML shows up in the panel
- [ ] T037 [P] [US5] The panel's e2e test (chromedp): sign in, decide a pending finding, configure e-mail, trigger a webhook test (SC-004)

## Phase 8: Polish & Release

- [ ] T038 [P] quickstart.md: the one-command installation (curl | sh into the user's space), the first scan, an SSH tunnel for the panel, the cPanel cron mode
- [ ] T039 [P] A structured log queryable in the panel (FR-015) and the `sentinelhost doctor` command (an environment/engine diagnosis)
- [ ] T040 The v0.1.0 release: linux/amd64+arm64 binaries, checksums, a changelog; manual validation on a real cPanel account (SC-006)

## Dependencies

- Phase 2 blocks every US; T004 blocks T005/T009/T014
- US1 (T011–T017) blocks US2 (it needs verdicts) and US3 (it needs the engines)
- US4 depends on T007 (the store) and on the events from US1/US2; US5 depends on
  everything it displays
- T035 depends on the approved mockup (docs/painel-mockup.html) and on T033/T034
