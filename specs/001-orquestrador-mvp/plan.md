# Implementation Plan: A multi-engine orchestrator with a consensus verdict (MVP)

**Branch**: `001-orquestrador-mvp` | **Date**: 2026-07-23 | **Spec**: specs/001-orquestrador-mvp/spec.md

**Input**: Feature specification from `/specs/001-orquestrador-mvp/spec.md`

## Summary

Build SentinelHost: a single Go binary that (1) probes and orchestrates open source
malware-detection engines as subprocesses under resource limits, (2) normalizes their
output into a versioned schema, (3) consolidates findings into a weighted consensus
verdict, (4) reversibly quarantines confirmed verdicts, (5) alerts through SMTP e-mail
and signed webhooks and (6) serves an embedded web panel (visual reference:
docs/panel-mockup.html). All of it operable without root on a shared hosting account.

## Technical Context

**Language/Version**: Go 1.24 (a static binary, CGO_ENABLED=0)

**Primary Dependencies**:
- the stdlib for HTTP (net/http), embed (the panel), os/exec (subprocesses)
- modernc.org/sqlite (pure-Go SQLite, no CGO) — state and history
- BurntSushi/toml — the configuration file
- wneessen/go-mail — SMTP sending
- hillu/go-yara is AVOIDED (CGO); the YARA rules run through the external `yara`
  binary when present (the php-malware-finder adapter)
- The panel: vanilla HTML/CSS/JS embedded through go:embed (no JS framework, no build
  step) — a direct evolution of the mockup

**Storage**: SQLite (verdicts, quarantine, history, alert deliveries) + a TOML file
(the configuration) + a data directory (~/.sentinelhost/): the baseline, the quarantine
vault, the raw output, the logs

**Testing**: go test; contract tests per adapter with raw-output samples versioned in
testdata/; an integration corpus with synthetic webshells (never live malware); a
quarantine round-trip test

**Target Platform**: Linux x86_64 and arm64, userland without root (cPanel accounts);
dev/CI on any OS through containers

**Project Type**: a CLI + daemon with an embedded web panel (a single project)

**Performance Goals**: an incremental cycle of a 20k-file site with 1% changed in under
5 min within the default limits; a full baseline of 100k files in under 30 min on a
limited CPU

**Constraints**: nice 19 + pauses between batches by default; under 128 MB of memory in
the orchestrator (the engines have their own limits/timeouts); no mandatory system
dependency; the panel listens on 127.0.0.1 by default

**Scale/Scope**: an MVP for 1 account/1 root per instance; multi-site on the same
account through multiple roots in the config (post-MVP: a multi-instance panel)

## Constitution Check

| Principle | How the plan satisfies it |
|---|---|
| I Reversibility | The quarantine vault + metadata in SQLite; a purge only by retention/manually; the round trip is tested |
| II Orchestrate | Zero signatures of our own; engines through os/exec; an MIT license is feasible (nothing GPL is linked — YARA through an external binary) |
| III Without root | A static userland binary; data in ~/.sentinelhost; a cron-only mode |
| IV A polite citizen | A central subprocess executor applies nice/ionice/timeout/batch-pause to every engine |
| V Transparent consensus | The Verdict keeps the votes/weights/rules; the UI and CLI display them; observation mode |
| VI The schema as a contract | A versioned schema package; Parse separate from Scan; the raw output archived |
| VII Simplicity | 1 binary, 1 TOML, SQLite, an embedded panel; no JS build step |

No violations. Complexity Tracking is empty.

## Project Structure

### Documentation (this feature)

```text
specs/001-orquestrador-mvp/
├── spec.md
├── plan.md              # this file
├── data-model.md        # → docs/schema-and-adapters.md (the source) + the SQLite DDL
├── quickstart.md        # the one-command installation + the first scan
├── contracts/           # the JSON Schema of the normalized schema + the webhook payloads
└── tasks.md
```

### Source Code (repository root)

```text
cmd/sentinelhost/        # main: the scan|serve|daemon|quarantine|config subcommands
internal/
├── schema/              # the Finding/ScanReport/Verdict types + versioning
├── adapter/             # the Adapter interface + the registry
│   ├── wpchecksums/     # native: the WordPress.org checksums API
│   ├── amwscan/         # a phar through the PHP CLI
│   ├── pmf/             # php-malware-finder through the yara binary
│   └── maldet/          # optional, when the environment allows
├── exec/                # the subprocess executor: nice, timeout, batch-pause, raw capture
├── verdict/             # the consensus engine: weights, thresholds, whitelist, checksum protection
├── baseline/            # incremental hashes, a walker with exclusions and limits
├── quarantine/          # the vault, neutralization, restore, retention
├── alert/
│   ├── email/           # SMTP, templates, the digest
│   └── webhook/         # HMAC, retries with backoff, the history
├── sched/               # the daemon, cycles, the instance lock, the cron watchdog
├── store/               # SQLite (modernc), migrations
├── config/              # TOML load/save/validate (the panel's source of truth)
└── web/                 # the panel: JSON handlers + go:embed of the assets
    └── assets/          # HTML/CSS/JS (an evolution of docs/panel-mockup.html)
tests/
├── contract/            # per adapter, with testdata/ of raw output
├── integration/         # the synthetic corpus, the quarantine round trip, the cycle's e2e
└── testdata/corpus/     # a clean (partial) WordPress + inert synthetic webshells
```

**Structure Decision**: a single Go project (option 1) — the CLI, the daemon and the
panel in the same binary, the panel embedded with no separate frontend, per Principle
VII.

## Recorded technical decisions

1. **YARA without CGO**: php-malware-finder requires YARA. Linking libyara would break
   the static binary and the license. Decision: the adapter probes for the `yara` binary
   on PATH or installs it in the user's space; without `yara`, the engine is unavailable
   with a clear reason (the consensus proceeds with the others).
2. **A panel with no framework**: the approved mockup is vanilla; the production panel
   evolves from it with fetch() against the local JSON API. It removes Node and any
   build step from the repo.
3. **The panel's authentication**: a single password set on first access, an argon2id
   hash in SQLite, a cookie session; TLS is left to an SSH tunnel or the hosting's proxy
   (documented in the quickstart).
4. **Webhook events**: `verdict.confirmed`, `verdict.likely`, `verdict.suspicious`,
   `quarantine.action`, `scan.completed`, `engine.failed` — the payload = the matching
   normalized object + delivery metadata. The contract is in contracts/webhooks.md.
5. **The digest**: an aggregation read from SQLite at the configured time — no extra
   state in memory; losing the process does not lose the digest.
