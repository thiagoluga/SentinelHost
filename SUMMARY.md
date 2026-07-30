# SUMMARY — feature 001-orquestrador-mvp

The state of SentinelHost's MVP implementation, with what is still pending and how to
run it.

---

## What was implemented

All 40 tasks in [`specs/001-orquestrador-mvp/tasks.md`](specs/001-orquestrador-mvp/tasks.md)
were carried out. A summary per phase:

### Phases 1–2 — Setup and foundation

| Task | Where |
|---|---|
| T001 Go module, structure, static Makefile, golangci-lint | `go.mod`, `Makefile`, `.golangci.yml` |
| T002 MIT, README, CONTRIBUTING | the root |
| T003 CI (lint + test + build amd64/arm64) | `.github/workflows/ci.yml` |
| T004 The versioned normalized schema | `internal/schema/` |
| T005 JSON Schema of the 3 objects + the webhooks contract | `specs/001-orquestrador-mvp/contracts/` |
| T006 A single TOML with safe defaults | `internal/config/` |
| T007 SQLite without CGO, migrations, DAOs | `internal/store/` |
| T008 An executor with resource limits | `internal/exec/` |
| T009 The `Adapter` interface + registry + shielding | `internal/adapter/` |
| T010 An inert synthetic corpus + per-engine fixtures | `tests/testdata/` |

### Phase 3 — US1: a multi-engine scan with a consensus verdict

| Task | Where |
|---|---|
| T011 The `wp-checksums` adapter (native) | `internal/adapter/wpchecksums/` |
| T012 The `amwscan` adapter | `internal/adapter/amwscan/` |
| T013 The `php-malware-finder` adapter | `internal/adapter/pmf/` |
| T014 The consensus engine | `internal/verdict/` |
| T015 `sentinelhost scan` (text + JSON, exit codes) | `cmd/sentinelhost/scan.go` |
| T016 Contract tests over the fixtures | `tests/contract/` |
| T017 SC-001 over the corpus | `tests/integration/consensus_test.go` |

### Phase 4 — US2: a reversible quarantine

| Task | Where |
|---|---|
| T018 The vault, with a re-hash before acting | `internal/quarantine/` |
| T019 A byte-for-byte restore, whitelist, retention purge | `internal/quarantine/`, `internal/verdict/` |
| T020 The verdict → action integration | `internal/cycle/persist.go` |
| T021 The `quarantine list\|restore\|purge\|verify` CLI | `cmd/sentinelhost/quarantine.go` |
| T022 The SC-003 round trip + full disk / no permission | `internal/quarantine/vault_test.go` |

### Phase 5 — US3: continuous monitoring

| Task | Where |
|---|---|
| T023 A walker with exclusions, symlinks and limits | `internal/baseline/walk.go` |
| T024 An incremental cycle by baseline diff | `internal/baseline/`, `internal/cycle/` |
| T025 The daemon, single-instance lock, resuming after a kill | `internal/sched/`, `internal/lock/` |
| T026 `sentinelhost cron-line` | `cmd/sentinelhost/misc.go` |
| T027 SC-002 + the lock's concurrency | `tests/integration/cycle_test.go` |

### Phase 6 — US4: alerts

| Task | Where |
|---|---|
| T028 Configurable SMTP, templates, a test send | `internal/alert/email/` |
| T029 A periodic digest aggregated from SQLite | `internal/alert/digest.go` |
| T030 HMAC-SHA256 webhooks with backoff and a history | `internal/alert/webhook/` |
| T031 Event dispatch | `internal/alert/dispatcher.go` |
| T032 Tests with a test HTTP server | `tests/integration/alerts_test.go` |

### Phase 7 — US5: the web panel

| Task | Where |
|---|---|
| T033 A JSON API over the store/config, listening on 127.0.0.1 | `internal/web/api.go` |
| T034 A password on first access, argon2id, sessions, rate limiting | `internal/web/auth.go` |
| T035 Porting the mockup's 7 areas, consuming the real API | `internal/web/assets/` |
| T036 Bidirectional config (FR-014) | `internal/web/patch.go` |
| T037 The panel's e2e | `tests/integration/panel_test.go` |

### Phase 8 — Polish

| Task | Where |
|---|---|
| T038 The quickstart | `specs/001-orquestrador-mvp/quickstart.md` |
| T039 A queryable structured log + `sentinelhost doctor` | `internal/store/events.go`, `cmd/sentinelhost/misc.go` |
| T040 linux/amd64 and linux/arm64 binaries + checksums | `dist/` (see the caveat below) |

---

## Success Criteria

| Criterion | State | Measured |
|---|---|---|
| **SC-001** — ≥95% of the corpus in `confirmed`/`likely`, zero `confirmed` false positives on an official file | ✅ | 10/10 malicious-content samples (100%); 12/12 detected at `suspicious`+; zero false positives. The core file flagged by 2 engines with a signature comes out `clean` by veto, with the overruled votes still visible. |
| **SC-002** — an incremental cycle of 20k files with 1% changed in under 5 min | ✅ | **2.5 s**. It re-read from disk exactly 200 of the 20,000 files (1.00%). |
| **SC-003** — 100% of the quarantine round trips byte for byte | ✅ | Tested with a binary, CRLF, an empty file, 1 MiB and multibyte UTF-8. The original permissions are restored too. |
| **SC-004** — a non-technical user configures an alert and decides a finding in under 5 min through the panel | ⚠️ partial | The **functional flow** is covered end to end by a test (`TestSC004TheCompletePanelFlow`). The **real usability** part (the time, with no documentation) requires validation with a real person — see the pending items. |
| **SC-005** — a `confirmed` alert delivered within 60 s | ✅ by construction | The dispatch happens synchronously inside the cycle, right after the verdict; each delivery's timeout is 10 s. It was not measured under real load. |
| **SC-006** — it runs on a real cPanel account without root, within the limits | ⚠️ pending | Static linux/amd64 and arm64 binaries were built and verified (an ELF with no dynamic interpreter). **The validation on a real cPanel account is missing** — see the pending items. |

---

## What is still pending

Nothing was silently omitted. This is the complete list.

### Closed after the validation with real engines

| Item | State |
|---|---|
| The adapters' command lines | ✅ validated against the real AMWScan 0.15.1 and yara 4.2.3 |
| `Probe()` confirming the engine runs | ✅ it executes the engine, not just checks a version and a file |
| The periodic maintenance in `cron` mode | ✅ `internal/housekeeping`, called by `scan`, `daemon` and the panel |
| Log and raw-output retention | ✅ actually applied (it used to be decorative configuration) |
| The data race in the panel's config | ✅ `RWMutex` + a deep `Clone()` + a concurrency test for `-race` |
| A flood of missing-core findings | ✅ an abstention above 10%, `anomaly` below |
| The engine executed once per batch | ✅ `Info().ScopeAware` — see below |
| Portuguese throughout the repository | ✅ everything committed is in English (constitution 1.1.0, Principle VIII) |
| The schema document missing from `HEAD` | ✅ recovered as `docs/schema-and-adapters.md` (`DECISIONS.md` D-012) |

#### The performance finding

Measured on a real WordPress 6.5.2 (3008 files), before and after:

| | Before | After |
|---|---|---|
| **Full cycle** | **21m45s** | **24.9s** |
| `amwscan` | 13m54s | 3.3s |
| `wp-checksums` | 7m02s | 6.2s |
| `php-malware-finder` | 11s | 8.7s |

The orchestrator was executing each engine **once per batch**. With batches of 200 and
3008 files that is ~16 invocations, and engines that cannot restrict their walk read
the whole root in each one. It was not only waste: `wp-checksums` reported **16
findings** for the same altered file, one per batch.

21 minutes of CPU at 200% per cycle is exactly what makes a hosting provider suspend
an account — a direct violation of Principle IV by the tool itself. Only a real run
exposed it; no unit test would have measured it.

### 1. Validation on a real cPanel account (SC-006, part of T040)

The static binaries were built and checked, but they **were not executed on a real
shared hosting account**. That requires a cPanel account, which this environment does
not have. What is left to verify there:

- the CPU/memory consumption under the default limits during a full cycle;
- how `nice`/`ionice` behave against the hosting's policies;
- that the process is not killed by the account's process limit;
- that the generated cron line works in the cPanel manager.

### 2. The `maldet` adapter

Not implemented — **no task from T001 to T040 asks for it**. `plan.md` describes it as
"optional, when the environment allows". Its weight (1.0) and the raw-output fixture
with its `PROVENANCE.md` are already versioned for when the adapter arrives; the engine
ships **disabled by default**, because enabling an engine with no adapter would make it
show up as an abstention in every cycle — a permanent alarm about something the user
has no way to resolve.

### 3. php-malware-finder's real coverage

The automated tests cover `Probe()` and `Parse()`; the `Install()` and `Scan()` paths
are validated in the container (`make validate-engines`, the item below).

What **remains unvalidated for real** is php-malware-finder's detection: the synthetic
corpus is too inert to match the real `php.yar` rules — `yara` run directly over the
corpus matches **zero** rules. The adapter is correct (the container confirms the
flags, the execution and the parsing), but the engine is not being exercised with
anything it recognizes. Validating that would require samples the constitution forbids
in the repository.

### 4. The panel's usability (part of SC-004)

The e2e test runs through the HTTP API, with no browser (`DECISIONS.md` D-017). It does
not cover rendering, layout, accessibility nor the time criterion with a real user. The
panel was checked manually during development (first access, authentication, all 7
areas loading with real data from the API), but the complete SC-004 remains validation
with a person.

### ~~4a. Plugin checksums~~ — implemented

FR-005 asks for the integrity "of the core **and, when available, plugins**". The
second half was missing and is now in `internal/adapter/wpchecksums/plugins.go`.

An abandoned plugin is the most common intrusion vector in WordPress, and a legitimate
plugin with one altered file is a backdoor's favourite hiding place: it does not show
up in the core check and the user never suspects what they installed themselves.

Three decisions the implementation encodes:

- **The slug is the directory's name**, not the `Plugin Name` header's. That is how the
  API indexes them; using the header would make every query 404 and the verifier would
  never find anything — failing silently.
- **A plugin with no published checksum produces an abstention with a reason, never
  silence.** A commercial or in-house plugin is not in the official directory. Treating
  the absence of *data* as the absence of a *problem* would declare clean what nobody
  checked, and the report records every unverified plugin.
- **An extra file is a `signature`; a missing file is an `anomaly`.** An official
  plugin does not grow a `.php` on its own — that is proof. A file that vanished, on
  the other hand, holds no malicious code and cannot be quarantined; as a `signature`,
  weight 1.50 would push the finding on its own close to `confirmed`.

Intact plugin files enter `clean_files` and get the same veto as the core — plugins
tend to carry minified JS and base64, which is exactly what produces heuristic false
positives.

16 tests cover this, none of them touching the network.

### ~~4b. Slack and Discord integration~~ — implemented

US4 says the webhooks serve to "integrate with Slack/Discord/n8n or your own systems".
That held for **n8n, Zapier and your own endpoints**, which accept any JSON — but not
for Slack and Discord, whose *incoming webhooks* reject an arbitrary payload: Slack
wants `{"text": …}`, Discord `{"content": …}`. Our envelope was either rejected or
arrived as an empty message, so "integrates with Slack" was a promise the generic
webhook could not keep.

A per-webhook `format` field closes it: `raw` (the default), `slack`, `discord`. Four
decisions the implementation encodes:

- **An empty format keeps meaning `raw`.** Every webhook configured before the field
  existed has none, and silently changing their body shape would break deliveries that
  work today.
- **The message carries the votes.** A chat alert that reads "threat confirmed" and
  nothing else forces the user into the panel to learn anything — and the votes are the
  whole point of a consensus verdict (Principle V). Abstentions travel with it too, so
  a cycle where half the engines failed does not read as clean.
- **Attacker-chosen text is escaped per destination.** The file path comes from the
  intruder. `<!channel>.php` is a legitimate filename and a perfectly good way to make
  our own alert ping an entire Slack workspace; Discord needs `@everyone` broken and
  its markdown escaped.
- **An unknown format fails the delivery** instead of falling back to `raw`. A delivery
  that "worked" in the wrong shape is exactly the quiet wrongness this project treats
  as a defect.

The HMAC signature is computed over the body that is actually sent, so it always
matches itself — but only `raw` has a receiver that reads it, and the configuration
warns when a secret is set on a chat format.

15 unit tests plus 4 integration tests through the real dispatch path, including the
**retry** path: a retry rebuilds the envelope from the persisted payload, and a
formatter that only handled the typed struct would degrade every retry to Slack.

Telegram is declared post-MVP in the spec itself (`spec.md:292`).

### ~~4c. A one-command installation script~~ — implemented

`install.sh`, required by Principle VII. POSIX `sh` (dash and busybox will do), without
root and without a package manager.

The point worth noting: **the checksum verification is not optional and its absence
aborts the install**. If `SHA256SUMS` is not available, the installation stops instead
of carrying on with an unchecked binary — `curl | sh` already asks for enough trust
without that. The installer also confirms the binary *runs* before declaring success,
because a directory with `noexec` is common on shared hosting and the error has to
appear during the installation, not on the first cron run.

Exercised in the container against a locally served release, including the case that
matters most: **a tampered binary is refused**.

### 5. Publishing the v0.1.0 release

The binaries and `dist/SHA256SUMS` are built, but **the release was not published on
GitHub** and there is no changelog. Publishing is an external action that depends on
your decision.

### 6. Out of scope by instruction

- **Feature 002** (the vulnerability scanner): not implemented. The schema already
  carries the `kind` field and the `component` block so no version break is needed
  later (`DECISIONS.md` D-013).
- `wordfence-cli`, `clamav` and Telegram: post-MVP by the spec itself.

---

## Recorded decisions

The points where the spec left room are in [`DECISIONS.md`](DECISIONS.md), each with
the constitution principle that settles it. The ones that affect behaviour most:

- **D-003/D-004** — the score is a sum over a ceiling, not an average. With an average,
  every engine that abstains would dilute the score, turning a technical failure into a
  vote of innocence.
- **D-005** — the official checksum is a **veto** applied after the calculation, not a
  negative vote. A vote could be overcome; the schema's rule is "never, regardless of
  votes".
- **D-006** — the whitelist blocks the **action** and keeps the level, so the file
  stays visible in the report.
- **D-016** — SC-001's denominator is the malicious-content samples; an isolated
  anomaly does not escalate to `likely`, and a test pins that.
- **D-017** — the panel's e2e over HTTP instead of `chromedp`.
- **D-022** — a test built on an assumption does not count as verification. It is the
  lesson that matters most in this project.
- **D-023** — English is the repository's language, retroactively.

---

## How to run it

The complete guide is in [`specs/001-orquestrador-mvp/quickstart.md`](specs/001-orquestrador-mvp/quickstart.md).
The essentials:

```bash
sentinelhost config init --root ~/public_html
sentinelhost doctor          # shows WHY each engine is or is not available
sentinelhost scan            # exit 0 = nothing; 1 = found; 2 = error; 3 = already running
sentinelhost cron-line       # a line ready for cPanel
sentinelhost serve           # the panel on 127.0.0.1:8787
```

### Development

```bash
make test
make lint
make build
make release                 # linux/amd64 + linux/arm64 + SHA256SUMS
```

The SC-002 test builds 20 thousand files and takes ~2 min. To skip it:

```bash
go test ./... -short
```

### The suite's state

```text
ok  internal/adapter      internal/baseline    internal/config
ok  internal/exec         internal/lock        internal/pathmatch
ok  internal/quarantine   internal/schema      internal/store
ok  internal/verdict      internal/housekeeping
ok  cmd/sentinelhost      tests/contract       tests/integration
```

All green. `go vet ./...` clean. CI (lint + test + build amd64/arm64) green.

### Validate the real engines before trusting a scan

```bash
make validate-engines
```

It brings up a Debian with the PHP CLI and `yara`, a non-root user, downloads a real
WordPress 6.5.2, plants two core tamperings, installs the engines and compares what the
orchestrator sees with what each engine sees on its own.

**This is not optional.** The automated suite does not execute the engines (D-011), and
because of that the adapters' command lines had never been exercised. The container
found **nine** defects no unit test would have caught:

| Defect | How it showed up |
|---|---|
| The AMWScan release URL | a 404 during the install — visible |
| `--format json` (it does not exist; it is `--report-format txt`, and it writes to a file) | the whole parser was built on a fictional format |
| `@file` in yara (it is `--scan-list`) | an invalid command line |
| `--filter-paths` with several paths (AND semantics) | **green engine, clean report, infected site** |
| A missing `mbstring` | an engine marked as healthy that could never run |
| 2998 `likely` missing-core findings | noise drowning the real findings |
| The engine invoked once per batch | 21m45s per cycle and 16× duplicate findings |
| `--config` ignored after a positional argument | `restore` failed or acted on the wrong instance |
| Plugin hashes declared as an array (the API uses a string) | **every plugin skipped, zero findings, no error** |

Five of them would have caused real damage: four would produce "0 findings" with the
appearance of health — and a scanner that reports a clean site without having scanned
is worse than no scanner, because it manufactures false confidence — and one could get
the account suspended for CPU consumption.

**Eight of the nine are the same mistake**: an assumption about the outside world, with
a test written from that same assumption. See `DECISIONS.md` D-022 — it is the lesson
that matters most in this project, and the reason the real samples are versioned.

#### What the validation proves today

```text
✓ the orchestrator saw what AMWScan saw on its own (3 vs 3)
✓ wp-checksums ran over a real WordPress
✓ the core tampering was detected (weight 1.50)
✓ one strong vote alone stopped at likely (it did not escalate to confirmed)
✓ two votes (checksum + heuristic) reached confirmed
✓ the file was moved into the vault (it is no longer in place)
✓ the vault is intact (the hashes check out)
✓ the byte-for-byte restore worked on an unprivileged account
✓ the orchestrator's memory peak: 51 MB (promised limit: 128 MB)
```

The consensus's escalation is exercised with real engines: a file with only the
checksum's vote stops at `likely`; another with the checksum **and** a heuristic reaches
`confirmed` and fires the reversible quarantine.

### Run the tests on Linux, not only on the workstation

The first CI run failed and exposed **two defects Windows was hiding**, both already
fixed:

1. **The quarantine was unrecoverable on Linux.** The vault applied `chmod 000`, and
   `Restore` and `quarantine verify` have to *read* the copy — both failed with
   "permission denied". That took down all of Principle I. Windows ignores POSIX
   permissions and lets you read a "0000" file, so the whole suite passed locally. It is
   `0400` now, and the neutralization test actually reads the file.
2. **`.gitignore` swallowed the program.** The pattern `sentinelhost` with no leading
   slash matches any file *or directory* with that name at any depth, and the first
   target was `cmd/sentinelhost/`. The first push published a repository with no `main`
   package, and only the CI build noticed.

The lesson holds for anyone contributing: this project has POSIX filesystem semantics
at its core, and a green suite on Windows is not evidence of anything in that area.

---

## The development environment

During the implementation, Windows Defender quarantined the schema document twice (a
heuristic triggered by the `matched_content` example in section 1.1). The second time
it cost the file: a `git add -A` recorded the deletion and the document disappeared
from the repository for several commits. It is back as
`docs/schema-and-adapters.md`, with that example **redacted** — which is the same rule
the adapters follow, and what makes the file survivable on a Windows workstation.

To clone this repository on Windows, an antivirus exclusion for the folder may still be
needed — the synthetic corpus is inert by construction
(`tests/testdata/corpus/SAMPLES.md`), but a heuristic gets the shape right, not the
intent.
