# Contributing to SentinelHost

## Everything here is written in English

Code, identifiers, comments, commit messages, docs, error messages, log output,
CLI help, panel strings, test names, shell scripts.

Shared hosting exists everywhere, and this project is for the people running it.
A comment explaining *why* the quarantine verifies its copy before deleting the
original is safety-critical knowledge — behind a language barrier, the next
contributor reintroduces the bug. Principle VIII of the constitution.

Discussion in issues and PRs can happen in any language. Committed artifacts
cannot.

## Read the constitution first

[`.specify/memory/constitution.md`](.specify/memory/constitution.md) defines
eight binding principles. **Pull requests that violate a principle get
rejected**, or must come with an approved amendment (recorded motivation, impact
analysis on existing specs, semantic version bump).

The mistakes the constitution exists to prevent:

- Adding a destructive action "just this once" (Principle I).
- Embedding our own signatures or heuristics in the orchestrator (Principle II).
- Depending on root, systemd, or an always-running daemon (Principle III).
- Removing a resource limit "because it was slow" (Principle IV).
- Producing a verdict the user cannot explain (Principle V).
- Letting the verdict engine know about a specific engine (Principle VI).
- Introducing CGO, a frontend build step, or a second config file (Principle VII).
- Committing anything not in English (Principle VIII).

## Development is spec-driven

Every feature starts from `spec.md` → `plan.md` → `tasks.md` under `specs/`.
Don't open a code PR for something that isn't in a spec. If the spec is
ambiguous, record the interpretation you chose in
[`DECISIONS.md`](DECISIONS.md), citing the principle that settles it.

## Verify against reality, not against your own assumptions

This is the hardest-won lesson in the project, recorded as `DECISIONS.md` D-022.

Nine defects were found by running the real binary against real engines and real
APIs. **Eight were the same mistake**: an assumption about how something
external behaves, plus a test written from that same assumption. The tests
passed. Against reality they failed — silently.

The worst case: plugin checksum verification had 16 green tests and detected
nothing, because the API's hash fields were declared as arrays when the real API
returns strings, so every plugin was skipped as "unreadable response".

In an orchestrator this class of bug doesn't raise an error. It produces
**"0 findings" with the engine marked healthy** — the one failure mode a user
cannot detect. So:

```bash
make validate-engines
```

Debian with PHP CLI and YARA, a non-root account, a real WordPress, a real
plugin. It compares what the **orchestrator** sees against what each **engine
sees alone**, and different numbers fail the run. Run it before claiming an
adapter works. It is not optional.

For every process boundary, the repository keeps a **captured real sample** and
the tests run against it — see `tests/testdata/raw/` and
`internal/adapter/wpchecksums/api_format_test.go`.

## Run the tests on Linux

Two defects hid behind Windows ignoring POSIX permissions:

1. The quarantine vault was **unrestorable** — `chmod 000` blocks the read that
   `restore` and `verify` need, killing Principle I outright. Windows lets you
   read a "0000" file, so the whole suite passed locally.
2. `.gitignore` had swallowed `cmd/sentinelhost/` — the first push published a
   repository with no `main` package, and only the CI build noticed.

A green suite on Windows is not evidence about anything permission-related.

## Required tests

- **Contract per adapter**: raw engine output fixtures in
  `tests/testdata/raw/<engine>/`, and a test that checks `Parse` against the
  normalized schema. Fixtures come from real runs, versioned.
- **Consensus corpus**: samples in `tests/testdata/corpus/`. **Synthetic, inert
  webshells only** — never live or executable malware. Each sample is documented
  in `AMOSTRAS.md` with what it simulates and why it is harmless.
- **Quarantine round-trip**: quarantine → restore → compare hash. Byte-for-byte
  identical, or it fails.

```bash
make test          # everything
make test-short    # skips the 20k-file SC-002 benchmark
make lint
make build         # local static binary
make release       # linux/amd64 + linux/arm64 + SHA256SUMS
```

## Adding an adapter

1. Implement `adapter.Adapter` in `internal/adapter/<slug>/`.
2. Keep the rule→(`category`, `severity`, `confidence`) table **explicit and
   versioned** next to the adapter. An unknown rule becomes
   `other`/`medium`/`heuristic` — **never discarded**. Otherwise a real finding
   disappears the moment the engine ships a new signature.
3. Declare `ScopeAware` honestly. An engine that cannot restrict its scan to a
   file list gets invoked **once per cycle**; claiming otherwise multiplies the
   work by the number of batches (this cost 21 minutes per cycle once).
4. Never write outside SentinelHost's working directory. The orchestrator moves
   files, never the adapter.
5. A failure, panic or timeout must become `ScanReport{status: failed}` and an
   abstention — never a collapsed cycle, never a clean vote.
6. GPL engines are invoked as subprocesses only. No linking.
7. Register it in `cmd/sentinelhost/common.go` and add fixtures.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), in English. Small
commits, one per spec task where practical:

```text
feat(verdict): weighted consensus engine (T014)
fix(quarantine): re-hash immediately before acting (FR-018)
```

Never add AI attribution trailers.
