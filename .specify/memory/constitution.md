# SentinelHost Constitution

**Version**: 1.1.0 | **Ratified**: 2026-07-23 | **Last amended**: 2026-07-29

SentinelHost is an open source orchestrator of malware scanners for shared
hosting (cPanel and similar). It does NOT implement a detection engine of its
own: it coordinates existing open source engines and consolidates their results
into a consensus verdict. These principles govern every design and
implementation decision. Violations require a recorded justification.

## Core Principles

### I. Reversibility above all

No destructive action is irreversible by default. Quarantine = move + record +
block, never delete. Permanent purge happens only by explicit user action or
after a configured retention period. A false positive that gets acted on must
never take the user's site down permanently.

### II. Orchestrate, don't compete

Detection comes from external engines (maldet, PHP Malware Finder, AMWScan,
Wordfence CLI, ClamAV) and from integrity verification against official
checksums. The project maintains no signature database of its own. GPL engines
are invoked exclusively as external processes via their CLI — never linked — so
that the orchestrator can keep an MIT license.

### III. Works without root, in user space

Every essential feature must work on a cheap shared hosting account: no root,
no systemd, possibly no SSH (falling back to cPanel cron). Features requiring
privileges (global inotify, the ClamAV daemon) are opportunistic: used when
available, never required.

### IV. A well-behaved hosting tenant

The scanner must never get the user's account suspended for resource abuse. CPU
limits (nice 19 by default), pauses between batches, incremental scans by
default, a maximum file size and a per-engine timeout are mandatory and active
by default.

### V. Transparent consensus

Every verdict shows which engines voted, with what weight, and by which rule.
The user can always answer "why was this file quarantined?". Automatic verdicts
only at the `confirmed` level; anything below always waits for a human decision.
An observation mode (no automatic action) is available.

### VI. The normalized schema is the contract

Adapters convert any engine output into the versioned normalized schema
(docs/schema-and-adapters.md). The verdict engine only ever knows the schema,
never a specific engine. Raw output is archived for auditing and reprocessing.
An adapter failure = abstention in the consensus, never a "clean vote" and never
a collapsed cycle.

### VII. Operational simplicity

Distributed as a single static Go binary, with no mandatory external
dependencies. Configuration in one readable file (TOML). State in SQLite (pure
Go driver, no CGO). Web panel embedded in the binary itself. One-command
install.

### VIII. English is the language of the repository

Everything committed to this repository is written in English: code,
identifiers, comments, error and log messages, CLI output, panel UI strings,
documentation, shell scripts, commit messages, and specification artifacts.

This is not a style preference. Shared hosting exists everywhere, and a
contributor must be able to read *why* the quarantine copies before it deletes
without needing a translator. Discussion between maintainers may happen in any
language; artifacts that are committed may not.

The panel ships English as its base locale. Additional locales are welcome
through i18n, never by replacing the base.

## Additional constraints

- Panel security: authentication mandatory by default; listens on localhost by
  default (access via SSH tunnel or a deliberately opened port).
- Malicious content is never executed nor re-served: snippets shown in the UI
  are truncated and sanitized; quarantined files lose execute permission and are
  stored with a neutralized extension.
- Privacy: no user file ever leaves the hosting account; external lookups send
  only hashes and version slugs (e.g. the WordPress.org checksums API).

## Development workflow

Spec-driven (Spec Kit): every feature starts from spec.md → plan.md → tasks.md.
Contract tests for each adapter (raw output samples versioned in the
repository). A test corpus of disabled/synthetic webshells to validate the
consensus — never live, executable malware in the repository.

## Governance

Amendments to this constitution require: a record of the motivation, an impact
analysis on existing spec artifacts, and a semantic version increment. Pull
requests that violate a principle must be rejected or accompanied by an approved
amendment.

### Amendment log

**1.1.0 — 2026-07-29 — Principle VIII added (English as the repository language)**

*Motivation.* The project was written in Portuguese, which made it unreadable to
most of the audience it targets. SentinelHost exists for people running cheap
shared hosting, and that population is global. A comment explaining why the
quarantine verifies its copy before deleting the original is safety-critical
knowledge; locking it behind a language barrier means the next contributor
reintroduces the bug.

*Impact on existing artifacts.* All of `specs/`, `docs/`, `internal/`, `cmd/`,
`tests/`, the shell scripts and the panel assets were translated. The
`spec.md` assumption stating "panel interface in pt-BR for the MVP, with i18n
prepared for en" is **reversed**: English becomes the base locale and other
locales arrive through i18n. No functional behaviour changed — the translation
covers identifiers, comments and strings, and the test suite plus
`make validate-engines` were used to confirm equivalence.

*Not covered.* This amendment does not require translating captured third-party
output in `tests/testdata/raw/`. Those files are evidence of what an external
engine actually printed; rewriting them would destroy their value as fixtures.
