# Working on SentinelHost

## Language policy — non-negotiable

**Everything that lives in this repository is written in English.** Code,
identifiers, comments, commit messages, documentation, error messages, log
output, CLI help, panel UI strings, test names, shell scripts — all of it.

This is not a style preference. SentinelHost is open source infrastructure for
shared hosting, and shared hosting exists everywhere. A contributor in Jakarta
or Lagos must be able to read a comment explaining *why* the quarantine copies
before it deletes, without a translator. A sysadmin reading a log line at 3 a.m.
must understand it. Portuguese in the repository makes the project unusable to
most of the people it was built for.

The **conversation** with the maintainer may be in any language — that is
separate. The rule applies to artifacts that are committed.

Applies to:

| Artifact | Rule |
|---|---|
| Go code | English identifiers and comments. No `achados`, no `pulados`. |
| Error and log messages | English, including strings a user will read |
| CLI help and output | English |
| Panel UI | English strings; `i18n` may add other locales later, English is the base |
| Markdown docs | English |
| Shell scripts | English, including echoed output |
| Commit messages | English |
| Spec Kit artifacts (`specs/`, `.specify/memory/`) | English |

If you find Portuguese in a file you are editing, translate it as part of the
change. Do not leave a file half-translated.

## What this project is

An orchestrator for existing malware scanners, not a scanner. It has no
detection engine of its own: it runs AMWScan, php-malware-finder (via YARA),
maldet, and native WordPress checksum verification as subprocesses, normalizes
their output to one schema, and consolidates a weighted-consensus verdict.

Read [`.specify/memory/constitution.md`](.specify/memory/constitution.md)
before changing behaviour. It has eight principles that are treated as binding.

## The failure mode this project is built to avoid

A scanner that reports **"0 findings" while having scanned nothing** is worse
than no scanner, because it manufactures false confidence. Almost every defect
found in this codebase so far has had that shape.

Consequences for how you work here:

- An engine that could not run **abstains** — it never counts as "found
  nothing". `ScanStatus.CountsAsVote()` enforces this.
- Anything skipped is **counted and reported**. Silent truncation reads as
  full coverage.
- Every verdict carries its votes, weights and rules, so a user can always
  answer "why was this file quarantined?".

## Verify against reality, not against your own assumptions

See `DECISIONS.md` D-022. Nine defects were found by running the real binary
against real engines and real APIs; **eight were the same mistake** — an
assumption about external behaviour, plus a test written to confirm that
assumption. They passed. Against reality they failed silently.

Therefore, for anything crossing a process boundary — engine CLI flags, output
formats, API responses — the repository stores a **captured real sample** and
the test runs against that:

| Boundary | Fixture |
|---|---|
| AMWScan output | `tests/testdata/raw/amwscan/` |
| YARA output | `tests/testdata/raw/php-malware-finder/` |
| Plugin checksums API | `internal/adapter/wpchecksums/api_format_test.go` |
| Engine flags | `docker/validate-engines.sh`, against the installed binary |

And before trusting a scan:

```bash
make validate-engines
```

That spins up Debian with PHP CLI and YARA, a non-root account, a real
WordPress, real plugins, and compares what the **orchestrator** sees against
what each **engine sees on its own**. Different numbers fail the run. It is not
optional.

## Development

```bash
make test            # full suite
make test-short      # skips the 20k-file SC-002 benchmark
make lint
make build
make release         # linux/amd64 + linux/arm64 + SHA256SUMS
make validate-engines
```

Run the suite on **Linux**, not only on a workstation. Two defects hid behind
Windows ignoring POSIX permissions: the quarantine vault was unrestorable
(`chmod 000` blocks the read that `restore` needs), and `.gitignore` had
swallowed the entire `cmd/sentinelhost/` directory. A green suite on Windows is
not evidence about anything permission-related.

## Conventions

- Conventional Commits.
- Never add AI attribution trailers to commits.
- Platform-specific code goes behind build tags (`_unix.go` / `_windows.go`);
  POSIX-only tests `t.Skip` with an explicit reason, never silently.
- New adapters: keep the rule→category table explicit and versioned next to the
  adapter. An unknown rule becomes `other`/`medium`/`heuristic` — never
  discarded.
- Record decisions where the spec left room in `DECISIONS.md`, citing the
  principle that settles it.
