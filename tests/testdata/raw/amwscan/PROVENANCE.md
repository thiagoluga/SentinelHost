# Provenance — AMWScan

- **Engine**: AMWScan (`marcocesarato/PHP-Antimalware-Scanner`)
- **Reference version for the format**: **0.15.1**, actually executed in the
  `docker/Dockerfile.validation` container (Debian bookworm, PHP 8.2.32)
- **Invocation**:
  ```
  php scanner.phar --report --report-format txt --path-report <base> \
      --no-colors --silent [--max-filesize N] [--filter-paths a,b,c] <root>
  ```
- **Format**: **text**, written to a FILE (`<base>.log`), not to stdout.

## An important correction

An earlier version of these fixtures was **invented JSON**, with rule names that do
not exist (`EVAL_POST`, `OBFUSCATED_BLOB`, `SIGNATURE_KNOWN_MARKER`) and a
`--format json` flag the engine does not have. The parser passed its own tests and
would have recognized absolutely nothing in production.

The mistake only surfaced when the engine was actually executed. Two lessons that
hold for any new fixture:

1. **AMWScan has no JSON output.** The formats are `html` and `txt`, through
   `--report-format`. There is no `--format`.
2. **It writes to a file, not to stdout.** With `--silent`, stdout stays empty —
   and mistaking "empty stdout" for "nothing found" is this adapter's classic bug.

A new fixture only enters here after coming out of a real run. Run
`make validate-engines` and copy it from the container.

## Format

```text
Scan date: 2026-07-29 15:59:45
File: /path/to/file.php
Exploits:
 => [!] Signature (d30fc49e) [line 4]
    - Malware Signature (hash: d30fc49e)
      => backdoor
```

Hierarchy: `File:` opens a block and everything below belongs to it until the next
`File:`. `Exploits:` and `Functions:` only separate sections. The line
`      => <tag>` is the category the engine assigned, and the adapter gives it
priority over the rule name — `Signature` with tag `backdoor` says more than
`Signature` alone.

## Peculiarities the adapter has to handle

- **`--report` is not optional.** Without it AMWScan enters interactive mode and
  may **clean or delete** files. This project's quarantine is reversible and
  recorded; its own is not.
- **The previous report has to be deleted before each run.** If the engine fails,
  last cycle's file is still there and `Parse` would return old findings as new.
- **The engine needs PHP extensions beyond the interpreter.** Without `mbstring` it
  dies with exit 255 and **zero output** — which is why `Probe` really executes
  `--version` instead of only checking that the file exists.
- **The incremental scope is applied by the adapter, not by the engine.** Two
  limitations of `--filter-paths`, both measured in the container:

  1. **AND semantics, not OR.** With one path it works; with two or more the engine
     runs, exits 0, writes the report and flags **nothing** — not even the files
     that would match on their own. Green engine, clean report, infected site.
  2. **It filters the report, not the walk.** One execution per file cost 1m37s for
     11 files, because each one walked the whole root again.

  That is why the adapter does **one execution per cycle, over the root**, and
  discards in `Parse` what the orchestrator did not ask for. It costs more CPU than
  ideal, but AMWScan simply does not know how to scan a file list.
- The engine does not report a hash. The orchestrator computes the sha256, because
  it is the deduplication key across engines.
- The txt report **does not include the code snippet**, only the rule and the line.
  Better that way: malicious content does not need to travel through the system for
  the user to understand a finding.
