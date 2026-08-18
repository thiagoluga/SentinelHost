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

3. **A real capture is necessary and not sufficient.** The `=> backdoor` line below came
   out of a real run and was still read wrongly, because one sample cannot tell you which
   parts of a line are structure and which are content. Where a format matters, capture
   more than one file — from more than one site if you can. The second capture here came
   from a live account and disagreed with the first about the thing that mattered most.

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
`File:`. `Exploits:` and `Functions:` only separate sections.

**The indented `      => ...` line is the SOURCE THAT MATCHED, not a category.** This
document used to say the opposite, and the adapter was built on it — reading that line as
the engine's category and giving it priority over everything else.

The fixture above is genuine. That is the part worth sitting with. `=> backdoor` really
was what the engine printed, because the matched content of that particular hit happened
to be the word "backdoor". One sample's coincidence was read as structure, and a parser
was written to it. Against a live account the same position holds things like:

```text
 => [!] Function (exec) [line 147]
    - Potentially dangerous function `exec`
      => exec('kill -' . (int) $signal . ' ' . (int) $pid . ' 2>/dev/null', $out, $code)
```

and the resulting "categories" read `lave`, `tressa`, `ipconfig`, `suhosin` — fragments of
somebody's source. (`lave` is `eval` backwards: AMWScan detects strrev-obfuscated calls and
prints the reversed string it found.)

**The discriminator is the parenthesised token**, and it is what the adapter classifies on:
`Function (eval)` is a backdoor indicator, `Function (exec)` a webshell one,
`Signature (11413268)` a hash that falls through to the rule name and reports known
malware. See `real-0.15.1-function-and-exploit.txt`, captured from a live hosting account.

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
- The txt report **does include the matched source**, on the indented `=>` line, and it
  can be long — hundreds of characters of the scanned file, truncated by the engine with
  an ellipsis. This document previously claimed the opposite. The adapter keeps it as
  evidence, through `SanitizeSnippet`, and never classifies on it.

## `real-0.15.1-function-and-exploit.txt`

Captured from a live cPanel hosting account on 2026-08-18, from the report the orchestrator
archives at `raw_ref` (which only holds the report at all since #94 — before that it
pointed at the process's stdout, which `--silent` keeps empty).

Sanitised: real paths rewritten to `/home/user/...`, and snippets longer than 200
characters truncated the way the engine itself truncates them. Nothing else is altered —
the spacing, the `[line N]` that is present on some findings and absent on others, and the
blank line between blocks are all as the engine wrote them.

It covers what the container's corpus never produced: `Function (eval)`, `Function (exec)`,
`Function (assert)`, `Function (shell_exec)`, `Function (proc_open)`, `Exploit (execution)`,
`Exploit (hex_char)`, and `Signature (<hash>)` — including two strrev-obfuscated hits whose
matched source reads `Lave` and `tressa`.

The distribution on that account, for anyone deciding what to add to the rule table next:

| rule | count | notes |
|---|---|---|
| `Exploit` | 779 | `execution` 732, then `base64_long`, `nano`, `hex_char`, … |
| `Function` | 333 | `eval` 199, `assert` 42, `exec` 29, `shell_exec` 12, … |
| `Signature` | 38 | hashes |

`Function` tokens are largely covered by the table already. The `Exploit` vocabulary is
not, and each entry needs the engine's own description read before it is mapped — they are
in the report, on the `- ` line under each finding.
