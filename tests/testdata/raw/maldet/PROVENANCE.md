# Provenance — maldet

- **Engine**: Linux Malware Detect (`maldet`)
- **Reference version for the format**: 1.6.5
- **Invocation**: `maldet -a <path>` followed by `maldet --report <SCANID>`
- **Format**: a text report with a metadata header and the `FILE HIT LIST`.

## Why it is optional in the MVP

`maldet` works **partially** without root: the scan runs, but the signature update
and the native quarantine usually need privilege. SentinelHost uses only the scan
and does its own quarantine — maldet's would violate Principle I, because it is not
our reversible, recorded quarantine.

When `maldet` is not available, the adapter abstains with a reason and the consensus
proceeds with the other engines.

## Format

```text
malware detect scan report for user:
SCAN ID: 260723-0300.12345
TIME: Jul 23 03:04:41 -0300
PATH: /home/user/public_html
TOTAL FILES: 412
TOTAL HITS: 2
TOTAL CLEANED: 0

FILE HIT LIST:
{HEX}php.base64.v23eb : /path/to/file.php
{YARA}php_backdoor : /another/path.php
```

## Peculiarities the adapter has to handle

- The prefix in braces is the signature's **type**: `{HEX}` and `{MD5}` are exact
  signatures (`confidence=signature`); `{YARA}` and `{CAV}` are heuristics. That
  distinction changes the vote's weight and must not be lost.
- `TOTAL HITS` has to match the number of lines in the list. A divergence means a
  truncated report → an abstention, not a partial report accepted as good.
- The report comes after the scan, in a separate invocation. If `--report` fails,
  the scan's result is useless: an abstention.
