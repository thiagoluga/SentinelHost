# Provenance — maldet

- **Engine**: Linux Malware Detect (`maldet`)
- **Reference version for the format**: **1.6.6**, actually installed and executed as an
  unprivileged account in a Debian bookworm container, from
  `https://www.rfxn.com/downloads/maldetect-current.tar.gz`
- **Invocation**:
  ```
  maldet --config-option quarantine_hits=0,quarantine_clean=0,quarantine_suspend_user=0 -a <root>
  maldet --report <SCANID> dump
  ```
- **Format**: a text report, printed by the `dump` argument.

## Six defects that only the real engine found

An earlier version of these fixtures was **invented**, written from the same reading of
the documentation as the code. Every unit test built on it passed. Against the real
1.6.6 the adapter did not work at all, and six separate reasons why came out one at a
time. This is D-022's whole argument in one adapter.

| # | The assumption | What 1.6.6 actually does | Cost if shipped |
|---|---|---|---|
| 1 | `maldet --report <id>` prints the report | It passes the session file to `$EDITOR`. The undocumented second argument **`dump`** is what prints | abstention every cycle, or a cycle hung until timeout on a host that has `vi` |
| 2 | The report opens with `malware detect scan report for user:` | No such line exists anywhere | every genuine report rejected as off-format |
| 3 | `--config-option` can be repeated per variable | It takes **one** comma-separated value | `quarantine_hits=0` dropped → **maldet moves the user's files into its own non-reversible quarantine** |
| 4 | A signature type is alphabetic (`[A-Za-z]+`) | `{MD5}` contains a digit | a third of hits silently dropped |
| 5 | A binary that runs is an engine that works | `scan_user_access="0"` is the **default**: maldet refuses every non-root account, printing the version banner and exiting 0 — from `--version` too | Probe reads a version off a refusal and reports the engine **healthy** where it can never scan |
| 6 | A finished scan announces `SCAN ID:` | The scan says `scan report saved, to view run: maldet --report <id>`. `SCAN ID:` belongs to the report, which cannot be fetched without the id | no id found after every successful scan → abstention every cycle |

Defects 5 and 6 are the ones no amount of care with the documentation would have caught,
and both produce the failure mode this project exists to prevent: an engine listed as
installed and healthy, contributing nothing.

A new fixture only enters here after coming out of a real run.

## Two gates, two different remedies

A fresh maldet refuses an unprivileged account **twice**, and the fixes are not the
same — so the adapter reports them separately (`accessGateReason`). Telling a user to
change a setting that is already correct is worse than telling them nothing.

1. `scan_user_access="0"`, the shipped default
   (`maldet-user-access-disabled.txt`) → the admin sets it to `"1"` in
   `/usr/local/maldetect/conf.maldet`.
2. Access enabled but the per-user paths do not exist yet
   (`maldet-pubpaths-missing.txt`) → the admin runs `maldet --mkpubpaths` as root, or
   waits for maldet's `cron.pub`.

Both print at **exit 0**, with the full version banner above them. That is what made
defect 5 possible.

The practical consequence for this project: **on most shared hosting maldet is present
and unusable**, because nobody flipped either switch. The adapter's job there is to
abstain and hand the user the exact line to forward to support — not to look healthy.

## Format

A real report, with the warning block that appears whenever the quarantine is off —
which, since the adapter disables it on every invocation, is every report this project
will ever parse (`quarantine-disabled-warning.txt`):

```text
Linux Malware Detect v1.6.6
            (C) 2002-2023, R-fx Networks <proj@rfxn.com>
            (C) 2023, Ryan MacDonald <ryan@rfxn.com>
This program may be freely redistributed under the terms of the GNU GPL v2

HOST:      validation-container
SCAN ID:   260730-0927.16
STARTED:   Jul 30 2026 09:27:48 +0000
COMPLETED: Jul 30 2026 09:27:50 +0000
ELAPSED:   2s [find: 0s]

PATH:          /home/hosting/s2
TOTAL FILES:   2
TOTAL HITS:    1
TOTAL CLEANED: 0

WARNING: Automatic quarantine is currently disabled, detected threats are still accessible to users!
To enable, set quarantine_hits=1 and/or to quarantine hits from this scan run:
/usr/local/sbin/maldet -q 260730-0927.16

FILE HIT LIST:
{MD5}php.corpus.marker.v1 : /home/hosting/s2/x.php
===============================================
Linux Malware Detect v1.6.6 < proj@rfxn.com >
```

That warning block is worth reading twice. It is maldet **confirming our flag took
effect** — the host in the validation image has `quarantine_hits="1"` in
`conf.maldet`, and the file was still left in place. It is also a trap: the
`/usr/local/sbin/maldet -q 260730-0927.16` line carries a token shaped exactly like a
scan id, and picking it up would mean fetching a different scan's report.

The hit list's shape is confirmed by maldet's own code rather than by inference —
`internals/functions` parses its own report with:

```sh
awk '/FILE HIT LIST:/{flag=1;next}/^=======/{flag=0}flag{print $3}'
grep -E '^{.*}' $sessdir/session.$scanid > $sessdir/session.hits.$scanid
```

So: the section is headed by `FILE HIT LIST:`, ends at a line of `=`, every hit line
starts with `{`, and the path is the third whitespace-separated field.

## Peculiarities the adapter has to handle

- The prefix in braces is the signature's **type**: `{HEX}` and `{MD5}` are exact
  signatures (`confidence=signature`); `{YARA}` and `{CAV}` are heuristics. That
  distinction changes the vote's weight and must not be lost — the type can contain a
  digit, and an `[A-Za-z]+` class silently skipped every `{MD5}` line.
- **A quarantined hit gains ` => <path>`.** maldet's own code tests
  `[[ "$hit_line" == *"=>"* ]]`, and the vault copy is the last field. Two consequences:
  the path to report is the original, before the arrow; and the arrow's presence is
  proof maldet moved a file despite this adapter disabling that, which is a Principle I
  violation to report loudly rather than a finding to list
  (`maldet-quarantined.txt`, `DECISIONS.md` D-025).
- `TOTAL HITS` has to match the number of lines in the list. A divergence means a
  truncated report → an abstention, not a partial report accepted as good.
- The report comes after the scan, in a separate invocation, and the scan announces the
  id only inside a `maldet --report <id>` suggestion.
- **`scan_ignore_root="1"` is the default**, so maldet skips files owned by root. It is
  not a problem in production, where the site belongs to the account user, but it makes
  a scan look empty when testing as root.
- **`--config-option` does NOT persist.** An earlier version of this file claimed it
  writes the values into `conf.maldet` for later runs. That was checked against the real
  engine and is wrong: after a run with `quarantine_hits=0`, `conf.maldet` still read
  `quarantine_hits="1"`. The values apply to the invocation only — which is better than
  what was documented here, and is recorded because a wrong note in a provenance file is
  exactly the kind of thing that gets trusted later.

## How the validation image forces a real hit

maldet loads ~51,000 signatures and finds **nothing** in this repository's corpus: the
samples are inert by construction and Principle VI forbids adding real executable
malware to change that. Zero hits leaves the whole half of the adapter that matters
unreached — no hit-line parsing, and no proof that `quarantine_hits=0` actually stops
maldet from moving files.

So `docker/Dockerfile.validation` teaches maldet **one custom signature for our own
inert marker file**, in the format of its shipped `sigs/md5v2.dat`:

```
<md5>:<size>:{MD5}php.corpus.marker.v1
```

MD5 and not HEX on purpose. MD5 is the path maldet resolves itself
(`val_hash=$(grep -m1 $hash $sig_user_md5_file $sig_md5_file)`), while HEX matching
goes through a perl fifo and a ClamAV that is not installed there — a custom hex
string gets loaded, counted in maldet's `1 USER` total, and never matched. Loaded but
never matched is this project's own worst failure mode wearing maldet's clothes.

maldet's detection quality is not what is being tested. Its behaviour when it *does*
hit something is.
