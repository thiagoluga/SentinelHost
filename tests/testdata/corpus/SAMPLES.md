# Corpus samples

Every sample under `synthetic/` is **inert**. The three guarantees, in every sample
without exception:

1. The first executable statement is an `exit()`.
2. The function-name fragments (`'ev' . 'al'`) are **never** joined into a dynamic
   call — without the joining, no execution is possible.
3. No sample makes a network call, writes to disk, reads user input or opens a
   process.

The marker `SENTINELHOST-SYNTHETIC-CORPUS` appears in plain text in all of them.

## Samples the consensus MUST flag

| File | Simulates | `category` | `severity` | expected `confidence` |
|---|---|---|---|---|
| `01-webshell-parameter.php` | A webshell taking a command from a request parameter | `webshell` | `critical` | `heuristic` |
| `02-backdoor-eval-post.php` | A backdoor evaluating code coming from POST | `backdoor` | `critical` | `heuristic` |
| `03-obfuscation-blob.php` | A long encoded blob + unintelligible names, with no readable code | `obfuscation` | `high` | `heuristic` |
| `04-uploader-no-validation.php` | An upload with no type/extension validation inside the web root | `dropper` | `high` | `heuristic` |
| `05-spam-seo-links.php` | Spam links shown only to the search engine's crawler (cloaking) | `spam_seo` | `medium` | `heuristic` |
| `06-phishing-harvest.php` | A cloned page that harvests credentials and exfiltrates them | `phishing` | `critical` | `heuristic` |
| `07-injection-in-theme.php` | A legitimate theme file with one injected line | `injection` | `high` | `heuristic` |
| `08-suspicious-location.php` | PHP inside `wp-content/uploads` — the signal is the **place** | `suspicious_location` | `medium` | `anomaly` (expected: `suspicious`) |
| `09-known-marker.php` | A deterministic marker, this corpus's "EICAR" | `known_malware` | `critical` | `signature` |
| `10-core-tampered.php` | A `wp-includes/` file that does not match the official checksum | `core_integrity` | `critical` | `signature` |
| `11-loose-permissions.php` | A 0777 file in the web root — the signal is the **mode** | `suspicious_perms` | `medium` | `anomaly` (expected: `suspicious`) |
| `12-reverse-shell-described.php` | A reverse shell: only the configuration data, no primitive at all | `backdoor` | `critical` | `heuristic` |

Notes per sample:

- **08 and 11** are deliberately banal in content. The finding has to come from the
  location and the permissions, not from a pattern in the text. They exist to prove
  the consensus handles `confidence=anomaly`, which is the weakest vote — and to pin
  the behaviour that **an anomaly alone never reaches `likely`**: two anomaly votes
  add up to 0.88 over the ceiling of 2.0 = 0.44, that is `suspicious`. If a single
  anomaly signal were enough for `likely`, a file in the wrong place would trigger an
  "action recommended" alert. That is why they stay out of SC-001's denominator
  (`DECISIONS.md` D-016).
- **09** is the EICAR analogue: an agreed marker that the test adapters recognize
  with `confidence=signature`, with no behaviour existing at all. It is what lets us
  test the "two engines with a signature → `confirmed`" path without real malware. The
  declared engines are `maldet` (weight 1.0) and `amwscan` (0.8): 1.8 over the ceiling
  of 2.0 = 0.90, exactly the `confirmed` threshold the schema documentation uses as an
  example.
- **10** exercises the maximum-weight vote (`wp-checksums`, weight 1.5). It is the
  only path by which **one** engine alone gets close to `confirmed`.
- **12** is the one that worries us most, so it is the one with the least code. A
  reverse shell needs a socket, a process and descriptor redirection; none of the
  three appears, not even broken into pieces.

## Files the consensus must NOT flag

| File | Why it commonly produces a false positive |
|---|---|
| `clean/base64-legitimate.php` | Uses `base64_encode` for what it is meant for (a data URI, an HMAC signature). A scanner flags any base64. |
| `clean/util.min.js` | Minified JS has high entropy, one-letter names and enormous lines — the same signals as obfuscation. |
| `clean/wp-includes/version.php` | A core file whose hash **matches** the official checksum. |
| `clean/legitimate-plugin.php` | An ordinary plugin, the baseline: if the consensus flags this one, the problem is in the engine. |

`clean/wp-includes/version.php` has a special role in the SC-001 test: two engines
flag it with `confidence=signature` (which would give `confirmed`) and the test
verifies that the verdict comes out `clean` with
`clean_reason=official_checksum_match`. The official-checksum protection is a
**veto**, not a vote — see `DECISIONS.md` D-005.

## Manifest

`manifest.json` carries the same information in a machine-readable format. It is what
the SC-001 test reads in order to know what to expect from each file. When adding a
sample, update both — the test fails if a file in the corpus is not in the manifest,
precisely so nobody adds a sample without declaring the expectation.
