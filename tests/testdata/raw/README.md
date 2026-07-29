# Engine raw-output fixtures

Each directory here holds **raw output** from one engine, in the exact format it
produces. They are the input of the contract tests: the test feeds `Parse()` with
the file and checks that the normalized `ScanReport` comes out right.

## What is under test here

The **parser**, not the detection. A contract test answers "does the adapter
understand what this engine says?" — never "does this engine find malware?".

That is why the files and snippets cited inside the fixtures point at the
repository's own synthetic corpus (`DECISIONS.md` D-009): the format is the
contract, and the content it points at can be synthetic without the test losing
any power.

## Provenance

Each directory has a `PROVENANCE.md` declaring which engine version the format was
derived from. When an engine changes format, add a **new** fixture with the new
version instead of editing the old one — the adapter has to keep reading both,
because the user's hosting may have the older version.

## Mandatory cases per engine

Every engine needs, at a minimum:

| Fixture | Why it is mandatory |
|---|---|
| `success-with-findings.*` | The normal path. |
| `success-no-findings.*` | Zero findings has to become `status=completed` with an empty list — and **not** be confused with a failure. |
| `empty-output.*` | An engine that died without writing anything must not become "found nothing": it has to become an abstention. |
| `corrupted-output.*` | Truncated or unreadable output has to become an abstention with a reason, never a panic and never a vote. |

Those four cover the distinction that matters most in this project: **"found
nothing" and "could not look" are different things** (Principle VI). A parser that
confuses the two turns an engine failure into a certificate of health.
