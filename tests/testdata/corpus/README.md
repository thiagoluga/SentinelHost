# Test corpus

This directory exists to validate the **consensus engine**, not to validate any
engine's detection ability.

## Absolute rule: nothing here is live malware

The project's constitution forbids executable malware in the repository. Every
sample under `synthetic/` is **inert by construction**:

- it reproduces the **structure** of a malicious pattern (obfuscated concatenation,
  dynamic callback, base64 blob, upload without validation), but
- it **never** assembles a working executable call, and
- it carries the marker `SENTINELHOST-SYNTHETIC-CORPUS` in plain text.

[`SAMPLES.md`](SAMPLES.md) documents, one by one, what each sample simulates, why it
is harmless and which category/severity/confidence of the normalized schema it
should receive. See `DECISIONS.md` D-010.

If you open one of these samples in a browser or hand it to `php`, it prints a
warning and exits. It opens no shell, writes no file, makes no network call.

## Structure

```text
corpus/
├── synthetic/       samples the consensus MUST flag
├── clean/           legitimate files the consensus must NOT flag
├── SAMPLES.md       what each sample simulates and why it is inert
└── manifest.json    the per-file expectation, read by the SC-001 test
```

`clean/` holds files that commonly produce false positives in a malware scanner:
legitimate PHP with `base64_encode` (normal usage), minified JS, and a WordPress
core file whose hash matches the official checksum. Detecting any of them as
`confirmed` fails SC-001.

## Workstation antivirus

An antivirus may react to this directory even with inert samples — the heuristic gets
the shape right, not the intent. If the repository clone comes out incomplete on
Windows, add an exclusion for the repository folder. No sample here can cause harm,
but that is a claim you should verify by reading the files, not by trusting this
README.

## What this corpus is NOT

It is not a detection benchmark. The real engines (AMWScan, php-malware-finder,
maldet) are not executed in the automated tests — see `DECISIONS.md` D-011. SC-001 is
verified with test adapters that emit fixed `ScanReport`s, because what is under test
is the consensus consolidation, not a third party's signature.
