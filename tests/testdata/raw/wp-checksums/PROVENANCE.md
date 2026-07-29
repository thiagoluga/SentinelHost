# Provenance — wp-checksums (native adapter)

- **Engine**: native to SentinelHost, no external binary
- **Data source**: the public API `https://api.wordpress.org/core/checksums/1.0/`
- **Invocation**: `GET ?version=<version>&locale=<locale>`
- **Format**: JSON shaped `{"checksums": {"relative/path": "<md5>"}}`

This adapter's "raw output" is the **API's response**, archived like any other
engine output. That allows reprocessing an old scan without querying the network
again.

## Privacy

The query sends only the WordPress **version** and **locale**. No file, path or hash
of the user's leaves the hosting — an explicit constraint of the constitution. The
comparison happens entirely locally.

## Peculiarities the adapter has to handle

- The API returns **MD5**, not SHA-256. The adapter compares by MD5 and reports the
  SHA-256 in the `Finding`, because the normalized schema uses SHA-256 as the
  deduplication key across engines.
- A **missing** file that should exist and a **modified** file are different
  findings, both `core_integrity`. An **extra** file inside `wp-admin/` or
  `wp-includes/` is also a finding: the official core has no extra files.
- The files that **match** the checksum go into the `ScanReport`'s `clean_files`. It
  is the only engine that votes positively for legitimacy, and that vote becomes a
  **veto** in the verdict engine (`DECISIONS.md` D-005).
- With no network, or with a WP version the API does not recognize, the adapter
  **abstains**. It never declares the core clean for lack of information.
- A site that is not WordPress: an abstention, without penalizing the other engines'
  score (an explicit edge case in the spec).
