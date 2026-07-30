# Webhooks contract

Every event is delivered as **one** JSON `POST` to the registered endpoint.
SentinelHost never sends files, only metadata and hashes (the constitution's privacy
principle).

## Delivery

```http
POST /your-endpoint HTTP/1.1
Content-Type: application/json
User-Agent: SentinelHost/0.1.0
X-Sentinel-Event: verdict.confirmed
X-Sentinel-Delivery: d_20260723_000441
X-Sentinel-Timestamp: 1785815082
X-Sentinel-Signature: sha256=9f8a7b6c...
```

### The signature

`X-Sentinel-Signature` is `sha256=` + a hexadecimal HMAC-SHA256, computed over
`<timestamp> + "." + <raw body>`, with the webhook's secret as the key.

The timestamp enters the signature so a captured delivery cannot be replayed
indefinitely. **Reject deliveries whose timestamp is more than 5 minutes old** and
**compare the signature in constant time**.

Verification (PHP):

```php
$payload  = file_get_contents('php://input');
$ts       = $_SERVER['HTTP_X_SENTINEL_TIMESTAMP'];
$expected = 'sha256=' . hash_hmac('sha256', $ts . '.' . $payload, $secret);
if (!hash_equals($expected, $_SERVER['HTTP_X_SENTINEL_SIGNATURE'])) {
    http_response_code(401);
    exit;
}
```

### Retries

Any response outside `2xx`, a timeout (10 s) or a connection error triggers a retry
with exponential backoff: **5 attempts** at 1 s, 4 s, 16 s, 64 s, 256 s (with jitter).
`X-Sentinel-Delivery` is **stable across the attempts** — use it for idempotency on your
side.

After the fifth failure the delivery is marked as `failed` and stays in the panel's
history with the real error code. A delivery that fails **never** blocks the scan cycle
nor the quarantine.

## The envelope

```json
{
  "schema_version": "1.0",
  "event": "verdict.confirmed",
  "delivery_id": "d_20260723_000441",
  "occurred_at": "2026-07-23T03:05:02-03:00",
  "instance": { "id": "i_a1b2c3", "hostname": "srv12.hosting.com", "root": "/home/user/public_html" },
  "data": { }
}
```

`data` carries the normalized object matching the event.

## Events

| Event | When | `data` |
|---|---|---|
| `verdict.confirmed` | A verdict reaches `confirmed` | `Verdict` |
| `verdict.likely` | A verdict reaches `likely` | `Verdict` |
| `verdict.suspicious` | A verdict reaches `suspicious` | `Verdict` |
| `quarantine.action` | A file was quarantined, restored or purged | `QuarantineEvent` |
| `scan.completed` | A cycle finishes (even with no findings) | `ScanSummary` |
| `engine.failed` | An engine fails, hits its timeout or is killed | `ScanReport` |

Each webhook declares which events it subscribes to. No subscription, no delivery.

### `quarantine.action`

```json
{
  "action": "quarantined",
  "quarantine_ref": "q_20260723_000132",
  "verdict_id": "v_3c2d1e",
  "original_path": "/home/user/public_html/wp-content/uploads/2026/07/cache.php",
  "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "size_bytes": 14382,
  "reversible": true,
  "retention_until": "2026-08-22T03:05:02-03:00"
}
```

`action` ∈ `quarantined`, `restored`, `purged`, `failed`. `reversible` is always `true`
while the item exists in the vault — a permanent purge only happens by manual action or
after the configured retention.

### `scan.completed`

```json
{
  "scan_id": "s_20260723_0300",
  "mode": "incremental",
  "started_at": "2026-07-23T03:00:05-03:00",
  "finished_at": "2026-07-23T03:04:41-03:00",
  "files_considered": 18234,
  "files_scanned": 412,
  "engines_ran": ["wp-checksums", "amwscan", "php-malware-finder"],
  "engines_abstained": [{ "engine": "maldet", "reason": "the binary was not found on PATH" }],
  "verdicts": { "confirmed": 1, "likely": 0, "suspicious": 3, "clean": 408 },
  "actions": { "quarantined": 1, "recommended": 0, "failed": 0 }
}
```

`engines_abstained` always travels with the summary: a cycle in which half the engines
failed must not look like a clean cycle (Principle VI).

### `engine.failed`

`data` is the complete `ScanReport`, with `status` (`failed`/`timeout`/`killed`) and
`error` filled in. It exists because silent coverage degradation is an orchestrator's
most dangerous failure mode.

## Test delivery

The panel and the CLI (`sentinelhost alert --test-webhook <id>`) fire a
`verdict.confirmed` event with sample `data` and a `delivery_id` prefixed with
`d_test_`. The real result (the HTTP status, the body, a connection error) is shown
right away — with no optimistic "sent successfully".
