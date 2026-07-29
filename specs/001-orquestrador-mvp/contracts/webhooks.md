# Contrato de webhooks

Todo evento é entregue como **um** `POST` JSON ao endpoint cadastrado.
O SentinelHost nunca envia arquivos, apenas metadados e hashes (Princípio de
privacidade da constituição).

## Entrega

```http
POST /seu-endpoint HTTP/1.1
Content-Type: application/json
User-Agent: SentinelHost/0.1.0
X-Sentinel-Event: verdict.confirmed
X-Sentinel-Delivery: d_20260723_000441
X-Sentinel-Timestamp: 1785815082
X-Sentinel-Signature: sha256=9f8a7b6c...
```

### Assinatura

`X-Sentinel-Signature` é `sha256=` + HMAC-SHA256 hexadecimal, calculado sobre
`<timestamp> + "." + <corpo bruto>`, com o segredo do webhook como chave.

O timestamp entra na assinatura para que uma entrega capturada não possa ser
reenviada indefinidamente. **Rejeite entregas com timestamp com mais de 5
minutos** e **compare a assinatura em tempo constante**.

Verificação (PHP):

```php
$payload = file_get_contents('php://input');
$ts      = $_SERVER['HTTP_X_SENTINEL_TIMESTAMP'];
$esperado = 'sha256=' . hash_hmac('sha256', $ts . '.' . $payload, $segredo);
if (!hash_equals($esperado, $_SERVER['HTTP_X_SENTINEL_SIGNATURE'])) {
    http_response_code(401);
    exit;
}
```

### Retentativas

Qualquer resposta fora de `2xx`, timeout (10 s) ou erro de conexão dispara
retentativa com backoff exponencial: **5 tentativas** em 1 s, 4 s, 16 s, 64 s,
256 s (com jitter). `X-Sentinel-Delivery` é **estável entre as tentativas** —
use-o para idempotência do seu lado.

Depois da quinta falha a entrega é marcada como `failed` e fica no histórico do
painel com o código de erro real. Uma entrega que falha **nunca** bloqueia o
ciclo de scan nem a quarentena.

## Envelope

```json
{
  "schema_version": "1.0",
  "event": "verdict.confirmed",
  "delivery_id": "d_20260723_000441",
  "occurred_at": "2026-07-23T03:05:02-03:00",
  "instance": { "id": "i_a1b2c3", "hostname": "srv12.hospedagem.com", "root": "/home/user/public_html" },
  "data": { }
}
```

`data` carrega o objeto normalizado correspondente ao evento.

## Eventos

| Evento | Quando | `data` |
|---|---|---|
| `verdict.confirmed` | Veredito atinge `confirmed` | `Verdict` |
| `verdict.likely` | Veredito atinge `likely` | `Verdict` |
| `verdict.suspicious` | Veredito atinge `suspicious` | `Verdict` |
| `quarantine.action` | Arquivo quarentenado, restaurado ou purgado | `QuarantineEvent` |
| `scan.completed` | Ciclo termina (mesmo sem achados) | `ScanSummary` |
| `engine.failed` | Engine falha, estoura timeout ou é morto | `ScanReport` |

Cada webhook declara a quais eventos assina. Sem inscrição, sem entrega.

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

`action` ∈ `quarantined`, `restored`, `purged`, `failed`. `reversible` é
sempre `true` enquanto o item existe no cofre — a purga definitiva só acontece
por ação manual ou após a retenção configurada.

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
  "engines_abstained": [{ "engine": "maldet", "reason": "binario nao encontrado no PATH" }],
  "verdicts": { "confirmed": 1, "likely": 0, "suspicious": 3, "clean": 408 },
  "actions": { "quarantined": 1, "recommended": 0, "failed": 0 }
}
```

`engines_abstained` sempre acompanha o resumo: um ciclo em que metade dos
engines falhou não pode parecer um ciclo limpo (Princípio VI).

### `engine.failed`

`data` é o `ScanReport` completo, com `status` (`failed`/`timeout`/`killed`) e
`error` preenchidos. Existe porque a degradação silenciosa de cobertura é o
modo de falha mais perigoso de um orquestrador.

## Teste de entrega

O painel e a CLI (`sentinelhost alert test --webhook <id>`) disparam um evento
`verdict.confirmed` com `data` de exemplo e `delivery_id` prefixado por
`d_test_`. O resultado real (status HTTP, corpo, erro de conexão) é exibido na
hora — sem "enviado com sucesso" otimista.
