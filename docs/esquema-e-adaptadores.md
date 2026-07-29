# SentinelHost — Esquema Normalizado de Resultados e Contrato de Adaptadores

Versão: 0.1.0 (rascunho de design)

O SentinelHost não implementa motor de detecção próprio. Ele orquestra engines
open source existentes (maldet, PHP Malware Finder/YARA, AMWScan, Wordfence CLI,
ClamAV quando disponível) e cruza os resultados num veredito por consenso.
As duas fundações do projeto são: (1) o **esquema normalizado** para o qual toda
saída de engine é convertida, e (2) o **contrato de adaptador** que cada engine
precisa cumprir para ser plugado.

---

## 1. Esquema normalizado de resultados

Todo adaptador converte a saída bruta do seu engine para este esquema (JSON).
É a única linguagem que o motor de veredito entende.

### 1.1 `Finding` — um achado individual

```json
{
  "schema_version": "1.0",
  "id": "f_9f8a7b6c",
  "engine": "php-malware-finder",
  "engine_version": "0.9.2",
  "rule": "ObfuscatedPhp",
  "rule_ref": "https://github.com/nbs-system/php-malware-finder",
  "file": {
    "path": "/home/user/public_html/wp-content/uploads/2026/07/cache.php",
    "size_bytes": 14382,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "mtime": "2026-07-21T14:03:22-03:00",
    "owner": "user",
    "perms": "0644"
  },
  "category": "obfuscation",
  "severity": "high",
  "confidence": "heuristic",
  "matched_content": "eval(base64_decode($_POST[...]))",
  "matched_offset": 1024,
  "scan_id": "s_20260723_0300",
  "detected_at": "2026-07-23T03:04:11-03:00"
}
```

Campos e domínios:

| Campo | Tipo | Regras |
|---|---|---|
| `schema_version` | string | Semver do esquema. Adaptadores declaram qual versão emitem. |
| `id` | string | Gerado pelo orquestrador (não pelo adaptador). |
| `engine` | string | Slug único do engine (`maldet`, `php-malware-finder`, `amwscan`, `wordfence-cli`, `clamav`, `wp-checksums`). |
| `engine_version` | string | Versão do binário/regras no momento do scan. |
| `rule` | string | Nome da assinatura/regra que bateu, como o engine reporta. |
| `category` | enum | `known_malware`, `obfuscation`, `backdoor`, `webshell`, `injection`, `spam_seo`, `phishing`, `dropper`, `core_integrity`, `suspicious_location`, `suspicious_perms`, `other`. Cada adaptador mantém uma tabela de mapeamento regra→categoria; o que não mapear vira `other`. |
| `severity` | enum | `critical`, `high`, `medium`, `low` — severidade **na visão do engine**, normalizada pelo adaptador. |
| `confidence` | enum | `signature` (hash/assinatura exata), `heuristic` (padrão/comportamento), `anomaly` (fora do padrão, sem assinatura). Alimenta o peso do voto. |
| `matched_content` | string | Trecho que disparou a regra, truncado a 512 bytes, **sanitizado** (nunca executável). Opcional. |
| `file.sha256` | string | Obrigatório. É a chave de deduplicação entre engines: mesmo arquivo apontado por N engines = N votos no mesmo alvo. |

### 1.2 `ScanReport` — resultado de uma execução de engine

```json
{
  "schema_version": "1.0",
  "scan_id": "s_20260723_0300",
  "engine": "amwscan",
  "engine_version": "0.10.4",
  "signatures_updated_at": "2026-07-20T00:00:00Z",
  "started_at": "2026-07-23T03:00:05-03:00",
  "finished_at": "2026-07-23T03:04:41-03:00",
  "scope": {
    "root": "/home/user/public_html",
    "mode": "incremental",
    "files_considered": 18234,
    "files_scanned": 412,
    "skipped_reason_counts": { "unchanged": 17801, "too_large": 12, "unreadable": 9 }
  },
  "status": "completed",
  "error": null,
  "resource_usage": { "wall_seconds": 276, "max_rss_mb": 84 },
  "findings": [ /* array de Finding */ ]
}
```

`status` ∈ `completed`, `partial` (terminou com erros em parte dos arquivos),
`failed`, `timeout`, `killed` (limite de recursos). Um `ScanReport` com
`status != completed` **nunca** conta como "engine não achou nada" no consenso —
conta como abstenção.

### 1.3 `Verdict` — decisão consolidada por arquivo

Produzido pelo motor de veredito, nunca por adaptadores.

```json
{
  "schema_version": "1.0",
  "verdict_id": "v_3c2d1e",
  "file_sha256": "e3b0c44...",
  "file_path": "/home/user/public_html/wp-content/uploads/2026/07/cache.php",
  "level": "confirmed",
  "score": 0.93,
  "votes": [
    { "engine": "maldet", "weight": 1.0, "finding_id": "f_1a2b" },
    { "engine": "php-malware-finder", "weight": 0.8, "finding_id": "f_9f8a" },
    { "engine": "wp-checksums", "weight": 1.5, "finding_id": "f_5e6f" }
  ],
  "abstentions": ["clamav"],
  "action_taken": "quarantined",
  "action_at": "2026-07-23T03:05:02-03:00",
  "quarantine_ref": "q_20260723_000132",
  "acknowledged_by_user": false
}
```

Níveis de veredito e ação padrão (tudo configurável):

| `level` | Critério padrão | Ação padrão |
|---|---|---|
| `confirmed` | score ≥ 0.9 — ex.: 2+ engines com `confidence=signature`, ou checksum oficial divergente + 1 engine | Quarentena automática + alerta |
| `likely` | 0.6 ≤ score < 0.9 — ex.: 2 engines heurísticos concordando | Alerta "ação recomendada", aguarda decisão |
| `suspicious` | 0.3 ≤ score < 0.6 — 1 engine heurístico, ou anomalia | Entra no relatório, sem alerta imediato |
| `clean` | score < 0.3 ou whitelist | Nada |

Regras fixas do motor (não configuráveis, por segurança):
- Arquivo na **whitelist do usuário** nunca é quarentenado, mas continua no relatório se engines apontarem.
- Arquivo idêntico (sha256) ao **checksum oficial do core/plugin do WordPress** nunca é quarentenado, independente de votos — engines dão falso positivo em arquivo legítimo minificado.
- Quarentena é sempre **reversível**: mover + registrar, nunca apagar. Purga definitiva só manual ou após retenção configurada (padrão 30 dias).

---

## 2. Contrato de adaptadores

Cada engine é integrado por um adaptador que implementa esta interface
(Go; nomes ilustrativos):

```go
type Adapter interface {
    // Identidade e metadados
    Info() AdapterInfo // slug, nome, licença, homepage, categorias suportadas

    // Detecta se o engine roda NESTE ambiente (binário presente, versão de
    // PHP/Python suficiente, permissões). Retorna Available/Unavailable+motivo.
    Probe(ctx context.Context, env Environment) ProbeResult

    // Instala ou atualiza o engine no espaço do usuário (sem root), quando
    // suportado. Ex.: baixar phar do AMWScan, clonar regras YARA.
    Install(ctx context.Context, env Environment) error

    // Atualiza assinaturas/regras, se o engine separa isso da instalação.
    UpdateSignatures(ctx context.Context) (updatedAt time.Time, err error)

    // Executa o scan sobre uma lista de caminhos (o ORQUESTRADOR decide a
    // lista — incremental por mtime/baseline; o adaptador não escolhe escopo).
    // Deve respeitar ctx (timeout/cancel) e os limites de recursos passados.
    Scan(ctx context.Context, req ScanRequest) (RawOutput, error)

    // Converte a saída bruta do engine para o esquema normalizado.
    // Separado de Scan() para permitir reprocessar saídas antigas quando o
    // mapeamento regra→categoria melhorar.
    Parse(raw RawOutput) (ScanReport, error)
}
```

Obrigações de todo adaptador:

1. **Nunca escreve fora do diretório de trabalho** do SentinelHost (exceto o scan em si, que é somente leitura). Quem move arquivo para quarentena é o orquestrador.
2. **Execução via subprocess** com `nice`/`ionice`/ulimits aplicados pelo orquestrador; o adaptador declara em `Info()` seu custo relativo (leve/médio/pesado) para o agendador intercalar.
3. **Saída bruta preservada**: `RawOutput` (stdout/stderr/arquivos de log) é arquivada por N dias para auditoria e para reprocessamento por `Parse`.
4. **Mapeamento explícito** regra→(`category`, `severity`, `confidence`) versionado junto do adaptador; regra desconhecida → `other`/`medium`/`heuristic`, nunca descartada.
5. **Falha isolada**: pânico/timeout de um adaptador não derruba o ciclo — vira `ScanReport{status: failed}` e abstenção no consenso.
6. **Licenças**: engines GPL são invocados como processos externos (saída via CLI), sem linkar código — o orquestrador pode manter licença própria (MIT/Apache-2.0).

### 2.1 Adaptadores do MVP

| Engine | Tipo | Requisitos | Papel no consenso |
|---|---|---|---|
| `wp-checksums` (nativo) | Integridade via API oficial WordPress.org | Só rede | Voto de peso máximo (1.5): core adulterado = quase certeza |
| `php-malware-finder` | Regras YARA | binário `yara` OU lib Go de YARA embutida | Heurística forte para PHP ofuscado (0.8) |
| `amwscan` | Scanner PHP puro (phar) | PHP CLI ≥ 7.1 | Roda em qualquer hospedagem; assinaturas + heurística (0.8) |
| `maldet` | Assinaturas + hex | Linux, funciona parcialmente sem root | Assinaturas maduras (1.0) |
| `wordfence-cli` | Assinaturas comerciais gratuitas | Python ≥ 3.8, licença gratuita | Forte em WordPress (1.0) — pós-MVP |
| `clamav` | Antivírus geral | Raramente disponível sem root | Oportunista (0.6) — pós-MVP |

O primeiro alvo de validação do projeto: `wp-checksums` + `amwscan` +
`php-malware-finder` rodando juntos num diretório de teste com amostras
de webshells conhecidas (EICAR-like para PHP) e um WordPress limpo,
medindo taxa de acerto do consenso vs. cada engine sozinho.

---

## 3. Segunda categoria de engine: vulnerabilidades (prevenção)

Além de detectar malware já instalado (reação), o SentinelHost orquestra
engines que detectam **componentes vulneráveis antes da exploração**
(prevenção): plugins/temas/core desatualizados com CVE conhecido,
dependências Composer/npm vulneráveis e configurações inseguras.

### 3.1 Extensão do esquema

`Finding` ganha o campo discriminador `kind`:

| `kind` | Significado | Ação possível |
|---|---|---|
| `malware` | Arquivo malicioso (seções 1–2) | Quarentena reversível |
| `vulnerability` | Componente com falha conhecida | **Nunca quarentena** — alerta + orientação de atualização |
| `hardening` | Configuração insegura | Alerta + correção guiada (opcionalmente automática) |

Findings `kind=vulnerability` trazem o bloco `component` no lugar de
`matched_content`:

```json
{
  "kind": "vulnerability",
  "engine": "wf-vulndb",
  "component": {
    "type": "wordpress-plugin",
    "slug": "contact-form-7",
    "installed_version": "5.7.1",
    "fixed_in": "5.7.2",
    "vuln_ids": ["CVE-2023-XXXXX"],
    "cvss": 8.8,
    "exploited_in_wild": true
  },
  "category": "vulnerable_component",
  "severity": "critical",
  "confidence": "signature"
}
```

Vereditos de vulnerabilidade são consolidados por **componente** (slug +
versão), não por arquivo, e têm níveis próprios: `urgent` (CVSS ≥ 9 ou
exploração ativa conhecida), `recommended` (correção disponível),
`informational` (sem correção publicada ainda). Malware e vulnerabilidade
nunca se misturam no mesmo score — são pipelines paralelos que compartilham
orquestrador, alertas e painel.

Sinergia entre os pipelines: quando um veredito de malware `confirmed`
ocorre num site que tinha vulnerabilidade `urgent` aberta, o relatório
correlaciona os dois ("provável porta de entrada"), orientando o usuário a
atualizar após a limpeza — senão a reinfecção é questão de dias.

### 3.2 Adaptadores de vulnerabilidade avaliados

| Engine | Licença | Cobertura | Papel |
|---|---|---|---|
| `wf-vulndb` (nativo) | API pública gratuita da Wordfence | Plugins, temas e core WP por versão | Principal para WP no MVP: comparar versões instaladas com o feed, sem token |
| `wpscan` | CLI open source; DB via API com tier gratuito limitado e restrições comerciais | WP completo + enumeração | Opcional, traz-seu-token; não pode ser dependência obrigatória |
| `osv-scanner` (Google) | Apache-2.0 | composer.lock, package-lock.json etc. via OSV.dev | Sites Laravel/Composer e temas com build JS |
| `composer audit` / advisories FriendsOfPHP | MIT/gratuito | Dependências PHP | Fallback leve quando Composer presente |
| `retire.js` | Apache-2.0 | Bibliotecas JS embutidas (jQuery velho etc.) | Complementar, baixo custo |
| `hardening` (nativo) | — | Permissões 777, `.env`/`.git`/backups expostos, debug ativo, listagem de diretório, editores de arquivo do wp-admin | Checagens próprias baratas, sem dependências |
| `semgrep` OSS | LGPL (engine) | Padrões inseguros em código próprio | Pós-MVP — pesado para hospedagem barata |

Detecção de versão instalada é responsabilidade do orquestrador (parser de
cabeçalhos de plugin/tema WP, `wp-includes/version.php`, lockfiles), para que
adaptadores de fonte de dados (`wf-vulndb`, `osv-scanner`) fiquem simples.

Especificação funcional: `specs/002-scanner-vulnerabilidades/spec.md`.
