# SentinelHost

**Orquestrador open source de scanners de malware para hospedagem compartilhada.**

O SentinelHost **não é um antivírus** e **não tem motor de detecção próprio**.
Ele coordena engines open source já existentes (AMWScan, php-malware-finder via
YARA, maldet, além de verificação de integridade por checksums oficiais do
WordPress.org), normaliza as saídas de todos eles para um esquema único e
consolida tudo num **veredito por consenso ponderado**.

A pergunta que ele responde não é "este arquivo é malware?" — é "quantos
engines independentes concordam que este arquivo é malware, com que peso, e
por qual regra?".

## Por que orquestrar em vez de competir

Cada scanner de malware para PHP tem pontos cegos diferentes. Rodar um só
significa aceitar os falsos negativos dele; rodar vários significa ter que
interpretar N relatórios em formatos incompatíveis. O SentinelHost roda os que
estiverem disponíveis no seu ambiente, cruza os resultados e entrega **um**
veredito por arquivo — com os votos à vista.

Engines GPL são invocados exclusivamente como **processos externos via CLI**,
nunca linkados, o que permite ao orquestrador manter licença MIT.

## Princípios

Estes são inegociáveis e estão registrados em
[`.specify/memory/constitution.md`](.specify/memory/constitution.md):

1. **Reversibilidade acima de tudo** — quarentena é mover + registrar +
   bloquear. Nunca apagar. Um falso positivo nunca derruba seu site
   permanentemente.
2. **Orquestrar, não competir** — zero base de assinaturas própria.
3. **Funciona sem root** — conta de hospedagem barata, sem systemd,
   possivelmente sem SSH (fallback via cron do cPanel).
4. **Cidadão educado da hospedagem** — `nice 19`, pausas entre lotes, scan
   incremental e timeout por engine ativos **por padrão**.
5. **Consenso transparente** — todo veredito mostra engines, pesos e regras.
   Ação automática só no nível `confirmed`.
6. **Esquema normalizado como contrato** — falha de adaptador vira abstenção,
   nunca "voto limpo" e nunca queda do ciclo.
7. **Simplicidade operacional** — um binário estático, um TOML, SQLite sem
   CGO, painel embutido.

## Estado atual

Em desenvolvimento — feature `001-orquestrador-mvp`. Veja
[`specs/001-orquestrador-mvp/`](specs/001-orquestrador-mvp/) para a
especificação, o plano e as tarefas, e [`SUMMARY.md`](SUMMARY.md) para o que já
está implementado.

## Engines do MVP

| Engine | Tipo | Requisitos | Peso no consenso |
|---|---|---|---|
| `wp-checksums` (nativo) | Integridade via API oficial do WordPress.org | Só rede | 1.5 |
| `maldet` | Assinaturas + hex | Linux, funciona parcialmente sem root | 1.0 |
| `amwscan` | Scanner PHP puro (phar) | PHP CLI ≥ 7.1 | 0.8 |
| `php-malware-finder` | Regras YARA | binário `yara` no PATH | 0.8 |

`wordfence-cli` e `clamav` ficam para depois do MVP.

## Instalação e uso

Veja [`specs/001-orquestrador-mvp/quickstart.md`](specs/001-orquestrador-mvp/quickstart.md).

```bash
sentinelhost scan --root ~/public_html
sentinelhost serve
```

## Documentação de design

- [`docs/esquema-e-adaptadores.md`](docs/esquema-e-adaptadores.md) — o esquema
  normalizado e o contrato de adaptadores (o coração do projeto)
- [`docs/painel-mockup.html`](docs/painel-mockup.html) — referência visual do
  painel web
- [`DECISIONS.md`](DECISIONS.md) — decisões tomadas onde a spec era ambígua

## Licença

MIT — veja [`LICENSE`](LICENSE).
