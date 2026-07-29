# Feature Specification: Pipeline de vulnerabilidades e hardening (prevenção)

**Feature Branch**: `002-scanner-vulnerabilidades`

**Created**: 2026-07-23

**Status**: Draft (depende da feature 001)

**Input**: User description: "Rodar também projetos open source que escaneiam
vulnerabilidades nos arquivos, para impedir que pessoas explorem as falhas
antes de o malware entrar."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Componentes vulneráveis do WordPress (Priority: P1)

Como dono de site WordPress em hospedagem compartilhada, quero ser avisado
quando um plugin, tema ou o core instalado tiver vulnerabilidade conhecida —
com a versão corrigida indicada — para atualizar antes que alguém explore.

**Why this priority**: A maioria absoluta das invasões em hospedagem
compartilhada entra por plugin desatualizado; prevenir custa menos que limpar.

**Independent Test**: Num WordPress de teste com um plugin em versão
sabidamente vulnerável, rodar `sentinelhost scan --vuln` e verificar veredito
`urgent`/`recommended` com slug, versão instalada, versão corrigida e IDs.

**Acceptance Scenarios**:

1. **Given** um plugin instalado em versão vulnerável segundo o feed, **When**
   o pipeline roda, **Then** um veredito de vulnerabilidade é criado por
   componente com nível derivado de CVSS/exploração ativa, nunca por arquivo.
2. **Given** vulnerabilidade com CVSS ≥ 9 ou exploração ativa, **When** o
   veredito é `urgent`, **Then** alerta imediato é disparado nos canais
   habilitados (mesmos canais da feature 001).
3. **Given** o mesmo componente apontado por duas fontes (ex.: wf-vulndb e
   wpscan), **When** consolidado, **Then** um único veredito lista ambas as
   fontes como votos.
4. **Given** um site sem WordPress, **When** o pipeline roda, **Then** os
   adaptadores WP abstêm-se silenciosamente.

---

### User Story 2 - Dependências e bibliotecas (Priority: P2)

Como desenvolvedor que hospeda um projeto PHP/Composer (ou tema com JS
embutido), quero que lockfiles e bibliotecas JS conhecidas sejam checados
contra bases públicas de vulnerabilidades (OSV.dev, advisories FriendsOfPHP,
retire.js).

**Independent Test**: Diretório com composer.lock contendo dependência
vulnerável conhecida → veredito `recommended` com pacote, versão e correção.

**Acceptance Scenarios**:

1. **Given** um composer.lock com pacote vulnerável, **When** osv-scanner (ou
   composer audit como fallback) roda, **Then** o achado é normalizado como
   `kind=vulnerability` com o bloco `component`.
2. **Given** uma biblioteca JS embutida desatualizada (ex.: jQuery com XSS),
   **When** retire.js roda, **Then** o achado aparece como `informational` ou
   `recommended` conforme severidade.

---

### User Story 3 - Hardening do ambiente (Priority: P2)

Como usuário leigo, quero que a ferramenta aponte configurações inseguras que
facilitam invasão — permissões 777, `.env`/`.git`/backups acessíveis
publicamente, WP_DEBUG ativo, editor de arquivos do wp-admin habilitado — com
correção guiada (e automática quando segura e reversível).

**Independent Test**: Ambiente de teste com 5 más-configurações plantadas →
as 5 reportadas com instrução de correção; as marcadas como auto-corrigíveis
são corrigidas e revertíveis.

**Acceptance Scenarios**:

1. **Given** um arquivo com permissão 777 dentro da raiz, **When** o check de
   hardening roda, **Then** um achado `kind=hardening` é criado com correção
   sugerida (chmod) e opção de aplicar.
2. **Given** correção automática aplicada, **When** o usuário desfaz pelo
   painel, **Then** o estado anterior é restaurado (Princípio I).

---

### Edge Cases

- Feed/API de vulnerabilidades fora do ar: pipeline abstém-se com aviso de
  "cobertura desatualizada há N dias"; nunca bloqueia o pipeline de malware.
- Plugin com versão modificada localmente (não bate com nenhuma release):
  reportar como `informational` + sugerir o pipeline de integridade.
- Sem rede de saída na hospedagem: modo offline com snapshot do feed
  embarcado na atualização do binário, com data visível.
- Falso "fixed_in" (feed errado): decisão do usuário de silenciar por
  componente+versão, registrada.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-101**: O orquestrador MUST detectar inventário instalado (core WP,
  plugins, temas com versões; lockfiles; bibliotecas JS conhecidas) sem
  depender de engine externo.
- **FR-102**: O sistema MUST consultar o feed público da Wordfence
  (wf-vulndb) sem token como fonte primária WP, com cache local e data do
  último sync visível.
- **FR-103**: Adaptadores `wpscan` (token do usuário), `osv-scanner`,
  `composer audit` e `retire.js` MUST seguir o mesmo contrato de adaptador da
  feature 001 (probe/instalação userland/execução/parse normalizado).
- **FR-104**: Vereditos de vulnerabilidade MUST ser consolidados por
  componente com níveis `urgent`/`recommended`/`informational` e MUST NOT
  acionar quarentena.
- **FR-105**: Achados `kind=hardening` MUST incluir correção sugerida;
  correções automáticas MUST ser reversíveis e opt-in.
- **FR-106**: O painel MUST ganhar a área "Vulnerabilidades" (inventário,
  vereditos por componente, silenciar, histórico) e os alertas MUST suportar
  os novos níveis nos filtros de e-mail/webhook.
- **FR-107**: O relatório MUST correlacionar veredito de malware `confirmed`
  com vulnerabilidades `urgent` abertas no mesmo site ("provável porta de
  entrada — atualize após a limpeza").
- **FR-108**: Atualização de componente nunca é executada automaticamente no
  MVP; quando wp-cli estiver disponível, o painel PODE oferecer o comando
  pronto para copiar.

### Key Entities

- **ComponentInventory**: componentes instalados (tipo, slug, versão, origem
  da detecção) — atualizado a cada ciclo.
- **VulnFinding**: achado normalizado `kind=vulnerability` (bloco component).
- **VulnVerdict**: consolidação por componente; nível, fontes, silenciado?
- **HardeningFinding**: má-configuração + correção sugerida + estado
  (aberta/corrigida/desfeita/silenciada).

## Success Criteria *(mandatory)*

- **SC-101**: No ambiente de teste com 10 componentes vulneráveis plantados
  (plugins WP + composer + JS), ≥ 90% detectados com versão corrigida
  indicada, zero quarentena acionada.
- **SC-102**: Vulnerabilidade `urgent` gera alerta em ≤ 60 s após o ciclo.
- **SC-103**: Ciclo de vulnerabilidades completo (inventário + feeds) em
  < 2 min para site típico, respeitando os mesmos limites de recursos.
- **SC-104**: As 5 más-configurações do corpus de hardening são detectadas e
  as auto-corrigíveis passam no round-trip aplicar→desfazer.

## Assumptions

- Feature 001 implementada (orquestrador, esquema, alertas, painel).
- Fonte primária WP sem token (wf-vulndb); WPScan é opcional com token do
  usuário por conta das restrições de licença/limites do serviço.
- Rede de saída disponível por padrão; modo offline é degradação documentada.
- semgrep e auto-update de componentes ficam fora desta feature.
