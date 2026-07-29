# Feature Specification: Orquestrador multi-engine com veredito por consenso (MVP)

**Feature Branch**: `001-orquestrador-mvp`

**Created**: 2026-07-23

**Status**: Draft

**Input**: User description: "Ferramenta open source para hospedagens compartilhadas
que orquestra scanners de malware existentes, escaneia continuamente, quarentena
ameaças confirmadas, alerta sobre suspeitas, com painel web para ver e configurar
tudo (engines, agendamento, webhooks, alertas por e-mail)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan multi-engine com veredito por consenso (Priority: P1)

Como dono de um site em hospedagem compartilhada, quero que a ferramenta rode os
scanners disponíveis no meu ambiente sobre meus arquivos e me diga, para cada
arquivo apontado, se a ameaça é confirmada, provável ou apenas suspeita —
combinando os resultados de todos os engines em vez de eu ter que interpretar
cada um separadamente.

**Why this priority**: É o núcleo do produto. Sem o scan orquestrado e o
veredito consolidado, nada mais (quarentena, alertas, painel) tem o que mostrar.

**Independent Test**: Rodar `sentinelhost scan` num diretório de teste contendo
um WordPress limpo + amostras sintéticas de webshell. Verificar que o relatório
final lista as amostras com nível `confirmed`/`likely` e não aponta os arquivos
limpos do core.

**Acceptance Scenarios**:

1. **Given** um diretório com 2+ engines disponíveis (ex.: amwscan e
   php-malware-finder), **When** o scan executa, **Then** cada engine roda como
   subprocess, suas saídas são normalizadas e cada arquivo apontado recebe um
   único veredito consolidado com score e lista de votos.
2. **Given** um arquivo apontado por 2 engines com confiança de assinatura,
   **When** o motor de veredito calcula o score, **Then** o nível é `confirmed`
   (score ≥ 0.9).
3. **Given** um arquivo apontado por apenas 1 engine heurístico, **When** o
   veredito é calculado, **Then** o nível é `suspicious` e nenhuma ação
   automática ocorre.
4. **Given** um engine que falha ou estoura timeout, **When** o ciclo termina,
   **Then** o engine consta como abstenção, o ciclo completa com os demais e a
   falha aparece no relatório.
5. **Given** um arquivo do core do WordPress idêntico ao checksum oficial,
   **When** qualquer engine o aponta, **Then** o veredito é `clean` (proteção
   contra falso positivo) com o motivo registrado.

---

### User Story 2 - Quarentena reversível automática (Priority: P1)

Como dono do site, quero que ameaças confirmadas sejam neutralizadas
automaticamente — sem apagar nada — e quero poder restaurar qualquer arquivo
quarentenado com um clique, porque tenho medo de a ferramenta quebrar meu site.

**Why this priority**: É a ação de proteção que justifica rodar a ferramenta
continuamente; a reversibilidade é o que torna a automação aceitável.

**Independent Test**: Forçar um veredito `confirmed` num arquivo de teste;
verificar que ele foi movido para a quarentena (permissão 000, extensão
neutralizada), que o site continua funcional e que `restore` o devolve
byte a byte ao local original.

**Acceptance Scenarios**:

1. **Given** um veredito `confirmed` com ação automática habilitada, **When** a
   quarentena executa, **Then** o arquivo é movido para o cofre com metadados
   (caminho original, hashes, permissões, dono, timestamps) e um alerta é gerado.
2. **Given** um arquivo em quarentena, **When** o usuário clica em restaurar,
   **Then** o arquivo volta ao caminho original com o mesmo conteúdo e
   permissões, e o evento é registrado.
3. **Given** o modo observação ativo, **When** um veredito `confirmed` ocorre,
   **Then** nenhum arquivo é movido e o alerta indica "ação recomendada".
4. **Given** itens em quarentena além do período de retenção, **When** a rotina
   de purga roda, **Then** apenas itens expirados são removidos definitivamente
   e o total purgado é registrado.
5. **Given** um arquivo na whitelist do usuário, **When** engines o apontam,
   **Then** ele nunca é quarentenado, mas permanece visível no relatório.

---

### User Story 3 - Monitoramento contínuo adaptado à hospedagem (Priority: P2)

Como usuário de hospedagem barata, quero que a ferramenta fique vigiando meus
arquivos sem estourar os limites de CPU da minha conta — escaneando só o que
mudou, no horário e ritmo que eu configurar, e funcionando mesmo se a hospedagem
matar processos longos.

**Why this priority**: Transforma o scanner pontual em proteção contínua; é o
diferencial frente aos scanners existentes, mas depende do P1 existir.

**Independent Test**: Configurar ciclo incremental de 1h num diretório com
baseline; modificar 3 arquivos; verificar que o próximo ciclo escaneia apenas
os 3 modificados e completa dentro dos limites de recursos configurados.

**Acceptance Scenarios**:

1. **Given** um baseline de hashes existente, **When** o ciclo incremental roda,
   **Then** apenas arquivos novos/modificados desde o último ciclo são
   escaneados pelos engines.
2. **Given** o modo daemon, **When** o processo é morto pela hospedagem,
   **Then** o próximo disparo (cron de watchdog) retoma do último estado sem
   corromper baseline nem quarentena.
3. **Given** limites configurados (nice, pausa entre lotes, tamanho máximo),
   **When** qualquer engine executa, **Then** os limites são aplicados ao
   subprocess.
4. **Given** o modo somente-cron, **When** o usuário conclui a configuração,
   **Then** a ferramenta exibe a linha de cron pronta para colar no cPanel.

---

### User Story 4 - Alertas por e-mail e webhooks (Priority: P2)

Como dono do site, quero ser avisado por e-mail quando algo for confirmado ou
provável, receber um resumo periódico, e poder plugar webhooks para integrar
com Slack/Discord/n8n ou sistemas próprios.

**Why this priority**: Sem notificação, a proteção contínua é invisível; o
usuário só descobre o ataque quando o Google marca o site como perigoso.

**Independent Test**: Configurar SMTP de teste + um webhook de teste; forçar um
veredito `confirmed`; verificar recebimento do e-mail com os campos corretos e
do POST JSON assinado no endpoint.

**Acceptance Scenarios**:

1. **Given** SMTP configurado e níveis selecionados, **When** um veredito de
   nível selecionado ocorre, **Then** um e-mail é enviado aos destinatários com
   arquivo, nível, score, votos e link para o painel.
2. **Given** digest diário habilitado, **When** o horário chega, **Then** um
   único e-mail consolida achados, ações e estatísticas do período (enviado
   mesmo sem incidentes críticos, se houver suspeitas acumuladas).
3. **Given** um webhook cadastrado com segredo, **When** um evento inscrito
   ocorre, **Then** um POST JSON é entregue com cabeçalho de assinatura
   HMAC-SHA256 e, em falha, retentado com backoff exponencial (5 tentativas).
4. **Given** o botão "enviar teste" (e-mail ou webhook), **When** acionado,
   **Then** uma entrega de teste ocorre e o resultado (sucesso/erro real) é
   exibido na hora.

---

### User Story 5 - Painel web embutido (Priority: P3)

Como usuário leigo, quero um painel simples onde vejo o estado do meu site
(visão geral, achados, quarentena) e configuro tudo (engines e pesos,
agendamento, limites, alertas, webhooks, limiares de veredito, whitelist) sem
editar arquivos de configuração.

**Why this priority**: Tudo do painel é operável por CLI + arquivo de config
(P1–P2); o painel é a camada de usabilidade que amplia o público da ferramenta.
Referência visual: `docs/painel-mockup.html`.

**Independent Test**: Subir `sentinelhost serve`, autenticar, percorrer as seis
áreas do mockup e verificar que cada controle lê e grava a configuração real e
que ações (quarentenar, restaurar, testar alerta) executam de verdade.

**Acceptance Scenarios**:

1. **Given** o binário rodando, **When** o usuário acessa o painel, **Then**
   autenticação é exigida (senha definida no primeiro acesso; escuta em
   localhost por padrão).
2. **Given** achados pendentes, **When** o usuário decide (quarentenar /
   ignorar / whitelist), **Then** a ação executa e o estado atualiza sem
   recarregar a página.
3. **Given** qualquer alteração de configuração no painel, **When** salva,
   **Then** ela é persistida no arquivo de configuração e aplicada no próximo
   ciclo sem reiniciar manualmente.

---

### Edge Cases

- Hospedagem sem nenhum engine disponível além dos nativos: a ferramenta opera
  só com `wp-checksums` + heurísticas de anomalia e deixa claro no painel que a
  cobertura é reduzida.
- Site que não é WordPress (Laravel, site estático, Joomla): `wp-checksums`
  abstém-se sem penalizar o score dos demais.
- Dois processos de scan simultâneos (cron + manual): lock de instância única;
  o segundo processo sai com mensagem clara.
- Arquivo apontado que muda de conteúdo entre o scan e a quarentena: re-hash
  antes de agir; se divergir, reescaneia em vez de quarentenar às cegas.
- Disco cheio ou sem permissão de escrita no cofre de quarentena: ação vira
  alerta crítico "não foi possível neutralizar" em vez de falhar silenciosamente.
- Milhões de inodes (sites com cache descontrolado): respeitar exclusões padrão
  e limite de profundidade; nunca varrer fora do diretório raiz configurado.
- SMTP da hospedagem bloqueando envio: erro real exibido no teste de e-mail;
  webhook segue funcionando como canal alternativo.
- Symlinks apontando para fora da raiz: nunca seguidos.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: O sistema MUST detectar quais engines estão disponíveis no
  ambiente (probe) e exibir o motivo de indisponibilidade de cada um.
- **FR-002**: O sistema MUST executar cada engine disponível como subprocess
  isolado com limites de recursos e timeout, coletando a saída bruta.
- **FR-003**: Cada adaptador MUST converter a saída bruta do seu engine para o
  esquema normalizado versionado (docs/esquema-e-adaptadores.md), preservando a
  saída bruta para auditoria.
- **FR-004**: O motor de veredito MUST consolidar achados por hash de arquivo em
  um único veredito com score ponderado, nível (`confirmed`/`likely`/
  `suspicious`/`clean`) e lista de votos e abstenções.
- **FR-005**: O sistema MUST verificar integridade de instalações WordPress
  contra os checksums oficiais do WordPress.org (core e, quando disponível,
  plugins), tratando divergência como voto de peso máximo e igualdade como
  proteção contra falso positivo.
- **FR-006**: O sistema MUST quarentenar automaticamente apenas vereditos
  `confirmed` (quando o modo observação estiver desativado), de forma
  reversível: mover para cofre, remover permissão de execução, neutralizar
  extensão e registrar metadados completos para restauração.
- **FR-007**: O usuário MUST poder restaurar, ignorar (uma vez) ou colocar na
  whitelist (permanente) qualquer arquivo apontado, via painel e via CLI.
- **FR-008**: O sistema MUST manter baseline de hashes para scans incrementais
  e executar scan completo em agenda separada configurável.
- **FR-009**: O sistema MUST operar em modo daemon e em modo somente-cron,
  gerando a linha de cron pronta para o cPanel neste último.
- **FR-010**: O sistema MUST enviar alertas por e-mail via SMTP configurável
  (host, porta, TLS, credenciais, remetente, destinatários), com seleção de
  níveis que disparam alerta imediato e digest periódico opcional.
- **FR-011**: O sistema MUST entregar eventos a webhooks cadastrados como POST
  JSON assinado (HMAC-SHA256 em cabeçalho), com filtro de eventos por webhook,
  retentativas com backoff exponencial e histórico do último envio.
- **FR-012**: O sistema MUST oferecer envio de teste para e-mail e para cada
  webhook, reportando o resultado real.
- **FR-013**: O sistema MUST servir um painel web embutido, autenticado, com as
  áreas: visão geral, achados, quarentena, engines, agendamento, alertas e
  configurações — conforme o mockup de referência.
- **FR-014**: Toda configuração exposta no painel MUST ser igualmente editável
  no arquivo de configuração e refletida nos dois sentidos.
- **FR-015**: O sistema MUST registrar todas as ações (scans, vereditos,
  quarentenas, restaurações, alertas, mudanças de config) em log estruturado
  consultável no painel.
- **FR-016**: O sistema MUST atualizar assinaturas/regras dos engines sob
  demanda e em agenda, registrando a data por engine.
- **FR-017**: Limiares de score dos níveis de veredito e pesos por engine MUST
  ser configuráveis, com valores padrão seguros e modo observação recomendado
  nos primeiros dias.
- **FR-018**: O sistema MUST impedir instâncias concorrentes (lock) e MUST
  re-hashear arquivos imediatamente antes de qualquer ação de quarentena.

### Key Entities

- **Engine/Adaptador**: motor externo de detecção + camada de conversão; tem
  slug, versão, estado de disponibilidade, peso, data das assinaturas.
- **ScanReport**: execução de um engine num ciclo; escopo, status, uso de
  recursos, achados.
- **Finding**: um apontamento de um engine sobre um arquivo; categoria,
  severidade, confiança, regra, trecho sanitizado.
- **Verdict**: decisão consolidada por arquivo; nível, score, votos,
  abstenções, ação tomada, decisão do usuário.
- **QuarantineItem**: arquivo neutralizado; metadados para restauração,
  retenção, referência ao veredito.
- **AlertChannel**: canal de notificação (e-mail SMTP, webhook, Telegram
  futuro); configuração, filtro de níveis/eventos, histórico de entregas.
- **Baseline**: mapa caminho→(hash, mtime, tamanho) usado pelos ciclos
  incrementais.
- **Config**: arquivo único (TOML) com todas as opções; fonte da verdade
  compartilhada entre CLI e painel.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: No corpus de teste (WordPress limpo + amostras sintéticas), o
  consenso detecta ≥ 95% das amostras como `confirmed`/`likely` com zero
  falso positivo `confirmed` em arquivos oficiais do core.
- **SC-002**: Scan incremental de um site de 20 mil arquivos com 1% de mudança
  completa em menos de 5 minutos dentro dos limites padrão de recursos.
- **SC-003**: Todo arquivo quarentenado é restaurável byte a byte; 100% dos
  testes de round-trip (quarentenar → restaurar → comparar hash) passam.
- **SC-004**: Um usuário leigo consegue, só pelo painel, configurar e-mail de
  alerta e decidir sobre um achado pendente em menos de 5 minutos, sem
  documentação.
- **SC-005**: Alertas de vereditos `confirmed` são entregues (e-mail ou
  webhook) em até 60 segundos após o veredito.
- **SC-006**: O binário roda em uma conta cPanel real sem root, e o processo
  nunca ultrapassa os limites de CPU/memória configurados (verificado nos
  testes de recursos).

## Assumptions

- O usuário tem ao menos acesso a cron (cPanel) e, idealmente, SSH; o painel
  pressupõe capacidade de acessar uma porta local (túnel SSH) ou porta
  liberada.
- MVP prioriza sites PHP/WordPress em Linux; outros CMSs funcionam com
  cobertura reduzida (sem checksums oficiais).
- Engines do MVP: `wp-checksums` (nativo), `amwscan`, `php-malware-finder`;
  `maldet` quando o ambiente permitir. `wordfence-cli`, `clamav` e Telegram
  ficam pós-MVP.
- Interface do painel em pt-BR no MVP, com i18n preparado para en.
- Licença do orquestrador: MIT; engines GPL somente via subprocess.
