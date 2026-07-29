# Constituição do SentinelHost

**Versão**: 1.0.0 | **Ratificada**: 2026-07-23 | **Última alteração**: 2026-07-23

O SentinelHost é um orquestrador open source de scanners de malware para
hospedagens compartilhadas (cPanel e similares). Ele NÃO implementa motor de
detecção próprio: coordena engines open source existentes e consolida os
resultados num veredito por consenso. Estes princípios governam toda decisão
de design e implementação. Violações exigem justificativa registrada.

## Core Principles

### I. Reversibilidade acima de tudo

Nenhuma ação destrutiva é irreversível por padrão. Quarentena = mover +
registrar + bloquear, nunca apagar. Purga definitiva só por ação manual do
usuário ou após período de retenção configurado. Um falso positivo tratado
nunca pode derrubar o site do usuário permanentemente.

### II. Orquestrar, não competir

Detecção vem de engines externos (maldet, PHP Malware Finder, AMWScan,
Wordfence CLI, ClamAV) e de verificação de integridade por checksums oficiais.
O projeto não mantém base de assinaturas própria. Engines GPL são invocados
exclusivamente como processos externos via CLI — nunca linkados — para que o
orquestrador possa manter licença MIT.

### III. Funciona sem root, no espaço do usuário

Todo recurso essencial precisa funcionar numa conta de hospedagem compartilhada
barata: sem root, sem systemd, possivelmente sem SSH (fallback via cron do
cPanel). Recursos que exigem privilégios (inotify global, ClamAV daemon) são
oportunistas: usados quando disponíveis, nunca obrigatórios.

### IV. Cidadão educado da hospedagem

O scanner nunca pode causar a suspensão da conta do usuário por abuso de
recursos. Limites de CPU (nice 19 por padrão), pausas entre lotes, scans
incrementais por padrão, limite de tamanho de arquivo e timeout por engine são
obrigatórios e ativos por padrão.

### V. Consenso transparente

Todo veredito exibe quais engines votaram, com que peso e por qual regra.
O usuário sempre consegue responder "por que este arquivo foi quarentenado?".
Vereditos automáticos só no nível `confirmed`; níveis inferiores sempre
aguardam decisão humana. Modo observação (sem ação automática) disponível.

### VI. Esquema normalizado como contrato

Adaptadores convertem qualquer saída de engine para o esquema normalizado
versionado (docs/esquema-e-adaptadores.md). O motor de veredito só conhece o
esquema, nunca um engine específico. Saída bruta é arquivada para auditoria e
reprocessamento. Falha de um adaptador = abstenção no consenso, nunca "voto
limpo" e nunca queda do ciclo.

### VII. Simplicidade operacional

Distribuição como binário Go único e estático, sem dependências externas
obrigatórias. Configuração num único arquivo legível (TOML). Estado em SQLite
(driver puro Go, sem CGO). Painel web embutido no próprio binário. Instalação
em um comando.

## Restrições adicionais

- Segurança do painel: autenticação obrigatória por padrão; escuta em
  localhost por padrão (acesso via túnel SSH ou porta liberada conscientemente).
- Conteúdo malicioso nunca é executado nem re-servido: trechos exibidos na UI
  são truncados e sanitizados; arquivos em quarentena perdem permissão de
  execução e são armazenados com extensão neutralizada.
- Privacidade: nenhum arquivo do usuário sai da hospedagem; consultas externas
  enviam apenas hashes e slugs de versão (ex.: API de checksums do
  WordPress.org).

## Fluxo de desenvolvimento

Spec-driven (Spec Kit): toda feature nasce de spec.md → plan.md → tasks.md.
Testes de contrato para cada adaptador (amostras de saída bruta versionadas no
repositório). Corpus de teste com webshells desativadas/sintéticas para
validar o consenso — nunca malware "vivo" executável no repositório.

## Governance

Emendas a esta constituição exigem: registro da motivação, análise de impacto
nos artefatos de spec existentes e incremento de versão semântica. Pull
requests que violem um princípio devem ser rejeitados ou acompanhados de
emenda aprovada.
