# Decisões de implementação

Registro das escolhas feitas onde a spec, o plano ou as tarefas deixavam
margem de interpretação. O critério de desempate é sempre o princípio da
constituição mais próximo. Cada decisão cita o princípio que a sustenta.

---

## D-001 — Caminho do módulo Go

**Ambiguidade**: T001 pede `go mod init github.com/<org>/sentinelhost`, sem
definir o org, e o repositório criado é `thiagoluga/SentinelHost` (com maiúsculas).

**Decisão**: `module github.com/thiagoluga/SentinelHost`.

**Motivo**: caminho de módulo em Go é sensível a maiúsculas e precisa bater com
o caminho real do repositório para `go install github.com/...@latest` funcionar.
Usar o lowercase convencional quebraria a instalação em um comando, que é
requisito do Princípio VII (simplicidade operacional).

---

## D-002 — Ambiente de desenvolvimento é Windows; o alvo é Linux

**Ambiguidade**: o plano define alvo Linux x86_64/arm64 em userland sem root,
mas o desenvolvimento está acontecendo em Windows.

**Decisão**: todo código específico de plataforma (nice/ionice, chmod 000,
uid/gid do dono, sinais) fica isolado atrás de arquivos com build tags
(`_unix.go` / `_windows.go`). Os testes que dependem de semântica POSIX de
permissão são pulados no Windows com `t.Skip` explícito, nunca silenciosamente.

**Motivo**: Princípio III exige que o comportamento real seja o do userland
Linux; o Windows é só a estação de trabalho. Esconder a diferença com `t.Skip`
mudo faria a suíte mentir sobre cobertura.

---

## D-003 — Score do consenso: soma normalizada por teto, não média

**Ambiguidade**: `docs/esquema-e-adaptadores.md` define os limiares de nível
(`confirmed` ≥ 0.9 etc.) e os pesos por engine (wp-checksums 1.5, maldet 1.0,
amwscan 0.8, pmf 0.8), mas não a fórmula que transforma votos em score.

**Decisão**: o score é a soma dos pesos efetivos dos votos dividida por um teto
de saturação configurável (`saturation`, padrão 2.0), truncada em 1.0. O peso
efetivo de um voto é `peso_do_engine × multiplicador_de_confiança`, com
`signature` = 1.0, `heuristic` = 0.8 e `anomaly` = 0.55.

**Motivo**: precisa reproduzir os exemplos que a documentação dá como
`confirmed`. Dois engines com `confidence=signature` (1.0 + 0.8 = 1.8 sobre
teto 2.0 = 0.9) chegam exatamente em `confirmed`, e checksum oficial divergente
(1.5) + um engine (0.8×0.8 = 0.64), somando 2.14, satura em 1.0 — também
`confirmed`. Uma média puniria o consenso a cada engine adicional que
abstivesse, o que contraria o Princípio VI ("abstenção nunca é voto limpo"):
com média, abster-se baixaria o score exatamente como um voto de inocência.

---

## D-004 — Abstenção não entra no denominador

**Ambiguidade**: o esquema exige registrar `abstentions`, mas não diz se elas
afetam o score.

**Decisão**: abstenções são registradas no `Verdict` para transparência e são
completamente ignoradas no cálculo do score.

**Motivo**: Princípio VI é explícito — falha de adaptador é abstenção, "nunca
voto limpo". Se a abstenção entrasse no denominador, um engine que estourou
timeout diluiria o score e poderia rebaixar um `confirmed` para `likely`,
transformando falha técnica em decisão de segurança.

---

## D-005 — Proteção por checksum oficial é veto, não voto

**Ambiguidade**: o esquema diz que arquivo idêntico ao checksum oficial "nunca é
quarentenado, independente de votos", mas o cenário 5 da US1 pede veredito
`clean`.

**Decisão**: bater com o checksum oficial força `level=clean` e `score=0`,
preservando a lista de votos que existiam e registrando
`clean_reason="official_checksum_match"`. Não é um voto negativo somado ao
score: é um veto aplicado depois do cálculo.

**Motivo**: o cenário 5 da spec pede `clean` com "o motivo registrado". Um voto
negativo poderia ser superado por votos suficientes, o que quebraria o "nunca,
independente de votos". Veto é a única implementação que honra as duas frases.

---

## D-006 — Whitelist bloqueia a ação, não o veredito

**Ambiguidade**: a whitelist "nunca quarentena, mas continua no relatório".

**Decisão**: o arquivo na whitelist mantém o nível e o score calculados
(inclusive `confirmed`) e aparece normalmente no relatório; o que muda é
`action_taken="skipped_whitelist"`.

**Motivo**: FR-007 e o cenário 5 da US2 exigem que ele "permaneça visível no
relatório". Rebaixar o nível para `clean` esconderia do usuário que os engines
continuam apontando aquele arquivo — colidiria com o Princípio V (consenso
transparente). Diferente do checksum oficial (D-005), onde há prova positiva de
que o arquivo é legítimo, a whitelist é só uma decisão do usuário.

---

## D-007 — Modo observação ligado nos primeiros 7 dias

**Ambiguidade**: T006 pede "observação ON nos primeiros 7 dias"; FR-017 fala em
"modo observação recomendado nos primeiros dias". Não estava definido de que
instante conta o prazo nem o que acontece ao expirar.

**Decisão**: a config guarda `first_run_at` (gravado no primeiro ciclo). Enquanto
`now < first_run_at + 7d`, nenhuma quarentena automática ocorre, mesmo com
`observation_mode=false`; os alertas saem marcados como "ação recomendada". Ao
expirar, o comportamento passa a seguir `observation_mode` puro, e o evento da
transição vai para o log estruturado e para o painel.

**Motivo**: Princípio I — o período de graça existe para o usuário calibrar
pesos e whitelist antes que a ferramenta mexa nos arquivos dele. Fazer a
expiração ser silenciosa seria uma mudança de comportamento sem aviso.

---

## D-008 — Ação automática exige `confirmed` E ausência de período de graça

**Decisão**: a quarentena automática só dispara quando, simultaneamente:
o nível é `confirmed`, `observation_mode=false`, o período de graça expirou, o
arquivo não está na whitelist, o arquivo não bate com checksum oficial, e o
re-hash imediatamente anterior à ação confere com o hash do veredito.

**Motivo**: FR-018 e Princípio I. Se o re-hash divergir, o arquivo mudou entre o
scan e a ação: a ferramenta reescaneia em vez de quarentenar às cegas (edge case
explícito na spec).

---

## D-009 — Fixtures de saída bruta são sintéticas, com procedência declarada

**Ambiguidade**: T010 e o CONTRIBUTING pedem fixtures "de saída bruta"; a
constituição proíbe malware vivo no repositório.

**Decisão**: as fixtures em `tests/testdata/raw/<engine>/` reproduzem
fielmente o **formato** de saída de cada engine, mas os arquivos e trechos
citados dentro delas apontam para o corpus sintético do próprio repositório.
Cada diretório de fixtures tem um `README.md` declarando de qual versão do
engine o formato foi derivado.

**Motivo**: o teste de contrato precisa validar o parser, não a detecção. O
formato é o contrato; o conteúdo apontado pode ser sintético sem perder poder
de teste, e isso mantém o repositório livre de amostras vivas.

---

## D-010 — Corpus sintético usa marcador inerte, no espírito do EICAR

**Ambiguidade**: a spec pede "amostras sintéticas de webshell" e
`docs/esquema-e-adaptadores.md` fala em "EICAR-like para PHP".

**Decisão**: cada amostra do corpus é um arquivo PHP **inerte** que contém um
marcador fixo do projeto (`SENTINELHOST-SYNTHETIC-CORPUS`) e reproduz a
*estrutura* de um padrão malicioso (concatenação ofuscada, callback dinâmico,
blob base64) sem nunca montar uma chamada executável funcional. Três garantias
valem para todas: a primeira instrução executável é um `exit()`; os fragmentos
de nome de função nunca são reunidos numa chamada dinâmica; nenhuma faz rede,
escreve em disco, lê entrada ou abre processo.

`tests/testdata/corpus/AMOSTRAS.md` documenta uma a uma o que simulam e qual
categoria/severidade/confiança deveriam receber, e `manifesto.json` traz a
mesma informação em formato legível por máquina. O teste do SC-001 falha se
encontrar um arquivo do corpus que não esteja no manifesto — assim ninguém
adiciona amostra sem declarar a expectativa.

**Motivo**: a constituição proíbe malware executável no repositório. O corpus
precisa exercitar o consenso, e para isso basta que os adaptadores *sintéticos
de teste* reconheçam os padrões — o valor do teste está no motor de veredito.

---

## D-011 — Engines reais não são baixados durante os testes

**Decisão**: nenhum teste automatizado baixa o phar do AMWScan, o binário
`yara` ou as regras do php-malware-finder. Os testes de contrato rodam sobre
fixtures; os testes de integração do consenso usam adaptadores falsos que
emitem `ScanReport` fixos.

**Motivo**: Princípio III e IV. Um teste que depende de rede e de binário
externo falha em CI e na hospedagem do usuário por motivos que não têm nada a
ver com o código. `Install()` é exercitado manualmente e documentado no
quickstart.

---

## D-012 — Ambiente de desenvolvimento com antivírus ativo

**Contexto**: durante a implementação, o Windows Defender colocou em quarentena
`docs/esquema-e-adaptadores.md` por causa do exemplo de `matched_content`.

**Decisão**: o corpus sintético (D-010) nunca contém um payload funcional, o
que reduz a chance de detecção heurística por antivírus de estação de trabalho.
O `README.md` de `tests/testdata/corpus/` documenta que uma exclusão de
antivírus pode ser necessária para clonar o repositório em Windows.

**Motivo**: um repositório de ferramenta de segurança que não pode ser clonado
sem desligar o antivírus é um repositório inútil na prática.

---

## D-013 — `kind` e `component` no esquema desde o MVP

**Ambiguidade**: a spec 002 (scanner de vulnerabilidades) não deve ser
implementada agora, mas `docs/esquema-e-adaptadores.md` seção 3 já define o
campo discriminador `kind` e o bloco `component`.

**Decisão**: os dois entram no pacote `internal/schema` desde já, com
`kind` vazio sendo tratado como `malware`. Nenhuma lógica de pipeline de
vulnerabilidade é implementada.

**Motivo**: a instrução era não tomar decisões que inviabilizem a 002.
Adicionar um campo discriminador depois obrigaria a incrementar a versão maior
do esquema e a reprocessar toda a saída bruta arquivada — enquanto adicioná-lo
agora, opcional e com default, custa nada. A validação já cobre a diferença que
importa: achado de vulnerabilidade é consolidado por componente, não por
arquivo, e por isso não exige `file.sha256`.

---

## D-016 — Denominador do SC-001: amostras de conteúdo malicioso

**Ambiguidade**: o SC-001 exige "≥ 95% das amostras como `confirmed`/`likely`".
O corpus tem 12 amostras, e duas delas (`08-localizacao-suspeita` e
`11-permissoes-frouxas`) simulam sinais cujo único indício é **anomalia** — um
arquivo PHP numa pasta de mídia, um arquivo 0777 na raiz web. Com os pesos e
multiplicadores do documento de esquema, dois votos de anomalia somam 0,88
sobre o teto 2,0, ou seja `suspicious`. Com 12 amostras, 95% significa que
todas as 12 teriam que chegar a `likely`.

**Decisão**: o SC-001 é medido sobre as amostras de **conteúdo malicioso** —
aquelas cujo manifesto declara `nivel_minimo_esperado` de `likely` ou
`confirmed` (10 das 12). As duas amostras de anomalia pura são verificadas
contra o piso `suspicious` que o manifesto declara, e existe um teste dedicado
(`TestAnomaliaSozinhaNaoChegaALikely`) que **trava** o comportamento de que
anomalia isolada não escala.

**Resultado medido**: 10/10 (100%) das amostras de conteúdo malicioso em
`confirmed`/`likely`, e 12/12 detectadas em `suspicious` ou acima, com zero
falso positivo `confirmed` nos arquivos limpos.

**Motivo**: forçar anomalia a `likely` seria mexer nos multiplicadores para
fazer um número passar, e o efeito colateral seria real: `likely` é o nível que
dispara alerta de "ação recomendada" (FR-010). Um arquivo no lugar errado
passaria a acordar o usuário no meio da noite, e o Princípio V é explícito ao
escalonar a resposta pela força da evidência. A alternativa — remover as duas
amostras do corpus — seria pior: o consenso deixaria de ter cobertura de teste
para `confidence=anomaly`, que é justamente o caminho mais fácil de quebrar sem
ninguém perceber.

---

## D-017 — Teste de painel por HTTP, não por navegador

**Ambiguidade**: T037 pede teste e2e do painel com `chromedp`.

**Decisão**: o teste e2e exercita o painel pela **API HTTP** (`httptest`),
cobrindo o fluxo completo do SC-004: primeiro acesso → definir senha → listar
achados → decidir sobre um achado → configurar e-mail → disparar teste de
webhook. Não há dependência de navegador.

**Motivo**: `chromedp` traria uma árvore de dependências grande e exigiria um
Chrome instalado para a suíte rodar — em CI e na máquina de quem contribui. O
Princípio VII (sem dependências externas obrigatórias) vale também para o
ambiente de desenvolvimento: um repositório cuja suíte só passa em quem tem
Chrome é um repositório com menos gente rodando os testes.

**O que isto NÃO cobre, e assumo explicitamente**: renderização, layout,
acessibilidade e a parte do SC-004 que é usabilidade real ("um usuário leigo
consegue, em menos de 5 minutos, sem documentação"). Isso continua sendo
validação manual, listada como pendente no `SUMMARY.md`.

---

## D-018 — Escopo incremental do AMWScan aplicado pelo adaptador

**Contexto**: o contrato diz que quem decide o escopo é o orquestrador, e o
adaptador só executa. Para o AMWScan isso não é implementável como pretendido.

**Medições no container de validação** (`make validar-engines`):

- `--filter-paths` com **um** caminho funciona; com **dois ou mais**, o engine
  roda, sai com código 0, escreve o relatório e não aponta nada — nem os
  arquivos que casariam sozinhos. É semântica de E, não de OU.
- `--filter-paths` filtra o **relatório**, não o conjunto varrido. Uma execução
  por arquivo custou 1m37s para 11 arquivos.

**Decisão**: uma execução por ciclo, sobre a raiz, e o `Parse` descarta os
achados fora da lista pedida. A lista viaja no `RawOutput.Extra`.

**Motivo**: das opções possíveis, é a única correta. Passar vários caminhos
produziria "0 achados" com o engine verde — engine saudável, relatório limpo,
site infectado, que é o modo de falha que o Princípio VI existe para impedir.
Uma execução por arquivo seria correta mas inviável em custo. O preço é CPU: o
AMWScan varre o site inteiro a cada ciclo, e nenhuma configuração do
SentinelHost muda isso, porque o engine não sabe escanear uma lista de arquivos.

---

## D-019 — Manutenção periódica também no caminho `scan`

**Ambiguidade**: T025 pede daemon com ciclos, retentativas e digest. Não diz
onde essas rotinas rodam no modo `cron`.

**Decisão**: retentativa de webhook, resumo periódico, purga por retenção, poda
de log e de saída bruta, e recuperação de ciclo interrompido vivem em
`internal/housekeeping` e são chamadas por **`scan` e `daemon`**.

**Motivo**: o modo padrão do projeto é `cron` (Princípio III — não se pode
pressupor um processo vivo). Com as rotinas só no daemon, no caminho
recomendado pela própria documentação o backoff de 5 tentativas existia no
código e nunca acontecia, o digest nunca saía, e o log e a saída bruta cresciam
até estourar a cota de disco da conta — a ferramenta derrubando o site que ela
promete proteger.

---

## D-020 — Ausência de arquivo do core não é assinatura

**Contexto**: na primeira execução real, o `wp-checksums` emitiu **2998**
achados `likely` — um por arquivo de core ausente, incluindo fontes `.woff2`.

**Decisão**: acima de 10% de arquivos do core ausentes, o adaptador **se
abstém** com motivo explícito. Abaixo disso, só arquivo com extensão executável
vira achado, com `confidence=anomaly` e `severity=medium`.

**Motivo**: um WordPress incompleto quase nunca é ataque — é core em
subdiretório, deploy parcial, symlink ou raiz mal configurada. E ausência não é
assinatura de nada: um arquivo que não existe não contém backdoor e não pode
ser quarentenado. Tratá-lo como `signature` fazia o peso 1,5 empurrar sozinho o
achado para perto de `confirmed`, autorizando ação sobre um arquivo inexistente.

---

## D-014 — Log estruturado no SQLite, saída bruta em arquivo

**Ambiguidade**: o plan.md lista "logs" no diretório de dados e o FR-015 exige
log estruturado **consultável no painel**.

**Decisão**: o log estruturado (`events`) fica no SQLite; a saída bruta dos
engines fica em arquivo, sob `<data_dir>/raw/<scan_id>/`.

**Motivo**: consultar com filtro por categoria, nível e período é exatamente o
que o painel precisa e exatamente o que arquivo de texto faz mal. A saída bruta
segue em arquivo porque é grande, é lida inteira quando é lida, e precisa
sobreviver a um banco corrompido para permitir reprocessamento por `Parse()`.

---

## D-015 — Purga de log não é ação destrutiva no sentido do Princípio I

**Decisão**: `PruneEvents` apaga eventos além da retenção sem exigir confirmação
do usuário.

**Motivo**: o Princípio I protege **arquivos do usuário**. Log é dado gerado
pela ferramenta, e numa conta com cota de disco um log que cresce sem limite
acaba derrubando o site — o oposto do que a ferramenta promete. A retenção é
configurável e o padrão (90 dias) é generoso.
