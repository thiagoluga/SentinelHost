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
