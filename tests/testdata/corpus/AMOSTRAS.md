# Amostras do corpus

Todas as amostras de `sintetico/` são **inertes**. As três garantias, em toda
amostra sem exceção:

1. A primeira instrução executável é um `exit()`.
2. Os fragmentos de nome de função (`'ev' . 'al'`) **nunca** são reunidos numa
   chamada dinâmica — sem a reunião, não há execução possível.
3. Nenhuma amostra faz rede, escreve em disco, lê entrada do usuário ou abre
   processo.

O marcador `SENTINELHOST-SYNTHETIC-CORPUS` aparece em texto claro em todas.

## Amostras que o consenso DEVE apontar

| Arquivo | Simula | `category` | `severity` | `confidence` esperada |
|---|---|---|---|---|
| `01-webshell-parametro.php` | Webshell que recebe comando por parâmetro de requisição | `webshell` | `critical` | `heuristic` |
| `02-backdoor-eval-post.php` | Backdoor que avalia código vindo de POST | `backdoor` | `critical` | `heuristic` |
| `03-ofuscacao-blob.php` | Blob codificado longo + nomes ininteligíveis, sem código legível | `obfuscation` | `high` | `heuristic` |
| `04-uploader-sem-validacao.php` | Upload sem validação de tipo/extensão dentro da raiz web | `dropper` | `high` | `heuristic` |
| `05-spam-seo-links.php` | Links de spam mostrados só para o robô do buscador (cloaking) | `spam_seo` | `medium` | `heuristic` |
| `06-phishing-coleta.php` | Página clonada que coleta credenciais e exfiltra | `phishing` | `critical` | `heuristic` |
| `07-injecao-em-tema.php` | Arquivo legítimo de tema com uma linha injetada | `injection` | `high` | `heuristic` |
| `08-localizacao-suspeita.php` | PHP dentro de `wp-content/uploads` — o sinal é o **lugar** | `suspicious_location` | `medium` | `anomaly` (esperado: `suspicious`) |
| `09-marcador-conhecido.php` | Marcador determinístico, o "EICAR" deste corpus | `known_malware` | `critical` | `signature` |
| `10-core-adulterado.php` | Arquivo de `wp-includes/` que não bate com o checksum oficial | `core_integrity` | `critical` | `signature` |
| `11-permissoes-frouxas.php` | Arquivo 0777 na raiz web — o sinal é o **modo** | `suspicious_perms` | `medium` | `anomaly` (esperado: `suspicious`) |
| `12-shell-reverso-descrito.php` | Shell reverso: só os dados de configuração, nenhuma primitiva | `backdoor` | `critical` | `heuristic` |

Notas por amostra:

- **08 e 11** são deliberadamente banais no conteúdo. O achado tem que vir da
  localização e da permissão, não de padrão no texto. Elas existem para provar
  que o consenso lida com `confidence=anomaly`, que é o voto mais fraco — e
  para travar o comportamento de que **anomalia sozinha nunca chega a
  `likely`**: dois votos de anomalia somam 0,88 sobre o teto 2,0 = 0,44, ou
  seja `suspicious`. Se um único sinal de anomalia bastasse para `likely`, um
  arquivo no lugar errado dispararia alerta de "ação recomendada". Por isso
  elas ficam fora do denominador do SC-001 (`DECISIONS.md` D-016).
- **09** é o análogo do EICAR: um marcador acordado que os adaptadores de teste
  reconhecem com `confidence=signature`, sem que exista nenhum comportamento.
  É o que permite testar o caminho "dois engines com assinatura → `confirmed`"
  sem malware real. Os engines declarados são `maldet` (peso 1,0) e `amwscan`
  (0,8): 1,8 sobre o teto 2,0 = 0,90, exatamente o limiar de `confirmed` que a
  documentação do esquema usa como exemplo.
- **10** exercita o voto de peso máximo (`wp-checksums`, peso 1.5). É o único
  caminho pelo qual **um** engine sozinho chega perto de `confirmed`.
- **12** é a que mais preocupa, então é a que menos código tem. Um shell reverso
  precisa de socket, processo e redirecionamento de descritor; nenhum dos três
  aparece, nem quebrado em pedaços.

## Arquivos que o consenso NÃO pode apontar

| Arquivo | Por que costuma dar falso positivo |
|---|---|
| `limpo/base64-legitimo.php` | Usa `base64_encode` para o que ele serve (data URI, assinatura HMAC). Scanner marca qualquer base64. |
| `limpo/util.min.js` | JS minificado tem entropia alta, nomes de uma letra e linhas enormes — os mesmos sinais da ofuscação. |
| `limpo/wp-includes/version.php` | Arquivo de core cujo hash **bate** com o checksum oficial. |
| `limpo/plugin-legitimo.php` | Plugin comum, linha de base: se o consenso apontar este, o problema está no motor. |

`limpo/wp-includes/version.php` tem um papel especial no teste do SC-001: dois
engines o apontam com `confidence=signature` (o que daria `confirmed`) e o
teste verifica que o veredito sai `clean` com
`clean_reason=official_checksum_match`. A proteção por checksum oficial é um
**veto**, não um voto — ver `DECISIONS.md` D-005.

## Manifesto

`manifesto.json` traz a mesma informação em formato legível por máquina. É o
que o teste do SC-001 lê para saber o que esperar de cada arquivo. Ao adicionar
uma amostra, atualize as duas coisas — o teste falha se um arquivo do corpus
não estiver no manifesto, justamente para que ninguém adicione amostra sem
declarar a expectativa.
