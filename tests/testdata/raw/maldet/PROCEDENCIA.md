# Procedência — maldet

- **Engine**: Linux Malware Detect (`maldet`)
- **Versão de referência do formato**: 1.6.5
- **Invocação**: `maldet -a <path>` seguido de `maldet --report <SCANID>`
- **Formato**: relatório de texto com cabeçalho de metadados e a `FILE HIT LIST`.

## Por que é opcional no MVP

O `maldet` funciona **parcialmente** sem root: o scan roda, mas a atualização
de assinaturas e a quarentena nativa costumam exigir privilégio. O SentinelHost
usa apenas o scan e faz a própria quarentena — a do `maldet` violaria o
Princípio I, porque não é a nossa quarentena reversível registrada.

Quando `maldet` não estiver disponível, o adaptador se abstém com motivo e o
consenso segue com os demais engines.

## Formato

```text
malware detect scan report for user:
SCAN ID: 260723-0300.12345
TIME: Jul 23 03:04:41 -0300
PATH: /home/user/public_html
TOTAL FILES: 412
TOTAL HITS: 2
TOTAL CLEANED: 0

FILE HIT LIST:
{HEX}php.base64.v23eb : /caminho/do/arquivo.php
{YARA}php_backdoor : /outro/caminho.php
```

## Particularidades que o adaptador precisa tratar

- O prefixo entre chaves é o **tipo** da assinatura: `{HEX}` e `{MD5}` são
  assinatura exata (`confidence=signature`); `{YARA}` e `{CAV}` são heurística.
  Essa distinção muda o peso do voto e não pode ser perdida.
- `TOTAL HITS` precisa bater com o número de linhas da lista. Divergência
  significa relatório truncado → abstenção, não relatório parcial aceito como
  bom.
- O relatório vem depois do scan, em invocação separada. Se o `--report` falhar,
  o resultado do scan é inútil: abstenção.
