# Procedência — AMWScan

- **Engine**: AMWScan (`marcocesarato/PHP-Antimalware-Scanner`)
- **Versão de referência do formato**: **0.15.1**, executada de verdade no
  container `docker/Dockerfile.validacao` (Debian bookworm, PHP 8.2.32)
- **Invocação**:
  ```
  php scanner.phar --report --report-format txt --path-report <base> \
      --no-colors --silent [--max-filesize N] [--filter-paths a,b,c] <raiz>
  ```
- **Formato**: **texto**, escrito num ARQUIVO (`<base>.log`), não em stdout.

## Correção importante

Uma versão anterior destas fixtures era **JSON inventado**, com nomes de regra
que não existem (`EVAL_POST`, `OBFUSCATED_BLOB`, `SIGNATURE_KNOWN_MARKER`) e
uma flag `--format json` que o engine não tem. O parser passava nos próprios
testes e não reconheceria absolutamente nada em produção.

O erro só apareceu quando o engine foi executado de verdade. Duas lições que
valem para qualquer fixture nova:

1. **O AMWScan não tem saída JSON.** Os formatos são `html` e `txt`, via
   `--report-format`. Não existe `--format`.
2. **Ele escreve num arquivo, não em stdout.** Com `--silent`, stdout fica
   vazio — e confundir "stdout vazio" com "nada encontrado" é o erro clássico
   deste adaptador.

Fixture nova só entra aqui depois de sair de uma execução real. Rode
`make validar-engines` e copie do container.

## Formato

```text
Scan date: 2026-07-29 15:59:45
File: /caminho/do/arquivo.php
Exploits:
 => [!] Signature (d30fc49e) [line 4]
    - Malware Signature (hash: d30fc49e)
      => backdoor
```

Hierarquia: `File:` abre um bloco e tudo abaixo pertence a ele até o próximo
`File:`. `Exploits:` e `Functions:` apenas separam seções. A linha
`      => <tag>` é a categoria que o engine atribuiu, e o adaptador dá
prioridade a ela sobre o nome da regra — `Signature` com tag `backdoor` diz
mais que `Signature` sozinho.

## Particularidades que o adaptador precisa tratar

- **`--report` não é opcional.** Sem ele o AMWScan entra em modo interativo e
  pode **limpar ou apagar** arquivos. A quarentena deste projeto é reversível e
  registrada; a dele não.
- **O relatório anterior precisa ser apagado antes de cada execução.** Se o
  engine falhar, o arquivo do ciclo passado continua lá e o `Parse` devolveria
  achados velhos como novos.
- **O engine exige extensões do PHP além do interpretador.** Sem `mbstring` ele
  morre com exit 255 e **zero saída** — por isso o `Probe` executa
  `--version` de verdade em vez de só conferir se o arquivo existe.
- O escopo incremental vai por `--filter-paths` (lista separada por vírgula).
  Acima de 64 KiB de argumento o adaptador desiste do filtro e varre a raiz,
  porque o Linux limita um único argumento a 128 KiB.
- O engine não reporta hash. Quem calcula o sha256 é o orquestrador, porque ele
  é a chave de deduplicação entre engines.
- O relatório txt **não inclui o trecho do código**, só a regra e a linha.
  Melhor assim: conteúdo malicioso não precisa atravessar o sistema para o
  usuário entender o achado.
