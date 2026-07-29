# Procedência — AMWScan

- **Engine**: AMWScan (`marcocesarato/PHP-Antimalware-Scanner`)
- **Versão de referência do formato**: 0.10.4
- **Invocação**: `php scanner.phar --report --json --path <root>`
- **Formato**: JSON único em stdout.

## Particularidades que o adaptador precisa tratar

- O AMWScan usa **exit code diferente de zero quando encontra algo**. Isso não
  é falha: é o modo dele de sinalizar detecção. O executor já preserva o exit
  code sem transformá-lo em erro.
- O campo `exploit` é o nome da regra. O mapeamento regra→categoria fica em
  `internal/adapter/amwscan/rules.go`, versionado junto do adaptador.
- Um `exploit` desconhecido vira `other`/`medium`/`heuristic` — nunca é
  descartado (obrigação 4 do contrato de adaptadores).
- O engine não reporta hash. Quem calcula o sha256 é o orquestrador, porque o
  hash é a chave de deduplicação entre engines e precisa ser calculado do mesmo
  jeito para todos.
