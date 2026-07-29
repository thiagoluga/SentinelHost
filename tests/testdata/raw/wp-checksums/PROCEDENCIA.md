# Procedência — wp-checksums (adaptador nativo)

- **Engine**: nativo do SentinelHost, sem binário externo
- **Fonte de dados**: API pública `https://api.wordpress.org/core/checksums/1.0/`
- **Invocação**: `GET ?version=<versao>&locale=<locale>`
- **Formato**: JSON com `{"checksums": {"caminho/relativo": "<md5>"}}`

A "saída bruta" deste adaptador é a **resposta da API**, arquivada como
qualquer outra saída de engine. Isso permite reprocessar um scan antigo sem
consultar a rede de novo.

## Privacidade

A consulta envia apenas a **versão** e o **locale** do WordPress. Nenhum
arquivo, caminho ou hash do usuário sai da hospedagem — restrição explícita da
constituição. A comparação acontece toda localmente.

## Particularidades que o adaptador precisa tratar

- A API devolve **MD5**, não SHA-256. O adaptador compara por MD5 e reporta o
  SHA-256 no `Finding`, porque o esquema normalizado usa SHA-256 como chave de
  deduplicação entre engines.
- Arquivo **ausente** que deveria existir e arquivo **modificado** são achados
  diferentes, ambos `core_integrity`. Arquivo **extra** dentro de `wp-admin/` ou
  `wp-includes/` também é achado: o core oficial não tem arquivos a mais.
- Os arquivos que **batem** com o checksum vão para `clean_files` do
  `ScanReport`. É o único engine que vota positivamente em legitimidade, e esse
  voto vira **veto** no motor de veredito (`DECISIONS.md` D-005).
- Sem rede, ou com versão do WP não reconhecida pela API, o adaptador se
  **abstém**. Nunca declara o core limpo por falta de informação.
- Site que não é WordPress: abstenção, sem penalizar o score dos demais engines
  (edge case explícito da spec).
