# Fixtures de saída bruta dos engines

Cada diretório aqui guarda **saída bruta** de um engine, no formato exato que
ele produz. São o insumo dos testes de contrato: o teste alimenta `Parse()` com
o arquivo e verifica que o `ScanReport` normalizado sai correto.

## O que está sob teste aqui

O **parser**, não a detecção. Um teste de contrato responde "o adaptador
entende o que este engine fala?" — nunca "este engine acha malware?".

Por isso os arquivos e trechos citados dentro das fixtures apontam para o
corpus sintético do próprio repositório (`DECISIONS.md` D-009): o formato é o
contrato, e o conteúdo apontado pode ser sintético sem o teste perder poder.

## Procedência

Cada diretório tem um `PROCEDENCIA.md` declarando de qual versão do engine o
formato foi derivado. Quando um engine mudar de formato, adicione uma **nova**
fixture com a nova versão em vez de editar a antiga — o adaptador precisa
continuar lendo as duas, porque a hospedagem do usuário pode ter a versão velha.

## Casos obrigatórios por engine

Todo engine precisa de, no mínimo:

| Fixture | Por que é obrigatória |
|---|---|
| `sucesso-com-achados.*` | O caminho normal. |
| `sucesso-sem-achados.*` | Zero achados tem que virar `status=completed` com lista vazia — e **não** ser confundido com falha. |
| `saida-vazia.*` | Engine que morreu sem escrever nada não pode virar "não achou nada": tem que virar abstenção. |
| `saida-corrompida.*` | Saída truncada ou ilegível tem que virar abstenção com motivo, nunca panic e nunca voto. |

Essas quatro cobrem a distinção que mais importa no projeto: **"não achou
nada" e "não conseguiu procurar" são coisas diferentes** (Princípio VI). Um
parser que confunde as duas transforma falha de engine em atestado de saúde.
