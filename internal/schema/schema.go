// Package schema define o esquema normalizado de resultados do SentinelHost.
//
// E a unica linguagem que o motor de veredito entende. Adaptadores convertem a
// saida bruta do seu engine para estes tipos; o motor de veredito nunca conhece
// um engine especifico (Principio VI da constituicao).
//
// Fonte: docs/esquema-e-adaptadores.md.
package schema

// Version e a versao do esquema normalizado que este pacote implementa.
// Adaptadores declaram qual versao emitem; o orquestrador recusa carregar um
// objeto de versao maior que a sua.
const Version = "1.0"

// MaxMatchedContentBytes limita o trecho que disparou a regra. A constituicao
// exige que conteudo malicioso nunca seja re-servido: o trecho e truncado e
// sanitizado antes de sair do adaptador.
const MaxMatchedContentBytes = 512
