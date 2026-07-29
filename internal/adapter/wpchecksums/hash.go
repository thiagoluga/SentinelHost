package wpchecksums

import (
	"crypto/sha256"
	"encoding/hex"
)

// pathHash devolve o sha256 do caminho.
//
// Serve para arquivos AUSENTES, que por definicao nao tem conteudo para
// hashear. O esquema exige sha256 porque e a chave de deduplicacao entre
// engines; usar o hash do caminho da ao achado uma chave estavel entre ciclos
// sem fingir que existe um arquivo ali. Nenhum outro engine vai produzir esse
// mesmo hash, entao o achado nunca se funde por engano com o de um arquivo real.
func pathHash(path string) string {
	sum := sha256.Sum256([]byte("sentinelhost:missing-core-file:" + path))
	return hex.EncodeToString(sum[:])
}
