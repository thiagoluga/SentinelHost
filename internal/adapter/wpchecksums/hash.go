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
// HashFileSHA256 e HashFileMD5 expoem os hashes de um arquivo.
//
// Existem para os testes montarem expectativas a partir do conteudo real que
// eles mesmos escreveram, em vez de constantes copiadas — hash literal no
// teste envelhece em silencio quando a fixture muda.
func HashFileSHA256(path string) (string, error) {
	_, sha, err := hashFile(path)
	return sha, err
}

// HashFileMD5 devolve o MD5, que e o formato que a API do core publica.
func HashFileMD5(path string) (string, error) {
	md5sum, _, err := hashFile(path)
	return md5sum, err
}

func pathHash(path string) string {
	sum := sha256.Sum256([]byte("sentinelhost:missing-core-file:" + path))
	return hex.EncodeToString(sum[:])
}
