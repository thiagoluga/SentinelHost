// Package pathmatch casa caminhos contra padroes glob com suporte a `**`.
//
// O `filepath.Match` da biblioteca padrao nao entende `**`, e todo padrao util
// numa arvore de site precisa disso: `**/wp-content/cache/**` e a forma natural
// de escrever "cache em qualquer profundidade". Sem `**`, o usuario teria que
// escrever exclusoes por nivel, erraria, e acabaria com o scanner varrendo o
// que ele achou que tinha excluido.
package pathmatch

import (
	"path/filepath"
	"strings"
)

// Match responde se o caminho casa com o padrao.
//
// Regras:
//   - `*`  casa qualquer sequencia sem separador
//   - `?`  casa um caractere que nao seja separador
//   - `**` casa qualquer sequencia, inclusive separadores e inclusive vazio
//   - a comparacao usa `/` como separador em qualquer sistema operacional
//
// `**` casar vazio significa que `a/**` tambem casa com `a`. E o comportamento
// util para exclusoes: quem escreve `**/cache/**` quer que o diretorio `cache`
// saia inteiro, nao que ele sobre como entrada solta no relatorio.
//
// A comparacao e case-sensitive: sistemas de arquivos Linux, o alvo do
// projeto, sao case-sensitive, e ignorar isso faria uma whitelist de
// `Config.php` proteger tambem um `config.php` que o atacante plantou.
func Match(pattern, path string) bool {
	pattern = filepath.ToSlash(pattern)
	path = filepath.ToSlash(path)
	return matchSegments(splitPattern(pattern), strings.Split(strings.Trim(path, "/"), "/"))
}

// MatchAny responde se algum padrao casa.
func MatchAny(patterns []string, path string) bool {
	for _, p := range patterns {
		if Match(p, path) {
			return true
		}
	}
	return false
}

// WhichMatches devolve o primeiro padrao que casa, ou "".
//
// Existe porque o usuario precisa saber QUAL regra da whitelist protegeu um
// arquivo — "por que este arquivo nao foi quarentenado?" e uma pergunta que a
// ferramenta tem que responder com precisao (Principio V).
func WhichMatches(patterns []string, path string) string {
	for _, p := range patterns {
		if Match(p, path) {
			return p
		}
	}
	return ""
}

func splitPattern(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// matchSegments casa segmento a segmento, com backtracking em `**`.
func matchSegments(pattern, path []string) bool {
	// Sem padrao restante: casa se tambem nao sobrou caminho.
	if len(pattern) == 0 {
		return len(path) == 0
	}

	if pattern[0] == "**" {
		// `**` no fim casa com todo o resto, inclusive nada.
		if len(pattern) == 1 {
			return true
		}
		// Tenta consumir 0, 1, 2... segmentos com o `**`.
		for i := 0; i <= len(path); i++ {
			if matchSegments(pattern[1:], path[i:]) {
				return true
			}
		}
		return false
	}

	if len(path) == 0 {
		return false
	}
	ok, err := filepath.Match(pattern[0], path[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], path[1:])
}
