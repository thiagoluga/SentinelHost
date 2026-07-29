package pathmatch_test

import (
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/pathmatch"
)

func TestMatch(t *testing.T) {
	casos := []struct {
		padrao   string
		caminho  string
		esperado bool
		porque   string
	}{
		// ** em qualquer profundidade — o motivo de este pacote existir.
		{"**/wp-content/cache/**", "/home/u/public_html/wp-content/cache/a/b/c.php", true, "cache em profundidade"},
		{"**/wp-content/cache/**", "/home/u/wp-content/cache/x.php", true, "cache raso"},
		{"**/wp-content/cache/**", "/home/u/wp-content/cache", true, "`**` no fim casa zero segmentos, entao o proprio diretorio tambem e excluido"},
		{"**/node_modules/**", "/site/a/b/node_modules/pkg/index.js", true, "node_modules aninhado"},

		// * nao atravessa separador.
		{"/home/*/public_html/x.php", "/home/user/public_html/x.php", true, "um nivel"},
		{"/home/*/public_html/x.php", "/home/a/b/public_html/x.php", false, "* nao atravessa separador"},

		// Extensoes.
		{"**/uploads/**/*.jpg", "/site/wp-content/uploads/2026/07/foto.jpg", true, "extensao em profundidade"},
		{"**/uploads/**/*.jpg", "/site/wp-content/uploads/2026/07/x.php", false, "extensao errada"},

		// ? casa um caractere.
		{"/site/x?.php", "/site/x1.php", true, "interrogacao"},
		{"/site/x?.php", "/site/x12.php", false, "interrogacao casa so um"},

		// ** no fim casa com nada.
		{"/site/**", "/site", true, "** casa vazio"},
		{"/site/**", "/site/a/b/c", true, "** casa varios"},

		// Caminho exato.
		{"/site/wp-config.php", "/site/wp-config.php", true, "exato"},
		{"/site/wp-config.php", "/site/wp-config.php.bak", false, "prefixo nao basta"},
	}

	for _, c := range casos {
		if got := pathmatch.Match(c.padrao, c.caminho); got != c.esperado {
			t.Errorf("Match(%q, %q) = %v, esperado %v (%s)", c.padrao, c.caminho, got, c.esperado, c.porque)
		}
	}
}

func TestMatchECaseSensitive(t *testing.T) {
	// Ignorar maiusculas faria uma whitelist de Config.php proteger tambem o
	// config.php que o atacante plantou.
	if pathmatch.Match("/site/Config.php", "/site/config.php") {
		t.Error("a comparacao deveria ser sensivel a maiusculas")
	}
}

func TestMatchNormalizaBarrasDoWindows(t *testing.T) {
	if !pathmatch.Match(`**\uploads\**`, "/site/wp-content/uploads/2026/x.php") {
		t.Error("padrao com barra invertida deveria ser normalizado")
	}
	if !pathmatch.Match("**/uploads/**", `C:\site\wp-content\uploads\2026\x.php`) {
		t.Error("caminho com barra invertida deveria ser normalizado")
	}
}

func TestWhichMatchesDizQualRegraProtegeu(t *testing.T) {
	// O usuario precisa saber QUAL regra da whitelist protegeu um arquivo.
	padroes := []string{
		"**/node_modules/**",
		"**/wp-content/plugins/meu-plugin/**",
		"**/vendor/**",
	}
	got := pathmatch.WhichMatches(padroes, "/site/wp-content/plugins/meu-plugin/loader.php")
	if got != "**/wp-content/plugins/meu-plugin/**" {
		t.Errorf("esperava a regra do plugin, veio %q", got)
	}
	if pathmatch.WhichMatches(padroes, "/site/index.php") != "" {
		t.Error("caminho sem regra deveria devolver vazio")
	}
}

func TestMatchAny(t *testing.T) {
	padroes := []string{"**/cache/**", "**/*.log"}
	if !pathmatch.MatchAny(padroes, "/site/var/cache/x.php") {
		t.Error("deveria casar com o primeiro padrao")
	}
	if !pathmatch.MatchAny(padroes, "/site/debug.log") {
		t.Error("deveria casar com o segundo padrao")
	}
	if pathmatch.MatchAny(padroes, "/site/index.php") {
		t.Error("nao deveria casar")
	}
	if pathmatch.MatchAny(nil, "/site/index.php") {
		t.Error("lista vazia nao casa com nada")
	}
}
