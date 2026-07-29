package wpchecksums

import "testing"

// A resposta REAL de downloads.wordpress.org/plugin-checksums, capturada do
// classic-editor 1.6.7 dentro do container de validação.
//
// Este teste existe porque a primeira versão do adaptador declarava os hashes
// como array e passava nos testes — que usavam array. Contra a API de verdade,
// o Unmarshal falhava e TODO plugin era pulado com "resposta ilegível": zero
// achados, nenhum erro visível. É o modo de falha que este projeto mais teme,
// e a única defesa é fixar o formato real numa fixture.
const respostaRealPluginChecksums = `{
  "plugin": "classic-editor",
  "version": "1.6.7",
  "source": "https://plugins.svn.wordpress.org/classic-editor/tags/1.6.7/",
  "zip": "https://downloads.wordpress.org/plugin/classic-editor.1.6.7.zip",
  "files": {
    "LICENSE.md": {
      "md5": "1e105fba976f011ed8d6ded846aeb98e",
      "sha256": "8917d53bcf385c095f5a10db31ab1b22d4c9e3d62db39a88957d747bf2303c43"
    },
    "classic-editor.php": {
      "md5": "d1ee02e06095fdbfe683e010ef078a41",
      "sha256": "1a8198e278ad1e820d93ccfe49defca612a9efe9a7d9ffd03e289410d85a6635"
    },
    "js/block-editor-plugin.js": {
      "md5": "66f7a0eac8f7520dd41e7232ea48c935",
      "sha256": "7398a516595b5dfbd9f8e09e22521caf7f3fa470edf86acd0e8a80e07453cfa9"
    }
  }
}`

func TestParsePluginChecksumsAceitaOFormatoRealDaAPI(t *testing.T) {
	resp, err := parsePluginChecksums([]byte(respostaRealPluginChecksums))
	if err != nil {
		t.Fatalf("a resposta REAL da API foi recusada: %v", err)
	}
	if resp.Plugin != "classic-editor" || resp.Version != "1.6.7" {
		t.Errorf("metadados: %+v", resp)
	}
	if len(resp.Files) != 3 {
		t.Fatalf("esperava 3 arquivos, veio %d", len(resp.Files))
	}

	f := resp.Files["classic-editor.php"]
	if !f.temHash() {
		t.Fatal("o arquivo principal veio sem hash")
	}
	if !f.bate("d1ee02e06095fdbfe683e010ef078a41", "nao-importa") {
		t.Error("o MD5 real deveria casar")
	}
	if !f.bate("nao-importa", "1a8198e278ad1e820d93ccfe49defca612a9efe9a7d9ffd03e289410d85a6635") {
		t.Error("o SHA-256 real deveria casar")
	}
	if f.bate("outro", "outro") {
		t.Error("hash diferente nao pode casar")
	}
}

func TestParsePluginChecksumsAceitaArrayDeVariantes(t *testing.T) {
	// O outro formato que a API usa: array quando o arquivo tem variantes
	// aceitas (CRLF e LF dao hashes diferentes para o mesmo conteudo logico).
	// Bater com QUALQUER uma basta.
	entrada := `{
	  "plugin": "x", "version": "1.0",
	  "files": {
	    "readme.txt": {
	      "md5": ["aaa", "bbb"],
	      "sha256": ["ccc", "ddd"]
	    }
	  }
	}`
	resp, err := parsePluginChecksums([]byte(entrada))
	if err != nil {
		t.Fatalf("array de variantes foi recusado: %v", err)
	}
	f := resp.Files["readme.txt"]
	if !f.bate("bbb", "x") {
		t.Error("a segunda variante de md5 deveria casar")
	}
	if !f.bate("x", "ddd") {
		t.Error("a segunda variante de sha256 deveria casar")
	}
	if f.bate("zzz", "zzz") {
		t.Error("hash fora das variantes nao pode casar")
	}
}

func TestParsePluginChecksumsMisturaOsDoisFormatos(t *testing.T) {
	// Nada garante que a API use o mesmo formato para todos os arquivos de uma
	// mesma resposta.
	entrada := `{
	  "plugin": "x", "version": "1.0",
	  "files": {
	    "a.php": {"md5": "um", "sha256": "dois"},
	    "b.php": {"md5": ["tres"], "sha256": ["quatro", "cinco"]}
	  }
	}`
	resp, err := parsePluginChecksums([]byte(entrada))
	if err != nil {
		t.Fatalf("mistura de formatos foi recusada: %v", err)
	}
	if !resp.Files["a.php"].bate("um", "") {
		t.Error("formato escalar nao funcionou")
	}
	if !resp.Files["b.php"].bate("", "cinco") {
		t.Error("formato array nao funcionou")
	}
}

func TestArquivoSemHashNaoViraAchado(t *testing.T) {
	// Entrada sem hash nenhum nao pode virar achado de "alterado": nao ha com o
	// que comparar, e inventar divergencia a partir de dado ausente e o mesmo
	// erro de declarar limpo o que ninguem conferiu, na direcao oposta.
	entrada := `{
	  "plugin": "x", "version": "1.0",
	  "files": {"vazio.php": {}, "nulo.php": {"md5": null, "sha256": null}}
	}`
	resp, err := parsePluginChecksums([]byte(entrada))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for nome, f := range resp.Files {
		if f.temHash() {
			t.Errorf("%s deveria ser reportado como sem hash", nome)
		}
		if f.bate("qualquer", "coisa") {
			t.Errorf("%s nao pode casar com nada", nome)
		}
	}
}

func TestFormatoInesperadoEhErroEmVezDeSilencio(t *testing.T) {
	// Um numero onde deveria haver hash e sinal de que a API mudou. Falhar alto
	// faz o plugin constar como nao verificado; ignorar faria ele parecer limpo.
	entrada := `{"plugin":"x","version":"1.0","files":{"a.php":{"md5":123}}}`
	if _, err := parsePluginChecksums([]byte(entrada)); err == nil {
		t.Fatal("formato inesperado deveria ser erro")
	}
}

func TestRespostaSemArquivosAbstem(t *testing.T) {
	if _, err := parsePluginChecksums([]byte(`{"plugin":"x","version":"1.0","files":{}}`)); err == nil {
		t.Fatal("resposta sem arquivos deveria virar abstencao")
	}
}
