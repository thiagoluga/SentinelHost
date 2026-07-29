package main

import (
	"flag"
	"io"
	"testing"
)

// O flag da biblioteca padrao para de parsear no primeiro argumento que nao
// comeca com traco. Isso fazia `quarantine restore <ref> --config /caminho`
// ignorar o --config em SILENCIO e cair no caminho padrao — e a forma
// documentada no quickstart e justamente essa.
//
// O sintoma era um erro enganoso ("configuracao nao encontrada") num comando
// que recebeu a configuracao corretamente; o risco real era agir sobre a
// instancia errada numa maquina com mais de um site.

func novoFS() (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet("teste", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "/padrao/config.toml", "")
	force := fs.Bool("force", false, "")
	return fs, cfg, force
}

func TestFlagDepoisDoPosicionalEhLida(t *testing.T) {
	fs, cfg, _ := novoFS()

	pos, err := parseArgs(fs, []string{"q_123", "--config", "/meu/config.toml"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 1 || pos[0] != "q_123" {
		t.Fatalf("posicionais: %v", pos)
	}
	if *cfg != "/meu/config.toml" {
		t.Errorf("--config depois do posicional foi ignorada: %q", *cfg)
	}
}

func TestFlagAntesDoPosicionalContinuaFuncionando(t *testing.T) {
	fs, cfg, _ := novoFS()

	pos, err := parseArgs(fs, []string{"--config", "/meu/config.toml", "q_123"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 1 || pos[0] != "q_123" {
		t.Fatalf("posicionais: %v", pos)
	}
	if *cfg != "/meu/config.toml" {
		t.Errorf("config: %q", *cfg)
	}
}

func TestFlagsIntercaladasComPosicionais(t *testing.T) {
	fs, cfg, force := novoFS()

	pos, err := parseArgs(fs, []string{"--force", "q_123", "--config", "/x.toml", "q_456"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 2 || pos[0] != "q_123" || pos[1] != "q_456" {
		t.Fatalf("posicionais: %v", pos)
	}
	if !*force {
		t.Error("--force antes do posicional foi perdida")
	}
	if *cfg != "/x.toml" {
		t.Errorf("--config entre posicionais foi perdida: %q", *cfg)
	}
}

func TestSemPosicionalUsaOPadrao(t *testing.T) {
	fs, cfg, _ := novoFS()

	pos, err := parseArgs(fs, []string{"--config", "/y.toml"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 0 {
		t.Errorf("nao deveria haver posicionais: %v", pos)
	}
	if *cfg != "/y.toml" {
		t.Errorf("config: %q", *cfg)
	}
}

func TestFlagDesconhecidaEhErro(t *testing.T) {
	// Uma flag digitada errado nao pode virar argumento posicional em
	// silencio: numa ferramenta que move arquivos, `--fofce` precisa falhar,
	// nao ser tratado como o nome de uma referencia de quarentena.
	fs, _, _ := novoFS()

	if _, err := parseArgs(fs, []string{"q_123", "--nao-existe"}); err == nil {
		t.Fatal("flag desconhecida deveria ser erro")
	}
}

func TestListaVaziaNaoQuebra(t *testing.T) {
	fs, cfg, _ := novoFS()

	pos, err := parseArgs(fs, nil)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 0 {
		t.Errorf("posicionais: %v", pos)
	}
	if *cfg != "/padrao/config.toml" {
		t.Errorf("o padrao deveria ter sido preservado: %q", *cfg)
	}
}
