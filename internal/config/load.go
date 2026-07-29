package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// ErrNotFound indica que o arquivo de configuracao nao existe.
var ErrNotFound = errors.New("arquivo de configuracao nao encontrado")

// Load le o TOML do caminho dado. Campos ausentes ficam com o valor de
// Default(), de modo que um arquivo com tres linhas continue valido: o usuario
// escreve so o que quer mudar.
func Load(path string) (*Config, error) {
	cfg := Default()
	cfg.path = path

	data, err := os.ReadFile(path) // caminho vem da CLI do proprio usuario
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, fmt.Errorf("lendo %s: %w", path, err)
	}

	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("TOML invalido em %s: %w", path, err)
	}

	// Chave desconhecida quase sempre e erro de digitacao. Avisar em vez de
	// ignorar evita o pior cenario possivel numa ferramenta de seguranca: o
	// usuario acredita ter desligado a quarentena automatica e nao desligou.
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		return cfg, fmt.Errorf("chaves desconhecidas em %s: %s (erro de digitacao?)",
			path, strings.Join(keys, ", "))
	}

	cfg.normalize()
	return cfg, nil
}

// LoadOrDefault le o arquivo; se ele nao existir, devolve os padroes marcados
// com o caminho, para que um Save() posterior crie o arquivo.
func LoadOrDefault(path string) (*Config, bool, error) {
	cfg, err := Load(path)
	if errors.Is(err, ErrNotFound) {
		def := Default()
		def.path = path
		return def, false, nil
	}
	if err != nil {
		return cfg, false, err
	}
	return cfg, true, nil
}

// normalize aplica ajustes que nao sao erro de validacao, so arrumacao.
func (c *Config) normalize() {
	c.General.DataDir = expandHome(c.General.DataDir)
	c.Quarantine.Dir = expandHome(c.Quarantine.Dir)
	for i, r := range c.General.Roots {
		c.General.Roots[i] = expandHome(r)
	}
	if c.Engines == nil {
		c.Engines = map[string]Engine{}
	}
}

func expandHome(p string) string {
	if p == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// Save grava o TOML de forma atomica.
//
// Atomico importa: o painel grava este arquivo enquanto um ciclo pode estar
// lendo. Uma escrita truncada deixaria a ferramenta sem configuracao — e sem
// configuracao ela nao sabe o que e whitelist nem onde fica o cofre.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config sem caminho definido: use SetPath()")
	}
	return c.SaveTo(c.path)
}

// SaveTo grava num caminho especifico.
func (c *Config) SaveTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("criando diretorio de configuracao: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("criando arquivo temporario: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op se o rename der certo

	enc := toml.NewEncoder(tmp)
	enc.Indent = "  "
	if err := enc.Encode(c); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("serializando configuracao: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sincronizando configuracao: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fechando arquivo temporario: %w", err)
	}

	// O arquivo guarda senha de SMTP e segredos de webhook: 0600, sempre.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("ajustando permissao da configuracao: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("gravando %s: %w", path, err)
	}
	c.path = path
	return nil
}

// EnsureDataDirs cria a arvore de diretorios de dados com permissao restrita.
func (c *Config) EnsureDataDirs() error {
	dirs := []string{
		c.General.DataDir,
		c.QuarantineDir(),
		c.RawOutputDir(),
		filepath.Join(c.General.DataDir, "engines"),
	}
	for _, d := range dirs {
		// 0700: o cofre de quarentena guarda arquivos maliciosos neutralizados.
		// Nenhum outro usuario da hospedagem tem o que fazer ali.
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("criando %s: %w", d, err)
		}
	}
	return nil
}
