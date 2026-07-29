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

// ErrNotFound signals that the configuration file does not exist.
var ErrNotFound = errors.New("configuration file not found")

// Load reads the TOML at the given path. Missing fields keep their Default()
// value, so a three-line file stays valid: the user writes only what they want
// to change.
func Load(path string) (*Config, error) {
	cfg := Default()
	cfg.path = path

	data, err := os.ReadFile(path) // path comes from the user's own CLI
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid TOML in %s: %w", path, err)
	}

	// An unknown key is almost always a typo. Reporting instead of ignoring
	// avoids the worst possible scenario in a security tool: the user believes
	// they turned off automatic quarantine and they did not.
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		return cfg, fmt.Errorf("unknown keys in %s: %s (typo?)",
			path, strings.Join(keys, ", "))
	}

	cfg.normalize()
	return cfg, nil
}

// LoadOrDefault reads the file; if it does not exist, it returns the defaults
// tagged with the path, so a later Save() creates the file.
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

// normalize applies adjustments that are tidying rather than validation errors.
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

// Save writes the TOML atomically.
//
// Atomicity matters: the panel writes this file while a cycle may be reading it.
// A truncated write would leave the tool with no configuration — and with no
// configuration it does not know what the whitelist is or where the vault lives.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config has no path set: use SetPath()")
	}
	return c.SaveTo(c.path)
}

// SaveTo writes to a specific path.
func (c *Config) SaveTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating configuration directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op if the rename succeeds

	enc := toml.NewEncoder(tmp)
	enc.Indent = "  "
	if err := enc.Encode(c); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("serializing configuration: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing configuration: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}

	// The file holds the SMTP password and webhook secrets: 0600, always.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("adjusting configuration permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	c.path = path
	return nil
}

// EnsureDataDirs creates the data directory tree with restricted permissions.
func (c *Config) EnsureDataDirs() error {
	dirs := []string{
		c.General.DataDir,
		c.QuarantineDir(),
		c.RawOutputDir(),
		filepath.Join(c.General.DataDir, "engines"),
	}
	for _, d := range dirs {
		// 0700: the quarantine vault holds neutralized malicious files. No other
		// user on the host has any business in there.
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", d, err)
		}
	}
	return nil
}
