package config

import (
	"fmt"
	"time"
)

// Duration e time.Duration que vai e volta do TOML como string legivel
// ("1h", "500ms", "5m").
//
// O TOML nao tem tipo de duracao. Guardar segundos crus obrigaria o usuario a
// contar na mao quanto e um dia, e o arquivo de configuracao precisa ser
// legivel por gente (Principio VII).
type Duration struct {
	time.Duration
}

// D constroi uma Duration.
func D(d time.Duration) Duration { return Duration{d} }

// UnmarshalText implementa encoding.TextUnmarshaler para o BurntSushi/toml.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("duracao %q invalida (use 30s, 5m, 1h): %w", string(text), err)
	}
	d.Duration = parsed
	return nil
}

// MarshalText implementa encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// MarshalJSON exporta a duracao como string, para a API do painel.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

// UnmarshalJSON aceita a string vinda do painel.
func (d *Duration) UnmarshalJSON(data []byte) error {
	s := string(data)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	return d.UnmarshalText([]byte(s))
}
