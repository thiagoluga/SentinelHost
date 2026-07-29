package config

import (
	"fmt"
	"time"
)

// Duration is a time.Duration that round-trips through TOML as a readable
// string ("1h", "500ms", "5m").
//
// TOML has no duration type. Storing raw seconds would force the user to count
// how many of them make a day, and the configuration file has to be readable by
// humans (Principle VII).
type Duration struct {
	time.Duration
}

// D builds a Duration.
func D(d time.Duration) Duration { return Duration{d} }

// UnmarshalText implements encoding.TextUnmarshaler for BurntSushi/toml.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q (use 30s, 5m, 1h): %w", string(text), err)
	}
	d.Duration = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// MarshalJSON exports the duration as a string, for the panel API.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

// UnmarshalJSON accepts the string coming from the panel.
func (d *Duration) UnmarshalJSON(data []byte) error {
	s := string(data)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	return d.UnmarshalText([]byte(s))
}
