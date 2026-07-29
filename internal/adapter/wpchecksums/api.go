package wpchecksums

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultAPIBase is WordPress.org's public checksums API.
const DefaultAPIBase = "https://api.wordpress.org/core/checksums/1.0/"

// maxAPIBody caps the response. A core has a few thousand files; 8 MiB is
// generous and keeps an anomalous response from blowing up the orchestrator's
// memory.
const maxAPIBody = 8 << 20

// ErrVersionUnknown means the API does not publish checksums for this version.
var ErrVersionUnknown = errors.New("the API does not publish checksums for this version")

// apiResponse is the shape of the response.
//
// checksums comes back as an object when the version exists and as `false` when
// it does not — which is why the field is a json.RawMessage and not a map.
type apiResponse struct {
	Checksums json.RawMessage `json:"checksums"`
}

// client fetches official checksums.
type client struct {
	base string
	// pluginsBase overrides the plugins API in tests. Empty uses the official one.
	pluginsBase string
	http        *http.Client
}

func newClient(base string) *client {
	if base == "" {
		base = DefaultAPIBase
	}
	return &client{
		base: base,
		http: &http.Client{
			// Shared hosting sometimes has slow or blocked outbound traffic. A
			// short timeout beats a hung cycle: with no network the adapter
			// abstains and the other engines proceed.
			Timeout: 20 * time.Second,
		},
	}
}

// fetch retrieves the API's raw response.
//
// It returns the raw body because THAT is this adapter's archived raw output.
// Privacy: the request carries only the version and the locale. No file, path or
// hash of the user's leaves the hosting.
func (c *client) fetch(ctx context.Context, version, locale string) ([]byte, error) {
	if locale == "" {
		locale = "en_US"
	}
	u, err := url.Parse(c.base)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL: %w", err)
	}
	q := u.Query()
	q.Set("version", version)
	q.Set("locale", locale)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("User-Agent", "SentinelHost (scanner orchestrator; +https://github.com/thiagoluga/SentinelHost)")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying the checksums API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the checksums API answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return nil, fmt.Errorf("reading the API response: %w", err)
	}
	return body, nil
}

// ErrPluginNoChecksum means the API does not publish checksums for that
// plugin/version.
//
// It is the NORMAL case for a commercial plugin, an in-house plugin, or a version
// that left the official directory. It is not a failure and not a finding: the
// adapter abstains about that plugin. Treating absence of data as absence of a
// problem would declare clean what nobody checked.
var ErrPluginNoChecksum = errors.New("the API does not publish checksums for this plugin at this version")

// pluginFileSums are the hashes the API publishes per plugin file.
//
// Unlike the core, which only publishes MD5, both come back here. And the format
// of each is AMBIGUOUS in the real API: usually a string,
//
//	"classic-editor.php": {"md5": "d1ee...", "sha256": "1a81..."}
//
// but an array when the file has accepted variants (CRLF and LF line endings
// produce different hashes for the same logical content).
//
// Declaring only one of the two formats breaks everything silently: with
// `[]string`, Unmarshal fails on the common response and EVERY plugin is skipped
// as "unreadable response"; with `string`, it fails on the files that have
// variants. That is how the first version of this passed its tests (which used
// arrays) and detected nothing against the real API.
type pluginFileSums struct {
	MD5    []string
	SHA256 []string
}

// UnmarshalJSON accepts either a string or an array in each field.
func (s *pluginFileSums) UnmarshalJSON(data []byte) error {
	var raw struct {
		MD5    json.RawMessage `json:"md5"`
		SHA256 json.RawMessage `json:"sha256"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	if s.MD5, err = hashesFrom(raw.MD5); err != nil {
		return fmt.Errorf("md5 field: %w", err)
	}
	if s.SHA256, err = hashesFrom(raw.SHA256); err != nil {
		return fmt.Errorf("sha256 field: %w", err)
	}
	return nil
}

// hashesFrom normalizes a field that may be a string, an array of strings, or
// absent.
func hashesFrom(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil, nil
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("neither a string nor an array of strings: %s", truncate(raw))
	}
	return many, nil
}

func truncate(b []byte) string {
	const max = 60
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// pluginChecksumsResponse is the format of downloads.wordpress.org/plugin-checksums.
type pluginChecksumsResponse struct {
	Plugin  string                    `json:"plugin"`
	Version string                    `json:"version"`
	Files   map[string]pluginFileSums `json:"files"`
}

// fetchPlugin fetches the checksums of a plugin at a version.
//
// Privacy: the request carries only the slug and the version — exactly what the
// constitution authorizes ("hashes and version slugs"). No path or content of
// the user's leaves the hosting.
func (c *client) fetchPlugin(ctx context.Context, slug, version string) ([]byte, error) {
	if slug == "" || version == "" {
		return nil, ErrPluginNoChecksum
	}
	// The slug comes from a directory name on the user's disk. PathEscape keeps a
	// directory called `../something` from building a URL to somewhere else in
	// the API.
	u := c.pluginBase() + url.PathEscape(slug) + "/" + url.PathEscape(version) + ".json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("User-Agent", "SentinelHost (scanner orchestrator; +https://github.com/thiagoluga/SentinelHost)")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying the checksums of plugin %s: %w", slug, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 is the expected answer for a plugin outside the official directory.
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s %s", ErrPluginNoChecksum, slug, version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the checksums API for plugin %s answered %s", slug, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return nil, fmt.Errorf("reading the API response: %w", err)
	}
	return body, nil
}

// pluginBase resolves the base of the plugins API.
//
// It derives from the core base when that was overridden in a test, so the test
// needs no network — and so that no test hits the public API by accident.
func (c *client) pluginBase() string {
	if c.pluginsBase != "" {
		return c.pluginsBase
	}
	return PluginsAPIBase
}

// parsePluginChecksums interprets a plugin's response.
func parsePluginChecksums(body []byte) (pluginChecksumsResponse, error) {
	var resp pluginChecksumsResponse
	if len(body) == 0 {
		return resp, errors.New("empty response from the plugin checksums API")
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, fmt.Errorf("the API response is not valid JSON: %w", err)
	}
	if len(resp.Files) == 0 {
		return resp, ErrPluginNoChecksum
	}
	return resp, nil
}

// matches answers whether the local hash matches any published variant.
func (s pluginFileSums) matches(md5sum, sha string) bool {
	for _, h := range s.SHA256 {
		if h != "" && h == sha {
			return true
		}
	}
	for _, h := range s.MD5 {
		if h != "" && h == md5sum {
			return true
		}
	}
	return false
}

// hasHash answers whether the API published any hash for this file. An entry
// with no hash at all cannot become an "altered" finding.
func (s pluginFileSums) hasHash() bool {
	return len(s.SHA256) > 0 || len(s.MD5) > 0
}

// parseChecksums interprets the raw response.
func parseChecksums(body []byte) (map[string]string, error) {
	if len(body) == 0 {
		return nil, errors.New("empty response from the checksums API")
	}
	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("the API response is not valid JSON: %w", err)
	}
	if len(resp.Checksums) == 0 {
		return nil, errors.New("the API response has no checksums field")
	}

	// The API returns `"checksums": false` for an unknown version. Treating that
	// as "no file diverges" would declare the core clean for lack of information
	// — exactly the mistake Principle VI forbids.
	var asBool bool
	if err := json.Unmarshal(resp.Checksums, &asBool); err == nil {
		return nil, ErrVersionUnknown
	}

	var sums map[string]string
	if err := json.Unmarshal(resp.Checksums, &sums); err != nil {
		return nil, fmt.Errorf("the checksums field has an unexpected format: %w", err)
	}
	if len(sums) == 0 {
		return nil, ErrVersionUnknown
	}
	return sums, nil
}
