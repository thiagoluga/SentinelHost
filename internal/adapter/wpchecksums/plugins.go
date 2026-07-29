package wpchecksums

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// PLUGIN integrity, the second half of FR-005 ("core and, when available,
// plugins").
//
// An abandoned plugin is the most common intrusion vector in WordPress, and a
// legitimate plugin with one altered file is a backdoor's favourite hiding place:
// it does not show up in the core verification and the user never suspects a
// plugin they installed themselves.
//
// The API differs from the core's, and the difference matters:
//   - the core has ONE list for the whole installation;
//   - each plugin has its own, published per version, and **only if it came from
//     the official directory**. A commercial or in-house plugin has no checksum
//     at all — and in that case the adapter abstains about it instead of treating
//     absence of data as absence of a problem.

// PluginsAPIBase publishes checksums per plugin and version.
const PluginsAPIBase = "https://downloads.wordpress.org/plugin-checksums/"

// maxPlugins caps how many plugins are verified in one cycle.
//
// Each plugin costs one HTTP request. A site with 80 plugins would generate 80
// requests per cycle — needless load on the public API of a project that serves
// us for free, and cycle time Principle IV does not authorize.
const maxPlugins = 40

// maxMissingRatioPlugin is the ceiling of missing files before the adapter
// concludes that directory is not the version it thinks it is.
//
// Looser than the core's (10%) on purpose: a plugin usually has few files, and a
// single missing one out of five would already be 20% without meaning anything.
const maxMissingRatioPlugin = 0.34

var (
	// WordPress plugin headers. `(?i)` because the WordPress standard is
	// case-tolerant and real plugins abuse it.
	pluginNameRe    = regexp.MustCompile(`(?i)^[ \t/*#@]*Plugin Name:\s*(.+)$`)
	pluginVersionRe = regexp.MustCompile(`(?i)^[ \t/*#@]*Version:\s*(.+)$`)
)

// PluginInstall is a plugin found on disk.
type PluginInstall struct {
	// Slug is the directory name, which is what the API indexes.
	Slug string `json:"slug"`
	// Dir is the absolute path of the plugin's directory.
	Dir string `json:"dir"`
	// Name is the "Plugin Name" header, for display only.
	Name string `json:"name"`
	// Version is the "Version" header. Empty blocks verification: with no version
	// there is no checksum to look up.
	Version string `json:"version"`
}

// DetectPlugins lists the plugins installed under the root.
//
// The slug is the DIRECTORY name, not the header's: that is how the API indexes
// them, and what WordPress uses to identify the plugin.
func DetectPlugins(root string) ([]PluginInstall, error) {
	base := filepath.Join(root, "wp-content", "plugins")
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A site with no wp-content/plugins is not an error: it may be an
			// installation with a custom content directory.
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", base, err)
	}

	var out []PluginInstall
	for _, e := range entries {
		if !e.IsDir() {
			// A single-file plugin (hello.php) has no published checksum.
			continue
		}
		// A symlink is never followed, here as in the walker: a link inside
		// wp-content/plugins could point outside the authorized root.
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		dir := filepath.Join(base, e.Name())
		p := PluginInstall{Slug: e.Name(), Dir: dir}
		if name, version := readPluginHeader(dir); version != "" {
			p.Name, p.Version = name, version
		}
		out = append(out, p)
	}

	// Stable order: two cycles' reports must not diverge because of directory
	// read order.
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// readPluginHeader looks for "Plugin Name" and "Version" in the PHP files at the
// directory's first level.
//
// WordPress reads only the first 8 KiB of the main file, and the header is always
// at the top — reading the whole file would be a waste in a directory that may
// hold megabytes of code.
func readPluginHeader(dir string) (name, version string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}

	// The main file usually carries the directory's name; try that one before
	// sweeping the rest, because it is the overwhelmingly common case.
	candidates := make([]string, 0, len(entries))
	main := filepath.Base(dir) + ".php"
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".php") {
			continue
		}
		if e.Name() == main {
			candidates = append([]string{e.Name()}, candidates...)
			continue
		}
		candidates = append(candidates, e.Name())
	}

	for _, file := range candidates {
		n, v := headerOf(filepath.Join(dir, file))
		if v != "" {
			return n, v
		}
	}
	return "", ""
}

func headerOf(path string) (name, version string) {
	f, err := os.Open(path) // path derived from the configured root
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(io.LimitReader(f, 8<<10))
	for sc.Scan() {
		line := sc.Text()
		if name == "" {
			if m := pluginNameRe.FindStringSubmatch(line); m != nil {
				name = strings.TrimSpace(m[1])
			}
		}
		if version == "" {
			if m := pluginVersionRe.FindStringSubmatch(line); m != nil {
				version = strings.TrimSpace(m[1])
			}
		}
		if name != "" && version != "" {
			break
		}
	}
	// A name with no version is useless for a checksum, and a version with no
	// name smells like a regex false positive (a stray `Version:` in a code
	// comment).
	if version == "" || name == "" {
		return "", ""
	}
	return name, version
}

// pluginInventory computes the hashes of a plugin's files.
//
// Unlike the core, here the inventory starts from the API's list rather than from
// walking the directory: what matters is comparing what the API knows with what
// is on disk.
func pluginInventory(dir string, checksums map[string]pluginFileSums) (map[string]LocalFile, []string) {
	local := make(map[string]LocalFile, len(checksums))
	var missing []string

	for rel := range checksums {
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			missing = append(missing, rel)
			continue
		}
		md5sum, sha, err := hashFile(abs)
		if err != nil {
			// Unreadable is neither missing nor altered. Asserting anything about
			// a file we could not read would be a guess.
			continue
		}
		local[rel] = LocalFile{
			RelPath: rel,
			AbsPath: abs,
			MD5:     md5sum,
			SHA256:  sha,
			Size:    info.Size(),
			Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
			MTime:   info.ModTime().Unix(),
		}
	}
	sort.Strings(missing)
	return local, missing
}

// extraPluginFiles looks for executable files the API does not know about.
//
// It is this verifier's most valuable finding: one extra `.php` inside an
// official plugin has no innocent explanation. Unlike the core, tolerance here is
// zero — a plugin does not grow files on its own.
func extraPluginFiles(dir string, checksums map[string]pluginFileSums, maxDepth int) []LocalFile {
	var out []LocalFile

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if depthOf(dir, path) > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		slashRel := filepath.ToSlash(rel)
		if _, known := checksums[slashRel]; known {
			return nil
		}
		if !isExecutableExt(slashRel) {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		md5sum, sha, hashErr := hashFile(path)
		if hashErr != nil {
			return nil
		}
		out = append(out, LocalFile{
			RelPath: slashRel,
			AbsPath: path,
			MD5:     md5sum,
			SHA256:  sha,
			Size:    info.Size(),
			Perms:   fmt.Sprintf("%04o", info.Mode().Perm()),
			MTime:   info.ModTime().Unix(),
		})
		return nil
	})

	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out
}
