package wpchecksums

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// scanPlugins verifies the integrity of each installed plugin.
//
// No failure here takes down the core verification: a plugin the API does not
// know, or a request that failed, goes into `skipped` with the reason. The core is
// the project's highest-weight signal and must not be left unverified because a
// third-party plugin has no published checksum.
func (a *Adapter) scanPlugins(ctx context.Context, root string) ([]pluginPayload, map[string]string) {
	skipped := map[string]string{}

	installed, err := DetectPlugins(root)
	if err != nil {
		skipped["*"] = "could not list the plugins: " + err.Error()
		return nil, skipped
	}
	if len(installed) == 0 {
		return nil, nil
	}

	if len(installed) > maxPlugins {
		// Truncating silently would make the report look complete. The user needs
		// to know that 30 of their 70 plugins were not looked at.
		for _, p := range installed[maxPlugins:] {
			skipped[p.Slug] = fmt.Sprintf(
				"the limit of %d plugins per cycle was reached; it will be verified in a later cycle", maxPlugins)
		}
		installed = installed[:maxPlugins]
	}

	var out []pluginPayload
	for _, p := range installed {
		if ctx.Err() != nil {
			skipped[p.Slug] = "the cycle was cancelled before verifying this plugin"
			continue
		}
		if p.Version == "" {
			skipped[p.Slug] = "the plugin does not declare Version in its header; with no version there is no checksum to look up"
			continue
		}

		body, err := a.api.fetchPlugin(ctx, p.Slug, p.Version)
		if err != nil {
			if errors.Is(err, ErrPluginNoChecksum) {
				// Normal case: a commercial or in-house plugin, or a version that
				// left the official directory.
				skipped[p.Slug] = fmt.Sprintf(
					"the API does not publish checksums for %s %s (commercial or in-house plugin?)", p.Slug, p.Version)
			} else {
				skipped[p.Slug] = "the API query failed: " + err.Error()
			}
			continue
		}

		resp, err := parsePluginChecksums(body)
		if err != nil {
			skipped[p.Slug] = "unreadable API response: " + err.Error()
			continue
		}

		local, missing := pluginInventory(p.Dir, resp.Files)

		// The same guard as the core's, calibrated for a plugin: if too much is
		// missing, the directory is probably not the version the header declares —
		// and emitting one finding per file would drown the report.
		if len(resp.Files) > 0 {
			ratio := float64(len(missing)) / float64(len(resp.Files))
			if ratio > maxMissingRatioPlugin {
				skipped[p.Slug] = fmt.Sprintf(
					"%d of %d files of %s %s do not exist on disk (%.0f%%): "+
						"the directory is probably not the version the header declares",
					len(missing), len(resp.Files), p.Slug, p.Version, ratio*100)
				continue
			}
		}

		out = append(out, pluginPayload{
			Slug:        p.Slug,
			Name:        p.Name,
			Version:     p.Version,
			Dir:         p.Dir,
			APIResponse: body,
			Local:       local,
			Missing:     missing,
			Extra:       extraPluginFiles(p.Dir, resp.Files, a.maxDepth),
		})
	}

	if len(skipped) == 0 {
		skipped = nil
	}
	return out, skipped
}

// parsePlugins turns the plugins payload into normalized findings.
//
// It also returns the sha256s that match the official ones: they go into
// `clean_files` alongside the core's and become a veto in the verdict engine. A
// legitimate plugin file flagged by another engine's heuristic needs that same
// protection — plugins tend to carry minified JS and base64, which is exactly what
// produces false positives.
func (a *Adapter) parsePlugins(raw rawOutputInfo, payload rawPayload, detectedAt time.Time) ([]schema.Finding, []string) {
	var findings []schema.Finding
	var clean []string

	for _, p := range payload.Plugins {
		resp, err := parsePluginChecksums(p.APIResponse)
		if err != nil {
			// The payload was written with a response that had already been
			// validated; getting here means the raw file is corrupted. Do not
			// invent a finding out of data that cannot be interpreted.
			continue
		}

		for rel, lf := range p.Local {
			official, ok := resp.Files[rel]
			if !ok || !official.hasHash() {
				continue
			}
			if official.matches(lf.MD5, lf.SHA256) {
				clean = append(clean, lf.SHA256)
				continue
			}
			findings = append(findings, pluginFinding(raw, p, lf, detectedAt,
				"plugin_file_modified", schema.SeverityCritical, schema.ConfidenceSignature,
				fmt.Sprintf("altered file in plugin %s %s: %s", p.Slug, p.Version, rel)))
		}

		for _, rel := range p.Missing {
			lf := LocalFile{
				RelPath: rel,
				AbsPath: p.Dir + "/" + rel,
				SHA256:  pathHash(p.Dir + "/" + rel),
			}
			findings = append(findings, pluginFinding(raw, p, lf, detectedAt,
				"plugin_file_missing", schema.SeverityMedium, schema.ConfidenceAnomaly,
				fmt.Sprintf("official file missing from plugin %s %s: %s", p.Slug, p.Version, rel)))
		}

		for _, lf := range p.Extra {
			// Zero tolerance: an official plugin does not grow a `.php` on its
			// own. It is this verifier's most valuable finding, because a backdoor
			// inside a legitimate plugin does not show up in the core check and the
			// user never suspects what they installed themselves.
			findings = append(findings, pluginFinding(raw, p, lf, detectedAt,
				"plugin_file_unexpected", schema.SeverityCritical, schema.ConfidenceSignature,
				fmt.Sprintf("executable file that does not belong to plugin %s %s: %s",
					p.Slug, p.Version, lf.RelPath)))
		}
	}

	sort.Strings(clean)
	return findings, clean
}

// rawOutputInfo is the minimum the Finding builders need from the RawOutput.
type rawOutputInfo struct {
	ScanID        string
	EngineVersion string
}

func pluginFinding(
	raw rawOutputInfo,
	p pluginPayload,
	lf LocalFile,
	detectedAt time.Time,
	rule string,
	sev schema.Severity,
	conf schema.Confidence,
	msg string,
) schema.Finding {
	var mtime time.Time
	if lf.MTime > 0 {
		mtime = time.Unix(lf.MTime, 0)
	}
	return schema.Finding{
		SchemaVersion: schema.Version,
		Kind:          schema.KindMalware,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		Rule:          rule,
		RuleRef:       "https://downloads.wordpress.org/plugin-checksums/",
		File: schema.FileRef{
			Path:      lf.AbsPath,
			SizeBytes: lf.Size,
			SHA256:    lf.SHA256,
			MD5:       lf.MD5,
			MTime:     mtime,
			Perms:     lf.Perms,
		},
		Category:       schema.CategoryCoreIntegrity,
		Severity:       sev,
		Confidence:     conf,
		MatchedContent: schema.SanitizeSnippet(msg),
		ScanID:         raw.ScanID,
		DetectedAt:     detectedAt,
	}
}
