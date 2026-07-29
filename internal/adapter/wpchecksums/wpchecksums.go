package wpchecksums

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// maxMissingRatio is the fraction of core files that may be absent before the
// adapter concludes that root does not hold a complete WordPress.
//
// 10% is generous on purpose: an intact core does not lose 300 files. Above that,
// the likely explanation is structural (core in a subdirectory, partial deploy,
// walker exclusion), never "the site was broken into in a way that deleted half of
// WordPress".
const maxMissingRatio = 0.10

// Adapter is the native WordPress integrity adapter.
type Adapter struct {
	api *client
	// maxDepth caps the search for extra files.
	maxDepth int
}

// New creates the adapter against the official API.
func New() *Adapter { return &Adapter{api: newClient(""), maxDepth: 12} }

// NewWithBase creates the adapter pointing at another API base (tests).
func NewWithBase(base string) *Adapter { return &Adapter{api: newClient(base), maxDepth: 12} }

// NewWithBases overrides BOTH the core and the plugins bases.
//
// It exists so no test hits the public WordPress.org API: a test that depends on
// the network fails in CI for reasons unrelated to the code, and would spend, for
// free, the infrastructure of a project that already serves us for free.
func NewWithBases(coreBase, pluginsBase string) *Adapter {
	c := newClient(coreBase)
	c.pluginsBase = pluginsBase
	return &Adapter{api: c, maxDepth: 12}
}

func (a *Adapter) Info() adapter.Info {
	return adapter.Info{
		Slug:     Slug,
		Name:     "WordPress core integrity",
		License:  "N/A (native; queries the public WordPress.org API)",
		Homepage: "https://codex.wordpress.org/WordPress.org_API",
		Kind:     schema.KindMalware,
		Categories: []schema.Category{
			schema.CategoryCoreIntegrity,
			schema.CategorySuspiciousLocation,
		},
		Cost: adapter.CostLight,
		// Integrity is a question about the WHOLE core; the adapter inventories
		// every file the API knows about, not the cycle's list.
		ScopeAware:      false,
		RequiresNetwork: true,
		DefaultWeight:   config.WeightWPChecksums,
	}
}

// Probe checks whether there is a WordPress under the root.
//
// The root arrives in env.BinaryPath by this native adapter's convention: it has
// no binary, and what it needs to know is where to look.
func (a *Adapter) Probe(_ context.Context, env adapter.Environment) adapter.ProbeResult {
	root := env.BinaryPath
	if root == "" {
		return adapter.Unavailable("the site root was not given to the adapter")
	}
	inst, err := Detect(root)
	if err != nil {
		// Not a failure: it is a site that is not WordPress. The adapter abstains
		// without penalizing the other engines.
		return adapter.Unavailable(err.Error())
	}
	if env.Offline {
		return adapter.Unavailable(fmt.Sprintf(
			"WordPress %s detected, but offline mode prevents querying the official checksums", inst.Version))
	}
	return adapter.ProbeResult{
		Available:  true,
		Version:    "WordPress " + inst.Version,
		BinaryPath: root,
	}
}

// Install does not apply: the adapter is native.
func (a *Adapter) Install(context.Context, adapter.Environment) error {
	return adapter.ErrNotInstallable
}

// UpdateSignatures does not apply: the checksums are fetched on every scan and
// always reflect the version installed at that moment.
func (a *Adapter) UpdateSignatures(context.Context, adapter.Environment) (time.Time, error) {
	return time.Time{}, nil
}

// rawPayload is what this adapter archives as its raw output.
//
// The API response goes in raw in APIResponse; the local inventory rides along so
// Parse can work without re-reading the disk. Unlike the other engines,
// reprocessing an old scan from here has limited value: integrity is a question
// about the CURRENT state of the files.
type rawPayload struct {
	WPVersion   string               `json:"wp_version"`
	Root        string               `json:"root"`
	APIResponse json.RawMessage      `json:"api_response"`
	Local       map[string]LocalFile `json:"local"`
	Missing     []string             `json:"missing"`
	Extra       []LocalFile          `json:"extra"`
	FetchedAt   time.Time            `json:"fetched_at"`

	// Plugins is the second half of FR-005. Empty when the installation has no
	// plugins or none of them has a published checksum.
	Plugins []pluginPayload `json:"plugins,omitempty"`
	// PluginsSkipped explains, per slug, why a plugin was not verified. It exists
	// so "not verified" never looks like "verified and clean" in the report.
	PluginsSkipped map[string]string `json:"plugins_skipped,omitempty"`
}

// pluginPayload is the result of verifying ONE plugin.
type pluginPayload struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Dir     string `json:"dir"`
	// APIResponse raw, so Parse can reprocess without the network.
	APIResponse json.RawMessage      `json:"api_response"`
	Local       map[string]LocalFile `json:"local"`
	Missing     []string             `json:"missing"`
	Extra       []LocalFile          `json:"extra"`
}

// Scan queries the API and builds the local inventory.
func (a *Adapter) Scan(ctx context.Context, env adapter.Environment, req adapter.ScanRequest) (adapter.RawOutput, error) {
	started := time.Now()
	out := adapter.RawOutput{
		Engine:         Slug,
		ScanID:         req.ScanID,
		Root:           req.Root,
		Mode:           req.Mode,
		StartedAt:      started,
		PathsRequested: len(req.Paths),
	}

	inst, err := Detect(req.Root)
	if err != nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, err
	}
	out.EngineVersion = "WordPress " + inst.Version

	if env.Offline {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf("offline mode: the checksums API will not be queried")
	}

	body, err := a.api.fetch(ctx, inst.Version, inst.Locale)
	if err != nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		// With no network the adapter abstains. Declaring the core clean because
		// it could not ask would be this engine's worst possible mistake.
		return out, fmt.Errorf("no official checksums: %w", err)
	}

	sums, err := parseChecksums(body)
	if err != nil {
		out.Stdout = body
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, err
	}

	local, missing := inventory(req.Root, sums)
	plugins, skipped := a.scanPlugins(ctx, req.Root)
	payload := rawPayload{
		WPVersion:      inst.Version,
		Root:           req.Root,
		APIResponse:    body,
		Local:          local,
		Missing:        missing,
		Extra:          extraFiles(req.Root, sums, a.maxDepth),
		FetchedAt:      time.Now(),
		Plugins:        plugins,
		PluginsSkipped: skipped,
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf("serializing the inventory: %w", err)
	}

	out.Stdout = blob
	out.Status = schema.StatusCompleted
	out.FinishedAt = time.Now()
	return out, nil
}

// Parse compares the inventory against the official checksums.
func (a *Adapter) Parse(raw adapter.RawOutput) (schema.ScanReport, error) {
	rep := schema.ScanReport{
		SchemaVersion: schema.Version,
		ScanID:        raw.ScanID,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		StartedAt:     raw.StartedAt,
		FinishedAt:    raw.FinishedAt,
		Status:        schema.StatusCompleted,
		Scope:         schema.Scope{Root: raw.Root, Mode: raw.Mode},
		Findings:      []schema.Finding{},
		RawRef:        raw.RawRef,
	}

	var payload rawPayload
	if err := json.Unmarshal(raw.Stdout, &payload); err != nil {
		return rep, fmt.Errorf("unreadable inventory: %w", err)
	}
	sums, err := parseChecksums(payload.APIResponse)
	if err != nil {
		return rep, err
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	// Files that MATCH become clean_files: the positive vote for legitimacy.
	clean := make([]string, 0, len(payload.Local))
	for rel, lf := range payload.Local {
		official, ok := sums[rel]
		if !ok {
			continue
		}
		if lf.MD5 == official {
			clean = append(clean, lf.SHA256)
			continue
		}
		rep.Findings = append(rep.Findings, finding(
			raw, lf, detectedAt,
			"core_file_modified",
			fmt.Sprintf("core file altered: %s", rel),
		))
	}
	rep.CleanFiles = clean

	// A missing core file needs far more care than an altered one.
	//
	// An "incomplete" WordPress is almost never an attack: it is the core living
	// in a subdirectory, a partial deploy, a symlink, or the configured root
	// pointing at the wrong place. Without the two guards below this adapter emits
	// THOUSANDS of `likely` findings at once — which is exactly what it did on its
	// first real run, with 2998 findings on a test site.
	//
	// Guard 1: the ratio. If too much of the core is missing, the whole comparison
	// lost its meaning — including for the altered files, which were checked
	// against almost nothing. The adapter abstains with a reason, which is the
	// honest answer (Principle VI).
	if len(sums) > 0 {
		missingRatio := float64(len(payload.Missing)) / float64(len(sums))
		if missingRatio > maxMissingRatio {
			return rep, fmt.Errorf(
				"%.0f%% of the core files (%d of %d) do not exist in %s: "+
					"this does not look like a complete WordPress at this root, and comparing "+
					"checksums here would produce thousands of meaningless findings",
				missingRatio*100, len(payload.Missing), len(sums), payload.Root)
		}
	}

	// Guard 2: executable code only. A .woff2 font or a .png that went missing is
	// not a security event — you cannot hide a backdoor in a file that does not
	// exist, and the noise would drown the findings that matter.
	for _, rel := range payload.Missing {
		if !isExecutableExt(rel) {
			continue
		}
		rep.Findings = append(rep.Findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          "core_file_missing",
			RuleRef:       "https://codex.wordpress.org/WordPress.org_API",
			File: schema.FileRef{
				Path: payload.Root + "/" + rel,
				// A missing file has no hash. The verdict engine deduplicates by
				// sha256, so we use the hash of the PATH so the finding has a
				// stable key across cycles without pretending to be a file that
				// exists.
				SHA256: pathHash(payload.Root + "/" + rel),
			},
			Category: schema.CategoryCoreIntegrity,
			// Absence is NOT a signature of anything. A file that vanished holds no
			// malicious code and cannot be quarantined; treating this as
			// `signature` would let weight 1.5 push the finding on its own close to
			// `confirmed`, authorizing action on a file that does not even exist.
			Severity:       schema.SeverityMedium,
			Confidence:     schema.ConfidenceAnomaly,
			MatchedContent: schema.SanitizeSnippet("official core file missing: " + rel),
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	// An extra executable file inside wp-admin/ or wp-includes/.
	for _, lf := range payload.Extra {
		rep.Findings = append(rep.Findings, finding(
			raw, lf, detectedAt,
			"core_file_unexpected",
			fmt.Sprintf("executable file that does not belong to the core: %s", lf.RelPath),
		))
	}

	// Plugins: the second half of FR-005.
	pluginFindings, pluginClean := a.parsePlugins(
		rawOutputInfo{ScanID: raw.ScanID, EngineVersion: raw.EngineVersion},
		payload, detectedAt)
	rep.Findings = append(rep.Findings, pluginFindings...)
	rep.CleanFiles = append(rep.CleanFiles, pluginClean...)

	rep.Scope.FilesConsidered = len(sums)
	rep.Scope.FilesScanned = len(payload.Local) + len(payload.Extra)
	for _, p := range payload.Plugins {
		rep.Scope.FilesConsidered += len(p.Local) + len(p.Missing)
		rep.Scope.FilesScanned += len(p.Local) + len(p.Extra)
	}

	// A plugin that was not verified must NEVER look like a plugin that was
	// verified and found clean. Each reason enters the report's accounting, which
	// the panel and `scan` display.
	if len(payload.PluginsSkipped) > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["plugin_without_checksum"] = len(payload.PluginsSkipped)
	}
	if n := len(payload.Plugins); n > 0 {
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts["plugin_verified"] = n
	}

	return rep, nil
}

func finding(raw adapter.RawOutput, lf LocalFile, detectedAt time.Time, rule, msg string) schema.Finding {
	return schema.Finding{
		SchemaVersion: schema.Version,
		Kind:          schema.KindMalware,
		Engine:        Slug,
		EngineVersion: raw.EngineVersion,
		Rule:          rule,
		RuleRef:       "https://codex.wordpress.org/WordPress.org_API",
		File: schema.FileRef{
			Path:      lf.AbsPath,
			SizeBytes: lf.Size,
			SHA256:    lf.SHA256,
			MD5:       lf.MD5,
			MTime:     time.Unix(lf.MTime, 0),
			Perms:     lf.Perms,
		},
		Category: schema.CategoryCoreIntegrity,
		// Divergence from the official checksum is proof, not suspicion: the file
		// is not what WordPress.org published. Hence confidence=signature and
		// severity=critical — that is what justifies weight 1.5 in the consensus.
		Severity:       schema.SeverityCritical,
		Confidence:     schema.ConfidenceSignature,
		MatchedContent: schema.SanitizeSnippet(msg),
		ScanID:         raw.ScanID,
		DetectedAt:     detectedAt,
	}
}
