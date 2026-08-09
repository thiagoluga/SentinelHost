package wpchecksums

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	// searchDepth caps how far below each root DetectAll looks for installations.
	// Zero means DefaultSearchDepth.
	searchDepth int
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

// searchRoots is where this adapter looks, in priority order.
//
// An explicit BinaryPath is the user saying "the WordPress is here", and it wins: a
// search must never overrule a person who told us the answer. Otherwise every configured
// root is searched.
func searchRoots(env adapter.Environment) []string {
	if env.BinaryPath != "" {
		return []string{env.BinaryPath}
	}
	return env.Roots
}

// Probe looks for WordPress installations at or under the configured roots.
//
// It used to ask whether the root ITSELF was a WordPress, and nothing else. On a hosting
// account that is the wrong question: the root is the home directory and the site lives
// at public_html/<domain>/. The engine reported "this does not look like a WordPress
// installation: /home/user/wp-includes/version.php does not exist" for accounts running
// several of them, and abstained for the whole cycle.
//
// The cost is larger than the missing check. This is the only engine that votes FOR
// legitimacy, and that vote is a veto — a file identical to the official checksum is
// never quarantined however many heuristics flag it (D-005). Silent, it leaves genuine
// core files to be judged by heuristics alone.
func (a *Adapter) Probe(ctx context.Context, env adapter.Environment) adapter.ProbeResult {
	roots := searchRoots(env)
	if len(roots) == 0 {
		return adapter.Unavailable("no site root was given to the adapter")
	}

	res := DetectAll(ctx, roots, a.searchDepth, 0, 0)
	if len(res.Installs) == 0 {
		// Not a failure: a site that is not WordPress is an ordinary case, and the
		// adapter abstains without penalizing the other engines.
		//
		// The reason says where it looked and how far, because "we found nothing" and
		// "we did not look there" are the two answers a reader has to be able to tell
		// apart — and the old message named a single file, which made a search that
		// never happened look like a definitive result.
		reason := fmt.Sprintf(
			"%s: searched %s to a depth of %d (%d directories examined)",
			ErrNotWordPress, strings.Join(roots, ", "), res.Depth, res.DirsWalked)
		if len(res.Unreadable) > 0 {
			reason += fmt.Sprintf("; could not read %s", strings.Join(res.Unreadable, ", "))
		}
		// A door the search did not open belongs in the same sentence as "found
		// nothing", or the two become the same statement to whoever reads it.
		if n := len(res.SymlinkedDirs); n > 0 {
			reason += fmt.Sprintf("; %d director%s reached through a symlink %s not "+
				"entered (%s) — symlinks are never followed, so a WordPress behind one "+
				"is unexamined rather than absent",
				n, plural(n, "y", "ies"), plural(n, "was", "were"),
				strings.Join(res.SymlinkedDirs, ", "))
		}
		if res.StoppedAt != "" {
			reason += "; " + res.StoppedAt
		}
		return adapter.Unavailable(reason)
	}

	if env.Offline {
		return adapter.Unavailable(fmt.Sprintf(
			"%d WordPress installation(s) found, but offline mode prevents querying the "+
				"official checksums", len(res.Installs)))
	}

	version := "WordPress " + res.Installs[0].Version
	if len(res.Installs) > 1 {
		version = fmt.Sprintf("%d WordPress installations (%s and %d more)",
			len(res.Installs), res.Installs[0].Version, len(res.Installs)-1)
	}
	return adapter.ProbeResult{
		Available:  true,
		Version:    version,
		BinaryPath: res.Installs[0].Root,
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
	// Installations is one entry per WordPress found. An account routinely has
	// several — one per addon domain — and reporting on the first while looking like
	// the account had been covered is the failure this whole adapter exists to avoid.
	Installations []installPayload `json:"installations"`

	// Where the search looked, and what stopped it. Archived so a report of "nothing
	// found" can be audited later without re-running anything.
	SearchedRoots []string  `json:"searched_roots,omitempty"`
	SearchDepth   int       `json:"search_depth,omitempty"`
	SearchStopped string    `json:"search_stopped,omitempty"`
	Unreadable    []string  `json:"unreadable_roots,omitempty"`
	FetchedAt     time.Time `json:"fetched_at"`
}

// installPayload is everything gathered about ONE WordPress installation.
type installPayload struct {
	WPVersion   string               `json:"wp_version"`
	Root        string               `json:"root"`
	APIResponse json.RawMessage      `json:"api_response"`
	Local       map[string]LocalFile `json:"local"`
	Missing     []string             `json:"missing"`
	Extra       []LocalFile          `json:"extra"`

	// Plugins is the second half of FR-005. Empty when the installation has no
	// plugins or none of them has a published checksum.
	Plugins []pluginPayload `json:"plugins,omitempty"`
	// PluginsSkipped explains, per slug, why a plugin was not verified. It exists
	// so "not verified" never looks like "verified and clean" in the report.
	PluginsSkipped map[string]string `json:"plugins_skipped,omitempty"`

	// Unusable says why this installation could not be compared — the API refused,
	// the version is unknown, too much of the core is absent. One bad installation
	// must not take the others down, and it must not vanish either: it becomes a
	// counted skip, because an installation nobody checked is a gap in coverage.
	Unusable string `json:"unusable,omitempty"`
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

	roots := searchRoots(env)
	if len(roots) == 0 {
		// No environment was given — a direct caller, or a test driving the adapter
		// with only a ScanRequest. The request's own root is the answer then.
		roots = []string{req.Root}
	}
	res := DetectAll(ctx, roots, a.searchDepth, 0, 0)
	if len(res.Installs) == 0 {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf("%w: searched %s to a depth of %d (%d directories examined)",
			ErrNotWordPress, strings.Join(roots, ", "), res.Depth, res.DirsWalked)
	}

	versions := make([]string, 0, len(res.Installs))
	for _, inst := range res.Installs {
		versions = append(versions, inst.Version)
	}
	out.EngineVersion = "WordPress " + strings.Join(versions, ", ")

	if env.Offline {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		return out, fmt.Errorf("offline mode: the checksums API will not be queried")
	}

	payload := rawPayload{
		SearchedRoots: res.Roots,
		SearchDepth:   res.Depth,
		SearchStopped: res.StoppedAt,
		Unreadable:    res.Unreadable,
		FetchedAt:     time.Now(),
	}

	// Every installation is inventoried. One that cannot be is recorded as unusable and
	// the rest proceed — but if NONE could be, the engine fails rather than reporting an
	// empty result, because "we checked nothing" and "we checked and found nothing" are
	// the two statements this project exists to keep apart.
	usable := 0
	var lastErr error
	for _, inst := range res.Installs {
		ip, err := a.scanOne(ctx, inst)
		if err != nil {
			lastErr = err
			payload.Installations = append(payload.Installations, installPayload{
				Root: inst.Root, WPVersion: inst.Version, Unusable: err.Error(),
			})
			continue
		}
		usable++
		payload.Installations = append(payload.Installations, ip)
	}
	if usable == 0 {
		out.Status = schema.StatusFailed
		out.FinishedAt = time.Now()
		// With no checksums the adapter abstains. Declaring the core clean because it
		// could not ask would be this engine's worst possible mistake.
		return out, fmt.Errorf("no installation could be verified: %w", lastErr)
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

// scanOne inventories a single installation against the official checksums.
//
// Extracted unchanged from Scan when it learned to handle more than one site; every
// failure here is that installation's failure and nobody else's.
func (a *Adapter) scanOne(ctx context.Context, inst Install) (installPayload, error) {
	body, err := a.api.fetch(ctx, inst.Version, inst.Locale)
	if err != nil {
		return installPayload{}, fmt.Errorf("no official checksums for %s: %w", inst.Root, err)
	}
	sums, err := parseChecksums(body)
	if err != nil {
		return installPayload{}, fmt.Errorf("unreadable checksums for %s: %w", inst.Root, err)
	}

	local, missing := inventory(inst.Root, sums)
	plugins, skipped := a.scanPlugins(ctx, inst.Root)
	return installPayload{
		WPVersion:      inst.Version,
		Root:           inst.Root,
		APIResponse:    body,
		Local:          local,
		Missing:        missing,
		Extra:          extraFiles(inst.Root, sums, a.maxDepth),
		Plugins:        plugins,
		PluginsSkipped: skipped,
	}, nil
}

// Parse compares every installation's inventory against the official checksums.
//
// It handles a list because an account has a list: one WordPress per addon domain is the
// ordinary shape of shared hosting, not an edge case. Each installation is judged on its
// own, and one that cannot be judged becomes a counted skip rather than an error that
// discards the others' results.
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
	if len(payload.Installations) == 0 {
		return rep, fmt.Errorf("the inventory names no WordPress installation")
	}

	detectedAt := raw.FinishedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}

	skips := map[string]int{}
	// The reason of the last installation that could not be judged. When NONE could be,
	// it is returned as the engine's error — an adapter answering "completed, no
	// findings" after failing to compare anything is this project's own worst case.
	var lastRefusal error
	judged := 0

	for _, ip := range payload.Installations {
		if ip.Unusable != "" {
			skips["wordpress_not_verified"]++
			lastRefusal = fmt.Errorf("%s", ip.Unusable)
			continue
		}
		findings, clean, considered, scanned, err := a.parseOne(raw, ip, detectedAt)
		if err != nil {
			// Not fatal on its own: a directory that turned out not to hold a complete
			// core is one site's problem. It is COUNTED, so the gap stays visible.
			skips["wordpress_not_verified"]++
			lastRefusal = err
			continue
		}
		judged++
		rep.Findings = append(rep.Findings, findings...)
		rep.CleanFiles = append(rep.CleanFiles, clean...)
		rep.Scope.FilesConsidered += considered
		rep.Scope.FilesScanned += scanned

		// A plugin that was not verified must NEVER look like a plugin that was verified
		// and found clean. Each reason enters the report's accounting, which the panel
		// and `scan` display.
		//
		// Only genuine gaps go in here. SkippedReasonCounts answers exactly one question
		// — what did the scan NOT look at? — and it is the question this project is
		// organised around. A successfully verified plugin used to be counted here too,
		// under plugin_verified, which inverted the meaning twice over: a user reading
		// "skipped: plugin_verified=1" concludes coverage was lost and goes hunting for a
		// problem that does not exist, and plugin_without_checksum — a real gap, a plugin
		// nobody checked — ends up in the same list, indistinguishable from a success.
		skips["plugin_without_checksum"] += len(ip.PluginsSkipped)
	}

	if judged == 0 {
		return rep, fmt.Errorf(
			"none of the %d WordPress installation(s) found could be verified: %w",
			len(payload.Installations), lastRefusal)
	}

	for reason, n := range skips {
		if n == 0 {
			continue
		}
		if rep.Scope.SkippedReasonCounts == nil {
			rep.Scope.SkippedReasonCounts = map[string]int{}
		}
		rep.Scope.SkippedReasonCounts[reason] = n
	}

	return rep, nil
}

// parseOne turns one installation's inventory into findings.
//
// The error return means "this installation could not be judged", never "the engine
// failed": the caller counts it and carries on with the others.
func (a *Adapter) parseOne(raw adapter.RawOutput, payload installPayload, detectedAt time.Time) (
	findings []schema.Finding, clean []string, considered, scanned int, err error) {

	sums, err := parseChecksums(payload.APIResponse)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	// A missing core file needs far more care than an altered one.
	//
	// An "incomplete" WordPress is almost never an attack: it is the core living in a
	// subdirectory, a partial deploy, a symlink, or the configured root pointing at the
	// wrong place. Without this guard the adapter emits THOUSANDS of `likely` findings at
	// once — which is exactly what it did on its first real run, with 2998 findings on a
	// test site.
	//
	// Checked BEFORE any finding is built, so a comparison that lost its meaning
	// contributes nothing at all — including for the altered files, which would have been
	// compared against almost nothing.
	if len(sums) > 0 {
		missingRatio := float64(len(payload.Missing)) / float64(len(sums))
		if missingRatio > maxMissingRatio {
			return nil, nil, 0, 0, fmt.Errorf(
				"%.0f%% of the core files (%d of %d) do not exist in %s: "+
					"this does not look like a complete WordPress at this root, and comparing "+
					"checksums here would produce thousands of meaningless findings",
				missingRatio*100, len(payload.Missing), len(sums), payload.Root)
		}
	}

	// Files that MATCH become clean_files: the positive vote for legitimacy.
	clean = make([]string, 0, len(payload.Local))
	for rel, lf := range payload.Local {
		official, ok := sums[rel]
		if !ok {
			continue
		}
		if lf.MD5 == official {
			clean = append(clean, lf.SHA256)
			continue
		}
		findings = append(findings, finding(
			raw, lf, detectedAt,
			"core_file_modified",
			fmt.Sprintf("core file altered: %s", rel),
		))
	}

	// Executable code only. A .woff2 font or a .png that went missing is not a security
	// event — you cannot hide a backdoor in a file that does not exist, and the noise
	// would drown the findings that matter.
	for _, rel := range payload.Missing {
		if !isExecutableExt(rel) {
			continue
		}
		findings = append(findings, schema.Finding{
			SchemaVersion: schema.Version,
			Kind:          schema.KindMalware,
			Engine:        Slug,
			EngineVersion: raw.EngineVersion,
			Rule:          "core_file_missing",
			RuleRef:       "https://codex.wordpress.org/WordPress.org_API",
			File: schema.FileRef{
				Path: payload.Root + "/" + rel,
				// A missing file has no hash. The verdict engine deduplicates by
				// sha256, so we use the hash of the PATH so the finding has a stable
				// key across cycles without pretending to be a file that exists.
				SHA256: pathHash(payload.Root + "/" + rel),
			},
			Category: schema.CategoryCoreIntegrity,
			// Absence is NOT a signature of anything. A file that vanished holds no
			// malicious code and cannot be quarantined; treating this as `signature`
			// would let weight 1.5 push the finding on its own close to `confirmed`,
			// authorizing action on a file that does not even exist.
			Severity:       schema.SeverityMedium,
			Confidence:     schema.ConfidenceAnomaly,
			MatchedContent: schema.SanitizeSnippet("official core file missing: " + rel),
			ScanID:         raw.ScanID,
			DetectedAt:     detectedAt,
		})
	}

	// An extra executable file inside wp-admin/ or wp-includes/.
	for _, lf := range payload.Extra {
		findings = append(findings, finding(
			raw, lf, detectedAt,
			"core_file_unexpected",
			fmt.Sprintf("executable file that does not belong to the core: %s", lf.RelPath),
		))
	}

	// Plugins: the second half of FR-005.
	pluginFindings, pluginClean := a.parsePlugins(
		rawOutputInfo{ScanID: raw.ScanID, EngineVersion: raw.EngineVersion},
		payload, detectedAt)
	findings = append(findings, pluginFindings...)
	clean = append(clean, pluginClean...)

	considered = len(sums)
	scanned = len(payload.Local) + len(payload.Extra)
	for _, p := range payload.Plugins {
		considered += len(p.Local) + len(p.Missing)
		scanned += len(p.Local) + len(p.Extra)
	}
	return findings, clean, considered, scanned, nil
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

// plural picks a suffix. A message that says "1 directories" reads as a program that
// did not look closely, on a line whose whole job is to be believed.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
