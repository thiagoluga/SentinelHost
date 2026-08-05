// Package catalog holds the rulesets SentinelHost can install.
//
// The manifests are embedded, not fetched. A registry downloaded at runtime would make
// whatever serves it the thing worth attacking, and "approved" would quietly come to mean
// "approved unless somebody took over that host". What a user can install is what shipped
// inside the binary they verified: submitting is a pull request, approving is a merge, and
// distributing is the next release.
package catalog

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed entries/*.toml
var entries embed.FS

// Entry is one installable ruleset.
type Entry struct {
	Slug     string `toml:"slug"`
	Name     string `toml:"name"`
	Homepage string `toml:"homepage"`
	// License is an SPDX identifier, and it is shown before installing.
	//
	// Rulesets are not always permissive: signature-base is CC-BY-NC, which forbids
	// commercial use. A hosting company rolling that across customer accounts would be
	// violating a licence nobody meant to violate, so the value is carried rather than
	// dropped as metadata.
	License string `toml:"license"`
	// Kind names the adapter that consumes this. Only yara-rules today.
	Kind string `toml:"kind"`

	URL    string `toml:"url"`
	SHA256 string `toml:"sha256"`

	Weight     float64 `toml:"weight"`
	Confidence string  `toml:"confidence"`
	Summary    string  `toml:"summary"`
}

// maxCommunityWeight caps what a submitted ruleset may claim.
//
// The consensus is weighted so that no single engine can quarantine a file alone. A
// community ruleset reaching the `confirmed` threshold by itself could act on somebody's
// site unilaterally, which is the property the whole design exists to prevent — so the
// ceiling is enforced here rather than left to a reviewer's judgement on a busy day.
const maxCommunityWeight = 1.0

var (
	slugPattern   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	commitPattern = regexp.MustCompile(`/[0-9a-f]{40}/`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	movingRefs    = []string{"/master/", "/main/", "/latest/", "/HEAD/", "/trunk/", "/develop/"}
)

// Validate reports everything wrong with an entry, rather than the first thing.
//
// All of it at once because these are reviewed in a pull request: a reviewer who has to
// push five times to discover five problems stops reading carefully by the third.
func (e Entry) Validate() []error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !slugPattern.MatchString(e.Slug) {
		add("slug %q must be lowercase words joined by hyphens: it becomes a directory name "+
			"and a configuration key", e.Slug)
	}
	for _, f := range []struct{ name, val string }{
		{"name", e.Name}, {"homepage", e.Homepage}, {"license", e.License},
		{"summary", e.Summary},
	} {
		if strings.TrimSpace(f.val) == "" {
			add("%s is empty", f.name)
		}
	}
	if e.Kind != "yara-rules" {
		add("kind %q has no adapter. A tool with its own output format needs Go code to "+
			"parse it, which is reviewed as code rather than as a manifest", e.Kind)
	}

	// The two that make approval mean anything.
	for _, moving := range movingRefs {
		if strings.Contains(e.URL, moving) {
			add("url points at %s, which upstream can change after this is reviewed. "+
				"Use a commit SHA or a release asset", strings.Trim(moving, "/"))
		}
	}
	if !commitPattern.MatchString(e.URL) && !strings.Contains(e.URL, "/releases/download/") {
		add("url is not addressed by a commit SHA or a release asset: %s", e.URL)
	}
	if !strings.HasPrefix(e.URL, "https://") {
		add("url must be https: %s", e.URL)
	}
	if !digestPattern.MatchString(e.SHA256) {
		add("sha256 must be 64 lowercase hex characters, got %q. Without it, an immutable "+
			"URL still buys nothing against an intercepted transfer", e.SHA256)
	}

	switch e.Confidence {
	case "signature", "heuristic", "anomaly":
	default:
		add("confidence %q is not one of signature, heuristic, anomaly", e.Confidence)
	}
	if e.Weight <= 0 {
		add("weight must be positive, got %v", e.Weight)
	}
	if e.Weight > maxCommunityWeight {
		add("weight %v is above the ceiling of %v for a submitted ruleset. The consensus "+
			"exists so that no single engine can quarantine a file on its own",
			e.Weight, maxCommunityWeight)
	}
	return errs
}

// All returns every entry, sorted, and fails loudly if any is invalid.
//
// An invalid manifest is a build-time mistake in this repository, not a user's problem —
// so it is surfaced rather than skipped. Skipping one would mean the catalogue silently
// offers less than it appears to, which is the shape of failure this project exists to
// avoid.
func All() ([]Entry, error) {
	files, err := fs.Glob(entries, "entries/*.toml")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var out []Entry
	seen := map[string]string{}
	for _, f := range files {
		b, err := entries.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		var e Entry
		if err := toml.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		if problems := e.Validate(); len(problems) > 0 {
			msgs := make([]string, 0, len(problems))
			for _, p := range problems {
				msgs = append(msgs, "  - "+p.Error())
			}
			return nil, fmt.Errorf("%s is not a valid catalogue entry:\n%s", f, strings.Join(msgs, "\n"))
		}
		if prev, dup := seen[e.Slug]; dup {
			return nil, fmt.Errorf("%s and %s share the slug %q, so one would silently shadow "+
				"the other", prev, f, e.Slug)
		}
		seen[e.Slug] = f
		out = append(out, e)
	}
	return out, nil
}
