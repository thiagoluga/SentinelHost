package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/selfupdate"
)

// maxBinaryBytes caps the download. The binary is ~12 MB; 64 MiB is generous and stops a
// hostile Content-Length from filling an account's disk quota.
const maxBinaryBytes = 64 << 20

// cmdUpdate replaces this binary with a newer, signed release.
//
// Never on a schedule, and never as a side effect of anything else. A security tool that
// replaces itself unattended on shared hosting behaves exactly the way the things it hunts
// behave, and the user has no way to tell the difference from the outside. `--check` is
// what belongs in cron: it reports and does nothing.
func cmdUpdate(ctx context.Context, args []string) error {
	fs, _ := flagSet("update")
	check := fs.Bool("check", false, "report whether a newer release exists and exit")
	rollback := fs.Bool("rollback", false, "put the previous binary back")
	yes := fs.Bool("yes", false, "install without the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding the running binary: %w", err)
	}

	if *rollback {
		return rollBack(self)
	}

	rel, err := latestRelease(ctx)
	if err != nil {
		return err
	}

	newer, err := selfupdate.IsNewer(version, rel.Version)
	if err != nil {
		// A development build, or a version this cannot read. Say so plainly rather than
		// offering an upgrade path that would discard what the person is running.
		fmt.Printf("Running %s. The latest release is %s.\n", version, rel.Version)
		return fmt.Errorf("not updating automatically: %w", err)
	}
	if !newer {
		fmt.Printf("Running %s, which is current (latest release: %s).\n", version, rel.Version)
		return nil
	}

	fmt.Printf("A newer release is available: %s (running %s).\n", rel.Version, version)
	if *check {
		// Exit 0 either way: "there is an update" is not a failure, and a cron line that
		// reported one as an error would train the user to ignore the mail.
		fmt.Printf("  %s\n  Install it with: sentinelhost update\n", rel.URL)
		return nil
	}

	if !*yes {
		// The binary guards the account. Replacing it is the user's decision, and asking
		// costs one keystroke.
		fmt.Print("Replace the running binary? Its predecessor is kept for rollback. [y/N] ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			return fmt.Errorf("cancelled")
		}
	}

	payload, err := download(ctx, rel.URL)
	if err != nil {
		return err
	}
	fmt.Printf("Downloaded %d bytes, sha256 %s\n", len(payload), selfupdate.Digest(payload))

	// The signature is fetched separately and is small; a failure here refuses the install
	// rather than falling back to installing unverified bytes.
	sigBytes, err := download(ctx, rel.Signature)
	if err != nil {
		return fmt.Errorf("fetching the signature: %w", err)
	}

	prev, err := selfupdate.Install(payload, string(sigBytes), self)
	if err != nil {
		// The install refuses rather than repairs. Everything that reaches here left the
		// existing binary untouched.
		return err
	}

	fmt.Printf("Installed %s.\nThe previous binary is at %s — restore it with: "+
		"sentinelhost update --rollback\n", rel.Version, prev)
	return nil
}

func rollBack(self string) error {
	prev := self + ".prev"
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("there is no previous binary at %s to go back to", prev)
	}
	// Swap rather than overwrite, so a rollback is itself reversible: somebody who rolls
	// back by mistake has not destroyed the version they were on.
	tmp := self + ".rollback-tmp"
	if err := os.Rename(self, tmp); err != nil {
		return fmt.Errorf("setting the current binary aside: %w", err)
	}
	if err := os.Rename(prev, self); err != nil {
		_ = os.Rename(tmp, self)
		return fmt.Errorf("restoring the previous binary: %w", err)
	}
	if err := os.Rename(tmp, prev); err != nil {
		return fmt.Errorf("the rollback worked, but the replaced binary is left at %s: %w", tmp, err)
	}
	fmt.Printf("Rolled back. Run `sentinelhost version` to confirm what is now in place.\n")
	return nil
}

// latestRelease asks GitHub what the newest release is.
//
// The response chooses nothing that matters: the asset is named from THIS process
// (selfupdate.AssetName), and the payload is verified against the compiled-in key. A
// hostile answer can waste a download and nothing else.
func latestRelease(ctx context.Context) (selfupdate.Release, error) {
	var rel selfupdate.Release

	const api = "https://api.github.com/repos/thiagoluga/SentinelHost/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SentinelHost/"+version)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return rel, fmt.Errorf("asking for the latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return rel, fmt.Errorf("there are no published releases yet")
	}
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("the release API answered %s", resp.Status)
	}

	var body struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
		HTMLURL string `json:"html_url"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	raw, err := selfupdate.ReadAll(resp.Body, 1<<20)
	if err != nil {
		return rel, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return rel, fmt.Errorf("reading the release listing: %w", err)
	}

	want := selfupdate.AssetName()
	rel.Version = body.TagName
	rel.Notes = body.Body
	rel.NotesURL = body.HTMLURL
	for _, a := range body.Assets {
		switch a.Name {
		case want:
			rel.URL = a.URL
		case want + ".sig":
			// Fetched below. Kept as a URL here so the signature travels with the asset
			// it signs rather than being looked up separately later.
			rel.Signature = a.URL
		}
	}
	if rel.URL == "" {
		return rel, fmt.Errorf("release %s has no asset named %s, so there is nothing to "+
			"install for this platform", rel.Version, want)
	}
	if rel.Signature == "" {
		return rel, fmt.Errorf("%w: release %s ships %s without %s.sig",
			selfupdate.ErrUnsigned, rel.Version, want, want)
	}
	return rel, nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SentinelHost/"+version)
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the download of %s answered %s", url, resp.Status)
	}
	return selfupdate.ReadAll(resp.Body, maxBinaryBytes)
}

// panelUpdates lets the web panel check and install releases.
//
// The same code path as the CLI, deliberately: two ways to replace the binary would be two
// places for the verification to drift apart, and one of them would be the one nobody
// exercises.
type panelUpdates struct {
	ctx  context.Context
	self string
}

func newPanelUpdates(ctx context.Context) (*panelUpdates, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &panelUpdates{ctx: ctx, self: self}, nil
}

func (p *panelUpdates) RunningVersion() string { return version }

func (p *panelUpdates) Latest() (selfupdate.Release, error) { return latestRelease(p.ctx) }

func (p *panelUpdates) Apply(rel selfupdate.Release) (string, error) {
	payload, err := download(p.ctx, rel.URL)
	if err != nil {
		return "", err
	}
	sig, err := download(p.ctx, rel.Signature)
	if err != nil {
		return "", fmt.Errorf("fetching the signature: %w", err)
	}
	return selfupdate.Install(payload, string(sig), p.self)
}
