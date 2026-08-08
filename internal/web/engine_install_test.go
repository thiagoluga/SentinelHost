package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/adapter"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// installFake is an engine whose install succeeds and whose availability is whatever the
// test says it is afterwards.
type installFake struct {
	slug       string
	installErr error
	after      adapter.ProbeResult
}

func (f *installFake) Info() adapter.Info {
	return adapter.Info{Slug: f.slug, Kind: schema.KindMalware, DefaultWeight: 0.8}
}
func (f *installFake) Probe(context.Context, adapter.Environment) adapter.ProbeResult {
	return f.after
}
func (f *installFake) Install(context.Context, adapter.Environment) error { return f.installErr }
func (f *installFake) UpdateSignatures(context.Context, adapter.Environment) (time.Time, error) {
	return time.Time{}, nil
}
func (f *installFake) Scan(context.Context, adapter.Environment, adapter.ScanRequest) (adapter.RawOutput, error) {
	return adapter.RawOutput{}, nil
}
func (f *installFake) Parse(adapter.RawOutput) (schema.ScanReport, error) {
	return schema.ScanReport{}, nil
}

func serverWith(t *testing.T, a adapter.Adapter) *Server {
	t.Helper()
	reg := adapter.NewRegistry()
	if err := reg.Register(a); err != nil {
		t.Fatalf("registering the fake: %v", err)
	}
	cfg := config.Default()
	cfg.General.DataDir = t.TempDir()
	return &Server{cfg: cfg, registry: reg}
}

func installEngine(t *testing.T, s *Server, slug string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/engines/"+slug+"/install", nil)
	req.SetPathValue("slug", slug)
	rec := httptest.NewRecorder()
	s.handleEngineInstall(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not JSON: %v (%q)", err, rec.Body.String())
	}
	return rec.Code, body
}

// An install that worked, on an engine that still cannot run, must say so.
//
// The two come apart without anything going wrong. Installing php-malware-finder fetches
// its YARA rules; running it needs the `yara` binary, which is a system package no
// unprivileged account can install. So Install returns nil and the engine stays unavailable
// — permanently, on that host.
//
// The handler used to answer {"ok": true} and stop there. The panel showed
// "php-malware-finder installed", the card underneath still said `unavailable` with the same
// button, and reloading changed nothing because nothing had changed. It was reported by
// someone doing exactly that.
//
// This is the project's own failure mode wearing different clothes: reporting the ABSENCE
// OF AN ERROR as a positive result, the same way a scanner that could not run must never
// report zero findings.
func TestAnInstallThatLeavesTheEngineUnusableSaysSo(t *testing.T) {
	const reason = "the `yara` binary was not found on PATH"
	s := serverWith(t, &installFake{
		slug:  "php-malware-finder",
		after: adapter.UnavailableInstallable(reason),
	})

	code, body := installEngine(t, s, "php-malware-finder")

	if code != http.StatusOK {
		t.Fatalf("the install itself worked, so it should not be an error: %d", code)
	}
	if body["available"] != false {
		t.Errorf("available is %v; the engine still cannot run and the panel is about to "+
			"say `unavailable` under a toast that claimed success", body["available"])
	}
	got, _ := body["reason"].(string)
	if !strings.Contains(got, "yara") {
		t.Errorf("reason is %q; it has to carry what the probe said, because that sentence "+
			"is the only actionable thing on the screen", got)
	}
}

// And when it really is usable afterwards, it says that.
//
// Worth its own test: a handler that always reported "still unavailable" would satisfy the
// one above and be just as useless in the other direction.
func TestAnInstallThatWorksReportsAvailable(t *testing.T) {
	s := serverWith(t, &installFake{
		slug:  "amwscan",
		after: adapter.ProbeResult{Available: true, Version: "AMWScan 0.15.1"},
	})

	code, body := installEngine(t, s, "amwscan")

	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if body["available"] != true {
		t.Errorf("available is %v, wanted true", body["available"])
	}
	if body["reason"] != "" {
		t.Errorf("reason is %q; there is nothing to report when the engine runs", body["reason"])
	}
}

// An engine that cannot be installed at all is refused, and the reason travels.
func TestInstallingAnEngineThatCannotBeInstalledIsRefused(t *testing.T) {
	s := serverWith(t, &installFake{
		slug:       "maldet",
		installErr: adapter.ErrNotInstallable,
		after:      adapter.Unavailable("the `maldet` binary was not found"),
	})

	code, _ := installEngine(t, s, "maldet")

	if code != http.StatusBadRequest {
		t.Errorf("status %d, wanted 400 — this engine is a system package and the panel "+
			"should not have offered the button in the first place", code)
	}
}
