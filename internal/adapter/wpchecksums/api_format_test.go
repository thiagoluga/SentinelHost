package wpchecksums

import "testing"

// The REAL response from downloads.wordpress.org/plugin-checksums, captured from
// classic-editor 1.6.7 inside the validation container.
//
// This test exists because the adapter's first version declared the hashes as
// arrays and passed its tests — which used arrays. Against the real API,
// Unmarshal failed and EVERY plugin was skipped as "unreadable response": zero
// findings, no visible error. It is the failure mode this project fears most, and
// the only defence is pinning the real format in a fixture.
const realPluginChecksumsResponse = `{
  "plugin": "classic-editor",
  "version": "1.6.7",
  "source": "https://plugins.svn.wordpress.org/classic-editor/tags/1.6.7/",
  "zip": "https://downloads.wordpress.org/plugin/classic-editor.1.6.7.zip",
  "files": {
    "LICENSE.md": {
      "md5": "1e105fba976f011ed8d6ded846aeb98e",
      "sha256": "8917d53bcf385c095f5a10db31ab1b22d4c9e3d62db39a88957d747bf2303c43"
    },
    "classic-editor.php": {
      "md5": "d1ee02e06095fdbfe683e010ef078a41",
      "sha256": "1a8198e278ad1e820d93ccfe49defca612a9efe9a7d9ffd03e289410d85a6635"
    },
    "js/block-editor-plugin.js": {
      "md5": "66f7a0eac8f7520dd41e7232ea48c935",
      "sha256": "7398a516595b5dfbd9f8e09e22521caf7f3fa470edf86acd0e8a80e07453cfa9"
    }
  }
}`

func TestParsePluginChecksumsAcceptsTheRealAPIFormat(t *testing.T) {
	resp, err := parsePluginChecksums([]byte(realPluginChecksumsResponse))
	if err != nil {
		t.Fatalf("the REAL API response was rejected: %v", err)
	}
	if resp.Plugin != "classic-editor" || resp.Version != "1.6.7" {
		t.Errorf("metadata: %+v", resp)
	}
	if len(resp.Files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(resp.Files))
	}

	f := resp.Files["classic-editor.php"]
	if !f.hasHash() {
		t.Fatal("the main file came back with no hash")
	}
	if !f.matches("d1ee02e06095fdbfe683e010ef078a41", "does-not-matter") {
		t.Error("the real MD5 should have matched")
	}
	if !f.matches("does-not-matter", "1a8198e278ad1e820d93ccfe49defca612a9efe9a7d9ffd03e289410d85a6635") {
		t.Error("the real SHA-256 should have matched")
	}
	if f.matches("other", "other") {
		t.Error("a different hash must not match")
	}
}

func TestParsePluginChecksumsAcceptsAnArrayOfVariants(t *testing.T) {
	// The other format the API uses: an array when the file has accepted variants
	// (CRLF and LF give different hashes for the same logical content). Matching
	// ANY one of them is enough.
	input := `{
	  "plugin": "x", "version": "1.0",
	  "files": {
	    "readme.txt": {
	      "md5": ["aaa", "bbb"],
	      "sha256": ["ccc", "ddd"]
	    }
	  }
	}`
	resp, err := parsePluginChecksums([]byte(input))
	if err != nil {
		t.Fatalf("the array of variants was rejected: %v", err)
	}
	f := resp.Files["readme.txt"]
	if !f.matches("bbb", "x") {
		t.Error("the second md5 variant should have matched")
	}
	if !f.matches("x", "ddd") {
		t.Error("the second sha256 variant should have matched")
	}
	if f.matches("zzz", "zzz") {
		t.Error("a hash outside the variants must not match")
	}
}

func TestParsePluginChecksumsMixesBothFormats(t *testing.T) {
	// Nothing guarantees the API uses the same format for every file of a single
	// response.
	input := `{
	  "plugin": "x", "version": "1.0",
	  "files": {
	    "a.php": {"md5": "one", "sha256": "two"},
	    "b.php": {"md5": ["three"], "sha256": ["four", "five"]}
	  }
	}`
	resp, err := parsePluginChecksums([]byte(input))
	if err != nil {
		t.Fatalf("the mixture of formats was rejected: %v", err)
	}
	if !resp.Files["a.php"].matches("one", "") {
		t.Error("the scalar format did not work")
	}
	if !resp.Files["b.php"].matches("", "five") {
		t.Error("the array format did not work")
	}
}

func TestAFileWithNoHashDoesNotBecomeAFinding(t *testing.T) {
	// An entry with no hash at all cannot become an "altered" finding: there is
	// nothing to compare against, and inventing a divergence out of missing data is
	// the same mistake as declaring clean what nobody checked, in the opposite
	// direction.
	input := `{
	  "plugin": "x", "version": "1.0",
	  "files": {"empty.php": {}, "null.php": {"md5": null, "sha256": null}}
	}`
	resp, err := parsePluginChecksums([]byte(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for name, f := range resp.Files {
		if f.hasHash() {
			t.Errorf("%s should be reported as having no hash", name)
		}
		if f.matches("any", "thing") {
			t.Errorf("%s must not match anything", name)
		}
	}
}

func TestAnUnexpectedFormatIsAnErrorRatherThanSilence(t *testing.T) {
	// A number where a hash should be is a sign the API changed. Failing loudly
	// makes the plugin show up as unverified; ignoring it would make it look clean.
	input := `{"plugin":"x","version":"1.0","files":{"a.php":{"md5":123}}}`
	if _, err := parsePluginChecksums([]byte(input)); err == nil {
		t.Fatal("an unexpected format should be an error")
	}
}

func TestAResponseWithNoFilesAbstains(t *testing.T) {
	if _, err := parsePluginChecksums([]byte(`{"plugin":"x","version":"1.0","files":{}}`)); err == nil {
		t.Fatal("a response with no files should become an abstention")
	}
}
