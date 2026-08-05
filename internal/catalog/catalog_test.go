package catalog_test

import (
	"strings"
	"testing"

	"github.com/thiagoluga/SentinelHost/internal/catalog"
)

// Every shipped entry is valid, and an invalid one is a build-time mistake here rather
// than something a user discovers.
func TestEveryShippedEntryIsValid(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("the catalogue does not load: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("the catalogue is empty, so this test would pass whatever was wrong with it")
	}
	for _, e := range all {
		if problems := e.Validate(); len(problems) > 0 {
			t.Errorf("%s: %v", e.Slug, problems)
		}
	}
}

// The two properties that make approval mean anything. A reviewer approves specific bytes;
// a moving URL means users run something else afterwards.
func TestNoEntryCanBeChangedAfterItIsApproved(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		for _, moving := range []string{"/master/", "/main/", "/latest/", "/HEAD/"} {
			if strings.Contains(e.URL, moving) {
				t.Errorf("%s is fetched from %s: upstream can change it after review",
					e.Slug, strings.Trim(moving, "/"))
			}
		}
		if len(e.SHA256) != 64 {
			t.Errorf("%s has no digest, so an immutable URL still buys nothing against an "+
				"intercepted transfer", e.Slug)
		}
	}
}

// A submitted ruleset must not be able to act on somebody's site by itself. The consensus
// is weighted precisely so that no single engine decides a quarantine alone.
func TestNoSubmittedRulesetCanDecideAVerdictAlone(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.Weight > 1.0 {
			t.Errorf("%s claims weight %v, enough to reach a verdict without agreement",
				e.Slug, e.Weight)
		}
	}
}

// The validator has to reject, not merely describe. These are the submissions a reviewer
// would otherwise have to catch by hand, every time, forever.
func TestTheValidatorRejectsWhatAReviewerWouldMiss(t *testing.T) {
	good := catalog.Entry{
		Slug: "example-rules", Name: "Example", Homepage: "https://example.test",
		License: "MIT", Kind: "yara-rules", Summary: "Example rules.",
		URL:    "https://raw.githubusercontent.com/o/r/" + strings.Repeat("a", 40) + "/x.yar",
		SHA256: strings.Repeat("b", 64), Weight: 0.5, Confidence: "heuristic",
	}
	if problems := good.Validate(); len(problems) > 0 {
		t.Fatalf("a well-formed entry was rejected: %v", problems)
	}

	cases := []struct {
		what   string
		mutate func(*catalog.Entry)
		expect string
	}{
		{"a branch URL", func(e *catalog.Entry) {
			e.URL = "https://raw.githubusercontent.com/o/r/master/x.yar"
		}, "upstream can change"},
		{"no digest", func(e *catalog.Entry) { e.SHA256 = "" }, "64 lowercase hex"},
		{"a weight that decides alone", func(e *catalog.Entry) { e.Weight = 2 }, "ceiling"},
		{"plain http", func(e *catalog.Entry) {
			e.URL = "http://raw.githubusercontent.com/o/r/" + strings.Repeat("a", 40) + "/x.yar"
		}, "must be https"},
		{"an unknown kind", func(e *catalog.Entry) { e.Kind = "custom-binary" }, "no adapter"},
		{"a missing licence", func(e *catalog.Entry) { e.License = "" }, "license is empty"},
		{"an invented confidence", func(e *catalog.Entry) { e.Confidence = "certain" }, "not one of"},
	}

	for _, c := range cases {
		e := good
		c.mutate(&e)
		problems := e.Validate()
		if len(problems) == 0 {
			t.Errorf("%s was accepted", c.what)
			continue
		}
		var found bool
		for _, p := range problems {
			if strings.Contains(p.Error(), c.expect) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was rejected, but not for the stated reason (%q): %v",
				c.what, c.expect, problems)
		}
	}
}

// Every problem at once. A reviewer who has to push five times to find five mistakes stops
// reading carefully by the third.
func TestValidationReportsEverythingNotJustTheFirstThing(t *testing.T) {
	bad := catalog.Entry{Slug: "Bad Slug", Kind: "nope", URL: "http://x/master/y", SHA256: "z"}
	if n := len(bad.Validate()); n < 5 {
		t.Errorf("an entry wrong in many ways produced %d problems", n)
	}
}
