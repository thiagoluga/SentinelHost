package main

import (
	"fmt"
	"io"

	"github.com/thiagoluga/SentinelHost/internal/catalog"
)

// printCatalogue lists the rulesets embedded in this build.
//
// Embedded, not fetched. A catalogue downloaded at runtime would make whatever serves it
// the thing worth attacking, and "approved" would quietly come to mean "approved unless
// somebody took over that host". This list is part of the release the user verified.
func printCatalogue(w io.Writer) error {
	all, err := catalog.All()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		_, _ = fmt.Fprintln(w, "This build ships no additional rulesets.")
		return nil
	}

	_, _ = fmt.Fprintf(w, "%d ruleset(s) can be installed by this build.\n", len(all))
	_, _ = fmt.Fprintln(w, "They are embedded in the binary: what you can install is what you verified.")

	for _, e := range all {
		_, _ = fmt.Fprintf(w, "\n  %s\n", e.Slug)
		_, _ = fmt.Fprintf(w, "    %s\n", e.Name)
		_, _ = fmt.Fprintf(w, "    %s\n", e.Summary)
		_, _ = fmt.Fprintf(w, "    weight %.2f as %s — below the built-in engines, so it cannot decide a verdict alone\n",
			e.Weight, e.Confidence)
		// The licence is shown rather than filed as metadata. signature-base is CC-BY-NC:
		// a hosting company rolling it across customer accounts would be violating it
		// without ever having been told.
		_, _ = fmt.Fprintf(w, "    licence %s — check it covers your use before installing\n", e.License)
		_, _ = fmt.Fprintf(w, "    %s\n", e.Homepage)
	}

	_, _ = fmt.Fprintln(w, "\nTo propose one: catalog/README.md")
	return nil
}
