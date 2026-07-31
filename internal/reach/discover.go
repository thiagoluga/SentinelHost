package reach

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiscoverDocumentRoots finds every directory the web server publishes for this account.
//
// A hosting account is rarely one site. Addon domains, subdomains and parked domains each
// get their own directory, and a webshell in a secondary domain is exactly as executable
// as one in the primary. Asking the user to list them by hand means the list is right on
// the day they wrote it and wrong the first time they add a domain — and nothing would
// say so, because a missing root only makes findings look LESS urgent than they are.
//
// So it is read from the control panel's own records rather than guessed. Two sources,
// in order of trust:
//
//  1. cPanel's ~/.cpanel/userdata/<domain> files, which carry a `documentroot:` line.
//     This is the server's own answer.
//  2. Directories that look like a site — an index.php or index.html near the top of the
//     home. Weaker, and only used to fill gaps the first source left.
//
// Returning nothing is a legitimate answer, and the caller must treat it as "unknown"
// rather than "nothing is served". Location.Reachable() already does.
func DiscoverDocumentRoots(home string) []string {
	found := map[string]bool{}

	for _, d := range fromCPanelUserdata(home) {
		found[d] = true
	}
	for _, d := range fromIndexFiles(home) {
		found[d] = true
	}

	out := make([]string, 0, len(found))
	for d := range found {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// fromCPanelUserdata reads the documentroot each domain is configured with.
//
// The files are one per domain, plus a `main` index and `*.cache` copies that repeat
// them. The cache files are skipped: they can lag behind a change, and a stale root is
// worse than a missing one — it points confidently at the wrong directory.
func fromCPanelUserdata(home string) []string {
	dir := filepath.Join(home, ".cpanel", "userdata")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "main" || strings.HasSuffix(name, ".cache") {
			continue
		}
		if root := documentRootIn(filepath.Join(dir, name)); root != "" {
			out = append(out, root)
		}
	}
	return out
}

// documentRootIn pulls the `documentroot:` value out of one userdata file.
//
// Parsed line by line rather than as YAML: the file is YAML-ish, the value is a plain
// path on a single line, and a parser dependency for one field would be the wrong trade
// in a project that ships as one static binary (Principle VII).
func documentRootIn(path string) string {
	f, err := os.Open(path) // a file inside the account's own home
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, "documentroot:")
		if !ok {
			continue
		}
		root := strings.Trim(strings.TrimSpace(rest), `"'`)
		// Only an existing directory. A domain can be configured and never deployed, and
		// a root that is not there would classify nothing while looking like coverage.
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
		return ""
	}
	return ""
}

// fromIndexFiles looks for directories that behave like a site.
//
// A fallback, for panels whose records this cannot read. It is deliberately shallow —
// three levels — because deeper matches are as likely to be an application's internal
// directory as a document root, and over-reporting here makes files look MORE urgent
// than they are, which is the safe direction but still noise.
func fromIndexFiles(home string) []string {
	var out []string
	seen := map[string]bool{}

	for _, name := range []string{"index.php", "index.html"} {
		for _, depth := range []string{"*", "*/*", "*/*/*"} {
			matches, _ := filepath.Glob(filepath.Join(home, depth, name))
			for _, m := range matches {
				dir := filepath.Dir(m)
				// The account's own directories are not sites, and the trash is not
				// served whatever it contains.
				if seen[dir] || isInternal(home, dir) {
					continue
				}
				seen[dir] = true
				out = append(out, dir)
			}
		}
	}
	return out
}

// internalDirs are the account's own furniture: not sites, whatever they contain.
var internalDirs = []string{
	".trash", ".cpanel", ".softaculous", ".cphorde", ".pki", ".security",
	".subaccounts", ".wp-cli", "mail", "logs", "etc", "ssl", "tmp", "perl5",
	"access-logs", "public_ftp",
}

func isInternal(home, dir string) bool {
	rel, err := filepath.Rel(home, dir)
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
	for _, d := range internalDirs {
		if first == d {
			return true
		}
	}
	return false
}
