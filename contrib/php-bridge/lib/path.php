<?php
/**
 * Path handling for the SentinelHost PHP bridge.
 *
 * This lives in its own file so the test can include it instead of extracting it from
 * index.php by regex and eval(). A security-relevant function pulled out of a file by
 * pattern matching is one refactor away from being tested in a shape it no longer has.
 */

declare(strict_types=1);

/**
 * The path the panel should see.
 *
 * The value arrives from the rewrite in .htaccess, as __shpath, and is already relative
 * to the bridge's directory. It is NOT inferred from SCRIPT_NAME and REQUEST_URI: those
 * two disagree the moment anything upstream rewrites, and on the account this was built
 * against a parent .htaccess did exactly that — nothing was stripped, and the panel
 * answered 404 to every request while looking perfectly healthy.
 *
 * The leading slash is forced, and that is not tidiness — it is the difference between a
 * proxy and a fetcher of whatever a visitor names.
 *
 * The result is concatenated onto "http://127.0.0.1:8787", and the visitor controls it. A
 * request for `/sentinel@evil.com` leaves `@evil.com` after the prefix is stripped, and
 * `http://127.0.0.1:8787@evil.com` is not the loopback at all: everything before the `@`
 * becomes userinfo, and the real host is `evil.com`. The bridge would fetch an attacker's
 * server from inside the account and hand the response back as if it were the panel.
 * Server-side request forgery, in one character.
 *
 * Anchoring to a single `/` closes it: `//evil.com` collapses to `/evil.com`, a path on
 * the loopback and nothing more. Backslashes are folded first, because some parsers treat
 * them as separators.
 */
function upstreamPath(string $path, string $query = ''): string
{
    $path = str_replace('\\', '/', $path);
    $path = '/' . ltrim($path, '/');
    // The query travels separately. Folding it in before anchoring would let a "?" in
    // the path decide where the path ends, which is one more thing the visitor controls.
    if ($query !== '') {
        $path .= '?' . $query;
    }
    return $path;
}

/**
 * Build the upstream URL, and refuse it if it does not point at the upstream.
 *
 * upstreamPath() already anchors the path, so this should never trigger. It exists
 * anyway, because the cost is one call and the thing it prevents is the bridge reaching
 * somewhere it was never meant to reach. A guarantee that can be checked at the point of
 * use should be, rather than left resting on a function three screens away continuing to
 * behave as it does today.
 */
function upstreamURL(string $hostPort, string $path): ?string
{
    // Plain HTTP by design: this address never leaves the machine. Terminating TLS
    // against yourself adds a certificate to manage and protects nothing.
    $url = 'http://' . $hostPort . $path; // NOSONAR - loopback only, verified immediately below
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['host'])) {
        return null;
    }
    [$expectedHost] = explode(':', $hostPort, 2);
    if ($parts['host'] !== $expectedHost || isset($parts['user']) || isset($parts['pass'])) {
        return null;
    }
    return $url;
}
