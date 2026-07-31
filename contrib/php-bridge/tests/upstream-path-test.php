<?php
/**
 * The one test that has to exist here.
 *
 * upstreamPath()'s result is concatenated onto "http://127.0.0.1:8787", and the visitor
 * controls it. If it can begin with anything other than a single "/", the bridge stops
 * being a proxy to the loopback and becomes a fetcher of whatever the visitor names —
 * server-side request forgery, from inside the account, with the response handed back as
 * if it were the panel.
 *
 * What is asserted is not the shape of the string. It is the host a client would dial
 * once the URL is assembled, because that is the thing that actually goes wrong.
 *
 * Run:  php contrib/php-bridge/tests/upstream-path-test.php
 */

declare(strict_types=1);

require __DIR__ . '/../lib/path.php';

const SCRIPT   = '/sentinel/index.php';
const UPSTREAM = '127.0.0.1:8787';

/** description => request URI. Every one of these must end up on the loopback. */
$cases = [
    'a normal page'        => '/sentinel/',
    'a panel route'        => '/sentinel/api/status',
    'a query string'       => '/sentinel/api/status?a=1',
    'the bare prefix'      => '/sentinel',
    'a dot segment'        => '/sentinel/../etc/passwd',
    // The attacks. Unanchored, each of these changes the host that gets dialled.
    'userinfo injection'   => '/sentinel@evil.com',
    'userinfo with a path' => '/sentinel@evil.com/x',
    'protocol-relative'    => '/sentinel//evil.com/x',
    'backslash separator'  => '/sentinel\\evil.com/x',
    'many slashes'         => '/sentinel/////evil.com',
];

$failed = 0;
foreach ($cases as $what => $uri) {
    $url  = upstreamURL(UPSTREAM, upstreamPath($uri, SCRIPT));
    $host = $url === null ? null : parse_url($url, PHP_URL_HOST);
    $ok   = $url !== null && $host === '127.0.0.1';

    // Only fixed labels and the derived host are printed — never the input. The URIs come
    // from the table above rather than from a live request, but keeping the output to
    // known values means this can never become a reflection of anything.
    printf("%-22s host=%-12s %s\n", $what, $host ?? '(refused)', $ok ? 'ok' : 'FAILED');
    if (!$ok) {
        $failed++;
    }
}

// And the guard itself: a path that somehow moved the host must be refused outright,
// rather than quietly dialling it.
foreach (['@evil.com', '//evil.com', 'evil.com'] as $hostile) {
    if (upstreamURL(UPSTREAM, $hostile) !== null) {
        echo "FAILED: upstreamURL accepted a path that leaves the loopback\n";
        $failed++;
    }
}

echo $failed === 0
    ? "\nevery case stays on the loopback\n"
    : "\n$failed case(s) would leave the loopback\n";

exit($failed === 0 ? 0 : 1);
