<?php
/**
 * The one test that has to exist here.
 *
 * upstreamPath()'s return value is concatenated onto "http://127.0.0.1:8787", and the
 * visitor controls it. If it can begin with anything other than a single "/", the bridge
 * stops being a proxy to the loopback and becomes a fetcher of whatever the visitor
 * names — server-side request forgery, from inside the account, with the response handed
 * back as if it were the panel.
 *
 * Run:  php contrib/php-bridge/tests/upstream-path-test.php
 */

declare(strict_types=1);

// Load only the function, not the request handling below it in the file.
$src = file_get_contents(__DIR__ . '/../index.php');
preg_match('/function upstreamPath\(\): string\s*\{.*?\n\}/s', $src, $m)
    || exit("could not find upstreamPath() in index.php\n");
eval($m[0]);

$cases = [
    // description                        REQUEST_URI                    SCRIPT_NAME
    ['a normal page',                     '/sentinel/',                  '/sentinel/index.php'],
    ['a panel route',                     '/sentinel/api/status',        '/sentinel/index.php'],
    ['a query string is kept',            '/sentinel/api/status?a=1',    '/sentinel/index.php'],
    ['the bare prefix',                   '/sentinel',                   '/sentinel/index.php'],
    // The attacks. Each of these, unanchored, changes the host curl connects to.
    ['userinfo injection',                '/sentinel@evil.com',          '/sentinel/index.php'],
    ['userinfo with a path',              '/sentinel@evil.com/x',        '/sentinel/index.php'],
    ['protocol-relative',                 '/sentinel//evil.com/x',       '/sentinel/index.php'],
    ['backslash separator',               '/sentinel\\evil.com/x',     '/sentinel/index.php'],
    ['many slashes',                      '/sentinel/////evil.com',      '/sentinel/index.php'],
];

$failed = 0;
foreach ($cases as [$what, $uri, $script]) {
    $_SERVER['REQUEST_URI'] = $uri;
    $_SERVER['SCRIPT_NAME'] = $script;
    $path = upstreamPath();
    $url  = 'http://127.0.0.1:8787' . $path;

    // The question is not what the path looks like. It is what host curl would dial.
    $host = parse_url($url, PHP_URL_HOST);
    $ok   = ($host === '127.0.0.1') && str_starts_with($path, '/') && !str_starts_with($path, '//');

    printf("%-22s %-26s -> %-24s host=%-12s %s\n",
        $what, $uri, $path, (string) $host, $ok ? 'ok' : 'FAILED');
    if (!$ok) {
        $failed++;
    }
}

echo $failed === 0
    ? "\nall cases stay on the loopback\n"
    : "\n$failed case(s) would leave the loopback\n";
exit($failed === 0 ? 0 : 1);
