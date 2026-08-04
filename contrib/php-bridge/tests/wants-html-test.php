<?php
/**
 * What a request gets while the panel is starting.
 *
 * The bridge used to hold a PHP worker for up to 8 seconds waiting for a cold start. A
 * cPanel account has a small ceiling on concurrent PHP processes, the panel is reaped
 * whenever it goes idle, and a page view fires more than one request — so a handful of
 * those held workers exhausts the pool and the SERVER starts refusing requests before PHP
 * runs at all. That is the "Service Unavailable" page with "an ErrorDocument" in it.
 *
 * The fix hands the waiting back to the client, which only works if the right client gets
 * the right body: a navigation can be given HTML that reloads itself, but the panel's own
 * fetch() would treat HTML as a parse error where a bare 503 is a case it handles.
 *
 * Run:  php contrib/php-bridge/tests/wants-html-test.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../lib/request.php';

$cases = [
    // Sec-Fetch-Mode decides whenever it is present: browsers send it on every request
    // and it is the only one of the two the page cannot lie about casually.
    'a browser opening the panel' => [
        ['HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_ACCEPT' => 'text/html,*/*'], true,
    ],
    'the panel\'s own fetch(), which asks for JSON' => [
        ['HTTP_SEC_FETCH_MODE' => 'cors', 'HTTP_ACCEPT' => 'application/json'], false,
    ],
    // The dangerous one: an XHR whose Accept still mentions text/html. Trusting Accept
    // alone would hand a JSON caller an HTML body.
    'an XHR with a broad Accept header' => [
        ['HTTP_SEC_FETCH_MODE' => 'cors', 'HTTP_ACCEPT' => 'text/html,application/json'], false,
    ],
    'a same-origin subresource' => [
        ['HTTP_SEC_FETCH_MODE' => 'no-cors', 'HTTP_ACCEPT' => 'text/html'], false,
    ],

    // No Sec-Fetch-Mode: curl, an old browser, a monitoring probe. Accept decides, and
    // being wrong here costs a plain-text 503, which is the safe direction.
    'curl, which sends neither' => [[], false],
    'curl asking for html' => [['HTTP_ACCEPT' => 'text/html'], true],
    'an old browser' => [['HTTP_ACCEPT' => 'text/html,application/xhtml+xml,*/*;q=0.8'], true],
    'a probe asking for json' => [['HTTP_ACCEPT' => 'application/json'], false],
    'an empty Accept' => [['HTTP_ACCEPT' => ''], false],
];

$failed = 0;
foreach ($cases as $description => [$server, $expected]) {
    $got = wantsHTML($server);
    if ($got !== $expected) {
        $failed++;
        printf("FAIL  %s\n      wanted %s, got %s\n",
            $description,
            $expected ? 'the self-retrying page' : 'a bare 503',
            $got ? 'the self-retrying page' : 'a bare 503');
    }
}

if ($failed > 0) {
    printf("\n%d of %d cases failed\n", $failed, count($cases));
    exit(1);
}
printf("ok — %d cases\n", count($cases));
