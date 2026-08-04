<?php
/**
 * Facts about the incoming request that the bridge has to decide on.
 *
 * In lib/ rather than index.php so it can be tested. index.php starts proxying the moment
 * it is included, so nothing in it can be required from a test — which is why the only
 * bridge test that existed covered lib/path.php and nothing else.
 */

declare(strict_types=1);

/**
 * Is this a browser asking for a page, rather than the panel's own fetch() asking for JSON?
 *
 * It decides what a request gets when the panel is still starting: a navigation gets an
 * HTML page that retries itself, everything else gets a bare 503 with Retry-After. An XHR
 * expecting JSON would treat an HTML body as a parse error, whereas a 503 is a case the
 * caller already handles.
 *
 * Sec-Fetch-Mode is the reliable half: browsers set it on navigations and never on
 * same-origin XHR. Accept is the fallback for clients that do not send it — curl, an old
 * browser, a monitoring probe — and there the worst case is a plain-text 503, which is
 * the safe way to be wrong.
 *
 * @param array<string,mixed> $server normally $_SERVER; injectable so the test does not
 *                                    have to mutate global state
 */
function wantsHTML(array $server): bool
{
    $mode = (string) ($server['HTTP_SEC_FETCH_MODE'] ?? '');
    if ($mode !== '') {
        return $mode === 'navigate';
    }
    $accept = (string) ($server['HTTP_ACCEPT'] ?? '');
    return stripos($accept, 'text/html') !== false;
}
