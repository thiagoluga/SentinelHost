<?php
/**
 * SentinelHost PHP bridge — the panel, available whenever you open the URL.
 *
 * Shared hosting kills long-running user processes. On the account this was built
 * against, `sentinelhost serve` survived fourteen minutes. So a panel that depends on a
 * process staying up cannot work there, and an SSH tunnel is out too when the provider
 * has disabled the shell.
 *
 * WordPress does not have that problem, and the reason is worth being precise about: it
 * is not that WordPress is more robust, it is that WordPress never runs continuously
 * either. The web server is what stays up, and the web server belongs to the host. PHP is
 * started per request, answers, and exits.
 *
 * This file gives the panel that same shape. On every request it:
 *
 *   1. checks whether the panel is answering on the loopback;
 *   2. starts it if it is not, holding a lock so two simultaneous requests cannot
 *      race two processes onto the same SQLite;
 *   3. proxies the request to it and returns the response.
 *
 * Nothing has to survive between requests. The panel dying is not a failure any more —
 * it is just something the next visit fixes.
 *
 * SECURITY — read contrib/php-bridge/README.md before installing this. In short: this
 * file puts an administrative panel on a public URL. The binary must stay OUTSIDE the
 * document root, and the accompanying .htaccess should restrict by IP. The panel's own
 * password is real protection, not decoration, but it should not be the only layer.
 */

declare(strict_types=1);

require_once __DIR__ . '/lib/path.php';
require_once __DIR__ . '/lib/request.php';
require_once __DIR__ . '/lib/panel.php';

// Every failure path here answers in plain text: an HTML error page from a security
// tool invites the reader to wonder what else is being rendered.
const PLAIN = 'Content-Type: text/plain';

// --- configuration ----------------------------------------------------------------
//
// SET THIS to your account's home directory. It is spelled out rather than computed on
// purpose: a `dirname(__DIR__, 3)` depends on how deep you happened to install the
// bridge, and installing it one level in or out silently points everything at the wrong
// place. On a real account that produced /home/user/public_html instead of /home/user,
// and the failure looked like the panel being broken rather than like a path being wrong.
//
// `php -r 'echo getenv("HOME");'` prints it, and cPanel shows it as "Home Directory".
$home     = '/home/YOURUSER';
$binary   = $home . '/sentinelhost/bin/sentinelhost';
$config   = $home . '/sentinelhost/config.toml';
$lockFile = $home . '/sentinelhost/.bridge.lock';
$logFile  = $home . '/sentinelhost/panel.log';
// Where the panel records its own process id, so a wedged one can be identified and
// cleared. The bridge passes this path to `serve`, so the two cannot drift apart: there is
// one place it is configured and it is this line.
$pidFile  = $home . '/sentinelhost/.panel.pid';
$upstream = '127.0.0.1:8787';                    // must match web.listen in the TOML
// How long a request may hold a PHP worker waiting for a cold start.
//
// This was 8 seconds, and that is what produced the web server's own "Service
// Unavailable" page — the one that also says "a 503 was encountered while trying to use
// an ErrorDocument", which means PHP never ran at all.
//
// A cPanel account has a small ceiling on concurrent PHP processes, and the panel is a
// long-running daemon that shared hosting reaps whenever it goes idle, so cold starts are
// routine rather than rare.
//
// This was first justified by saying each request arriving during a cold start held a
// worker for the full 8 seconds. Measured afterwards on the real account, a cold start
// takes 0.113s, so that is not what was happening and the cause of the 503 that prompted
// this is still unknown (D-049).
//
// The smaller claim survives and is the reason to keep this: when the panel CANNOT start,
// every request held a worker for the full ceiling, and a browser was given a connection
// held open until the web server killed it rather than an answer. Waiting 1.5s covers the
// 0.113s case with room to spare, and anything slower is handed back to the client.
//
// So: wait only long enough to cover the case where the panel answers almost at once, and
// otherwise hand the wait back to the client. A browser gets a page that retries itself,
// an API caller gets 503 with Retry-After. Both free the worker immediately.
$bootWait = 1.5;
$traceLog = $home . '/sentinelhost/bridge.log';  // one line per request; '' turns it off
// -----------------------------------------------------------------------------------

/**
 * One line per request, with where the time went.
 *
 * This exists because the bridge stopped answering — no error page, no response at all,
 * a browser waiting 300 seconds — while the panel itself was up, healthy, and the only
 * process of its kind on the account. Every hypothesis about why was a guess, and the
 * first one was wrong.
 *
 * A proxy that can hang has exactly three places to hang in: the liveness probe, the
 * start, and the upstream request. Timing all three turns the next occurrence from a
 * mystery into a line of text.
 *
 * It writes outside the document root, and the .htaccess denies *.log regardless.
 */
function trace(string $file, string $line): void
{
    if ($file === '') {
        return;
    }
    // Truncate rather than rotate: this is a debugging aid on an account with a disk
    // quota, and a log that outgrows the site it is meant to protect helps nobody.
    if (@filesize($file) > 512 * 1024) {
        @file_put_contents($file, "(truncated)\n");
    }
    @file_put_contents($file, gmdate('c') . ' ' . $line . "\n", FILE_APPEND);
}

/**
 * The last thing the panel said before giving up.
 *
 * The 503 page used to say "check panel.log", which is advice the reader cannot follow:
 * this bridge exists precisely because the account has no shell. So the log is read here
 * and the reason is put on the page.
 *
 * It happened on a real account. An invalid config meant every start died reading it, and
 * every visit started another one — 54 attempts, all identical, with nothing on screen but
 * a page that reloaded itself forever. The reason was one line in a file the owner had no
 * way to open.
 *
 * Only the tail, and only lines that look like a failure: the log is mostly startup
 * banners, and showing those would bury the one line that matters.
 */
function lastPanelError(string $logFile): string
{
    if ($logFile === '' || !is_readable($logFile)) {
        return '';
    }
    $size = @filesize($logFile);
    if ($size === false) {
        return '';
    }
    $fh = @fopen($logFile, 'rb');
    if ($fh === false) {
        return '';
    }
    // 8 KiB is many failures' worth; reading the whole file would be unbounded.
    $from = max(0, $size - 8192);
    fseek($fh, $from);
    $tail = (string) fread($fh, 8192);
    fclose($fh);

    $lines = preg_split('/\r?\n/', trim($tail)) ?: [];
    for ($i = count($lines) - 1; $i >= 0; $i--) {
        $line = trim($lines[$i]);
        if ($line === '') {
            continue;
        }
        // Anything that is not the ordinary startup chatter is worth showing.
        if (stripos($line, 'panel at') !== false || stripos($line, 'Ctrl-C') !== false) {
            continue;
        }
        // A long line is truncated rather than allowed to fill the page.
        return mb_strimwidth($line, 0, 300, '…');
    }
    return '';
}

/** Is the panel answering right now? See lib/panel.php for why this is not a TCP connect. */
function panelIsUp(string $hostPort, float $timeout = 1.5): bool
{
    return panelHealth($hostPort, $timeout) === PANEL_ANSWERING;
}

/**
 * Clear a process that holds the panel's port without answering on it.
 *
 * Nothing else can fix this. The port is taken, so every start dies with "address already in
 * use"; the process will not recover, because a wedged one does not; and the account has no
 * shell, which is the whole reason this bridge exists. Left alone it stays down forever while
 * each visit hangs for a minute.
 *
 * Two rules make killing safe enough to do without asking:
 *
 *   - Only a pid this account's own binary owns, proved through /proc, is ever signalled.
 *     ownedPanelPID() returns 0 for every doubt and 0 is never signalled. If some OTHER
 *     program of the account's has taken the port, this refuses and the 503 says so, which
 *     is a fact the owner can act on.
 *   - TERM first, KILL only if the port is still occupied afterwards. A panel that is merely
 *     slow shuts down cleanly and finishes what it was doing; only one that cannot respond
 *     to a signal gets the hard one.
 *
 * Returns the reason it could not, or '' on success.
 */
function clearStuckPanel(string $upstream, string $pidFile, string $binary): string
{
    $pid = ownedPanelPID($pidFile, $binary);
    if ($pid === 0) {
        // Requests arrive together, and a moment ago one of them may have cleared this and
        // taken the pid file with it. Reporting a blocked port to everyone who lost that
        // race would be wrong: the port is no longer blocked. So the state is re-read rather
        // than inferred from a pid file that has already served its purpose.
        if (panelHealth($upstream, 0.5) !== PANEL_SILENT) {
            return '';
        }
        return 'something is holding ' . $upstream . ' without answering, and it could not be '
            . 'identified as this account\'s panel — nothing was killed';
    }

    // 15 = TERM, 9 = KILL. The numbers rather than the constants, which live in ext-posix
    // and this host may not have it.
    if (!signalPanel($pid, 15)) {
        return 'process ' . $pid . ' is holding ' . $upstream . ' without answering, and this '
            . 'PHP cannot signal it (neither posix_kill nor exec is available)';
    }

    // Up to two seconds for it to go. Longer would hold a PHP worker for a case that is
    // already a fault; shorter would send KILL to something on its way out cleanly.
    $deadline = microtime(true) + 2.0;
    while (microtime(true) < $deadline) {
        usleep(150000);
        if (panelHealth($upstream, 0.3) === PANEL_DOWN) {
            return '';
        }
    }

    signalPanel($pid, 9);
    usleep(300000);
    if (panelHealth($upstream, 0.3) !== PANEL_DOWN) {
        return 'process ' . $pid . ' survived both TERM and KILL and still holds ' . $upstream;
    }
    return '';
}

/**
 * Start the panel, once.
 *
 * The lock is the point. Two requests arriving together would otherwise both find the
 * panel down and both start one: two processes against one SQLite database and one
 * quarantine vault, which is not a state worth debugging on someone else's server. The
 * second request waits for the first one's process instead.
 *
 * A non-blocking acquire, deliberately: a request that cannot get the lock does not sit
 * there holding a PHP worker open, it just waits for the panel the other request is
 * already starting.
 */
function startPanel(string $binary, string $config, string $lockFile, string $logFile, string $pidFile, string $upstream, float $wait): bool
{
    $lock = is_executable($binary) ? @fopen($lockFile, 'c') : false;
    if ($lock === false) {
        // Either there is no binary to start or no lock to take. Both mean the same
        // thing to the caller: the panel is not going to come up by itself.
        return false;
    }

    $deadline = microtime(true) + $wait;

    // Between finding the panel down and taking the lock, another request may have
    // finished starting it, so the check is repeated inside the lock rather than trusted
    // from before it.
    if (flock($lock, LOCK_EX | LOCK_NB)) {
        if (!panelIsUp($upstream)) {
            // --pidfile so the process can be identified later. A panel that wedges keeps
            // its listening socket, and without a verifiable pid there is nothing on this
            // account able to clear it.
            $cmd = sprintf(
                'nohup %s serve --config %s --pidfile %s >> %s 2>&1 &',
                escapeshellarg($binary),
                escapeshellarg($config),
                escapeshellarg($pidFile),
                escapeshellarg($logFile)
            );
            // exec() rather than shell_exec(): nothing here wants the output, and the
            // trailing & detaches it so the panel outlives this PHP process.
            @exec($cmd);
        }
        flock($lock, LOCK_UN);
    }
    fclose($lock);

    // Whether we started it or someone else did, wait for it to answer.
    while (microtime(true) < $deadline) {
        if (panelIsUp($upstream)) {
            return true;
        }
        usleep(150000);
    }
    return panelIsUp($upstream);
}

/** Headers to forward upstream, minus the ones that describe THIS connection. */
function forwardedHeaders(): array
{
    // Hop-by-hop headers describe the client-to-PHP connection and mean nothing to the
    // panel. Host is rewritten because the panel is being addressed on the loopback.
    $skip = [
        'host' => true, 'connection' => true, 'keep-alive' => true,
        'transfer-encoding' => true, 'upgrade' => true, 'te' => true,
        'trailer' => true, 'proxy-authorization' => true, 'proxy-authenticate' => true,
        'content-length' => true, 'accept-encoding' => true,
        // The client does not get to say what the scheme was, or who it was.
        //
        // These were forwarded and then the bridge appended its own — so both arrived,
        // the client's first, and Go's Header.Get returns the first. A caller sending
        // `X-Forwarded-Proto: http` to an HTTPS site made the panel drop the Secure flag
        // from its own session cookie. The comment below claims these are "set from what
        // actually happened"; they were being ADDED TO.
        'x-forwarded-proto' => true, 'x-forwarded-for' => true,
        'x-forwarded-host' => true, 'x-forwarded-port' => true,
        'x-real-ip' => true, 'forwarded' => true,
    ];

    $out = [];
    foreach ($_SERVER as $key => $value) {
        if (!str_starts_with($key, 'HTTP_')) {
            continue;
        }
        $name = strtolower(str_replace('_', '-', substr($key, 5)));
        if (isset($skip[$name])) {
            continue;
        }
        $out[] = $name . ': ' . $value;
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $out[] = 'Content-Type: ' . $_SERVER['CONTENT_TYPE'];
    }

    // The panel reads X-Forwarded-Proto to decide whether to mark its session cookie
    // Secure. Getting this wrong in the permissive direction would hand out a cookie
    // that travels in the clear, so it is set from what actually happened, never assumed.
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
    $out[] = 'X-Forwarded-Proto: ' . ($https ? 'https' : 'http');
    $out[] = 'X-Forwarded-For: ' . ($_SERVER['REMOTE_ADDR'] ?? '');

    return $out;
}

// --- the request ------------------------------------------------------------------

if (!extension_loaded('curl')) {
    http_response_code(500);
    header(PLAIN);
    exit("SentinelHost bridge: PHP has no curl extension, so it cannot reach the panel.\n");
}

// An arrival line, written before anything can block.
//
// Every other trace() call here reports what happened, which means a request that never
// finishes is a request that never appears. That absence has cost real time: the panel
// stopped answering from outside, the log showed a healthy sequence of 200s, and the two
// could not be reconciled because the failing requests were exactly the ones missing from
// it. The evidence for this class of failure was the evidence the log could not produce.
//
// Now an unfinished request leaves a `>>>` with no matching outcome, which is a fact
// rather than a silence, and it distinguishes the two possibilities that look identical
// from a browser: no `>>>` at all means the request never reached PHP and the web server
// refused it; a `>>>` with nothing after it means PHP ran and something here hung.
//
// The id ties the two lines together, since requests overlap. getmypid plus a counter
// would be prettier; uniqid needs no state and cannot collide across processes.
$reqID = substr(uniqid('', true), -8);
trace($traceLog, sprintf('>>> %-6s %-28s id=%s',
    $_SERVER['REQUEST_METHOD'] ?? '?',
    substr((string) ($_SERVER['REQUEST_URI'] ?? '/'), 0, 28),
    $reqID));

$t0 = microtime(true);
$health = panelHealth($upstream);
$wasUp = $health === PANEL_ANSWERING;
$tProbe = microtime(true);

// The port accepts and nothing answers on it.
//
// Confirmed with a second, slower probe before acting: one silent reply could be a moment of
// load, and what follows kills a process. Two in a row, on a handler that touches no database
// and takes no lock, is not load.
$stuckReason = '';
if ($health === PANEL_SILENT && panelHealth($upstream, 3.0) === PANEL_SILENT) {
    trace($traceLog, sprintf('!!! %s accepts connections and does not answer; id=%s',
        $upstream, $reqID));
    $stuckReason = clearStuckPanel($upstream, $pidFile, $binary);
    if ($stuckReason !== '') {
        trace($traceLog, sprintf('!!! could not clear %s: %s; id=%s',
            $upstream, $stuckReason, $reqID));
    }
}

$started = $wasUp
    || ($stuckReason === ''
        && startPanel($binary, $config, $lockFile, $logFile, $pidFile, $upstream, $bootWait));
$tStart = microtime(true);

if (!$started) {
    // Two situations wear the same status code, and telling them apart is the difference
    // between "wait a moment" and "go and fix your install".
    $missing = !is_executable($binary);

    http_response_code(503);
    // Two seconds is right for a cold start, which the next visit finishes. It is wrong for
    // a port held by something that will not let go: that does not clear on its own, and a
    // page reloading every two seconds against it is just a faster way of getting nowhere.
    header('Retry-After: ' . ($missing || $stuckReason !== '' ? '30' : '2'));

    if ($missing) {
        $why = "the binary is missing or not executable at {$binary}";
        trace($traceLog, sprintf('503 probe=%.2fs start=%.2fs id=%s %s',
            $tProbe - $t0, $tStart - $tProbe, $reqID, $why));
        header(PLAIN);
        exit("SentinelHost bridge: {$why}.\n");
    }

    $why = $stuckReason !== ''
        ? $stuckReason
        : sprintf('still starting after %.1fs; worker released for the client to retry', $bootWait);

    // What the panel actually complained about, if it complained. This is the difference
    // between a page that says "wait" forever and one that names the cause.
    $panelError = lastPanelError($logFile);
    $panelErrorHTML = '';
    if ($panelError !== '') {
        $why .= ' — last error: ' . $panelError;
        $panelErrorHTML = '<p style="color:#e6a">The panel last reported:</p>'
            . '<pre style="text-align:left;white-space:pre-wrap;word-break:break-word;'
            . 'background:#000;padding:.75rem;border-radius:6px;font-size:.8rem;color:#f8d">'
            . htmlspecialchars($panelError, ENT_QUOTES, 'UTF-8') . '</pre>';
    }
    trace($traceLog, sprintf('503 probe=%.2fs start=%.2fs id=%s %s',
        $tProbe - $t0, $tStart - $tProbe, $reqID, $why));

    // A browser asking for a page gets a page that retries itself. Handing the waiting
    // back to the client is the entire point: the worker is free the moment this is sent,
    // so ten people reloading cost ten short requests instead of ten held workers.
    if (wantsHTML($_SERVER)) {
        header('Content-Type: text/html; charset=utf-8');

        // A blocked port is not a slow start, and saying "starting" over it would be a lie
        // the reader can do nothing with. No self-refresh either: reloading changes nothing
        // here, and a page that keeps retrying reads as progress when there is none.
        $stuck = $stuckReason !== '';
        $heading = $stuck ? 'The panel cannot start' : 'Starting the panel';
        $explain = $stuck
            ? '<p>Its port, ' . htmlspecialchars($upstream, ENT_QUOTES, 'UTF-8') . ', is held '
                . 'by a process that is not answering, so a new panel cannot bind to it. '
                . 'Reloading will not clear this.</p>'
                . '<p style="color:#e6a">' . htmlspecialchars($stuckReason, ENT_QUOTES, 'UTF-8')
                . '</p>'
            : '<p>Shared hosting does not keep the panel running between visits, so the '
                . 'first request after an idle period has to start it. This page reloads by '
                . 'itself every two seconds.</p>'
                . '<p>If it has not settled within a minute the panel failed to start: check '
                . htmlspecialchars(basename($logFile), ENT_QUOTES, 'UTF-8') . '.</p>';

        // Nothing external: this renders while the panel is, by definition, not answering.
        exit('<!doctype html><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . ($stuck ? '' : '<meta http-equiv="refresh" content="2">')
            . '<title>SentinelHost — ' . ($stuck ? 'blocked' : 'starting') . '</title>'
            . '<style>body{font:16px/1.6 system-ui,sans-serif;margin:0;min-height:100vh;'
            . 'display:grid;place-items:center;background:#111;color:#eee}'
            . 'div{max-width:32rem;padding:2rem;text-align:center}'
            . 'p{color:#aaa;font-size:.9rem}</style>'
            . '<div><h1>' . $heading . '</h1>'
            . $explain
            . $panelErrorHTML . '</div>');
    }

    header(PLAIN);
    exit("SentinelHost bridge: {$why}.\n");
}

// Plain HTTP, and correctly so: this never leaves the machine. The panel listens on the
// loopback, and terminating TLS against yourself adds a certificate to manage while
// protecting nothing. What reaches the visitor is HTTPS, terminated by the web server.
//
// upstreamURL() re-checks that the assembled URL really points at the loopback, and
// returns null if anything in the path moved the host. That should be impossible after
// upstreamPath() anchors it; it is checked at the point of use anyway, because the cost
// is one call and the alternative is resting on a function three screens away continuing
// to behave as it does today.
// The path comes from the rewrite, in __shpath, already relative to this directory. The
// query string is rebuilt without it, so the panel sees the visitor's own parameters and
// not the bridge's plumbing.
$params = $_GET;
$rawPath = (string) ($params['__shpath'] ?? '/');
unset($params['__shpath']);
$target = upstreamURL($upstream, upstreamPath($rawPath, http_build_query($params)));
if ($target === null) {
    http_response_code(400);
    header(PLAIN);
    exit("SentinelHost bridge: refusing a request whose path does not resolve to the panel.\n");
}

// $target has been through upstreamURL(), which returns null unless the assembled URL
// really points at the loopback — no userinfo, host unchanged — and the request is
// refused above when it does. The path being visitor-controlled is the point of a proxy;
// what matters is that it cannot move the destination, and that is checked rather than
// assumed.
$ch = curl_init($target); // NOSONAR - validated by upstreamURL() and refused above if it moved
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

curl_setopt_array($ch, [
    CURLOPT_CUSTOMREQUEST  => $method,
    CURLOPT_HTTPHEADER     => forwardedHeaders(),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER         => true,
    CURLOPT_FOLLOWLOCATION => false, // the browser follows redirects, not the bridge
    // 20s, not 60. A proxy that HANGS is worse than one that fails: a browser waited
    // 300 seconds on this and learned nothing, while each pending request held a PHP
    // worker open. Twenty seconds is generous for a panel on the loopback — the slowest
    // page measured is under a second — and anything past it is a fault worth reporting
    // as one, with a line in the trace log saying where the time went.
    CURLOPT_TIMEOUT        => 20,
    CURLOPT_CONNECTTIMEOUT => 5,
]);

if (!in_array($method, ['GET', 'HEAD'], true)) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
}

$response = curl_exec($ch);
$tUp = microtime(true);
if ($response === false) {
    $err = curl_error($ch);
    curl_close($ch);
    trace($traceLog, sprintf('502 %-6s probe=%.2fs start=%.2fs upstream=%.2fs id=' . $reqID . ' curl=%s',
        $method, $tProbe - $t0, $tStart - $tProbe, $tUp - $tStart, $err));
    http_response_code(502);
    header(PLAIN);
    exit("SentinelHost bridge: could not reach the panel ({$err}).\n");
}

$headerLen = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$status    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// probe: how long it took to learn whether the panel was listening.
// start: how long a cold start took, 0 when it was already up.
// upstream: the panel's own response time.
trace($traceLog, sprintf('%3d %-6s %-28s probe=%.2fs start=%.2fs upstream=%.2fs id=' . $reqID . '%s',
    $status, $method, substr(upstreamPath($rawPath), 0, 28),
    $tProbe - $t0, $tStart - $tProbe, $tUp - $tStart,
    $wasUp ? '' : ' (cold start)'));

$rawHeaders = substr($response, 0, $headerLen);
$body       = substr($response, $headerLen);

http_response_code($status);
foreach (explode("\r\n", $rawHeaders) as $line) {
    if ($line === '' || str_starts_with($line, 'HTTP/')) {
        continue;
    }
    [$name] = explode(':', $line, 2);
    $lower = strtolower(trim($name));
    // Content-Length and the transfer headers describe the upstream response body as it
    // was framed there; PHP frames its own. Set-Cookie must pass through unchanged and
    // may repeat, so it is the one header appended rather than replaced.
    if (in_array($lower, ['content-length', 'transfer-encoding', 'connection'], true)) {
        continue;
    }
    header($line, $lower !== 'set-cookie');
}

echo $body;
