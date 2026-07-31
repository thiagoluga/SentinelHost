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

require __DIR__ . '/lib/path.php';

// Every failure path here answers in plain text: an HTML error page from a security
// tool invites the reader to wonder what else is being rendered.
const PLAIN = 'Content-Type: text/plain';

// --- configuration ----------------------------------------------------------------
//
// $home is the account's home directory. The binary and the data live under it and NOT
// under the document root: a Go binary served as a download is a gift to anyone probing,
// and the quarantine vault holds the files that were removed from the site.
$home     = dirname(__DIR__, 3);                 // adjust if this file is nested differently
$binary   = $home . '/sentinelhost/bin/sentinelhost';
$config   = $home . '/sentinelhost/config.toml';
$lockFile = $home . '/sentinelhost/.bridge.lock';
$logFile  = $home . '/sentinelhost/panel.log';
$upstream = '127.0.0.1:8787';                    // must match web.listen in the TOML
$bootWait = 8.0;                                 // seconds to wait for a cold start
// -----------------------------------------------------------------------------------

/** Is the panel accepting connections right now? */
function panelIsUp(string $hostPort, float $timeout = 1.5): bool
{
    [$host, $port] = explode(':', $hostPort, 2);
    $sock = @fsockopen($host, (int) $port, $errno, $errstr, $timeout);
    if ($sock === false) {
        return false;
    }
    fclose($sock);
    return true;
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
function startPanel(string $binary, string $config, string $lockFile, string $logFile, string $upstream, float $wait): bool
{
    if (!is_executable($binary)) {
        return false;
    }

    $lock = @fopen($lockFile, 'c');
    if ($lock === false) {
        return false;
    }

    $deadline = microtime(true) + $wait;

    // Between finding the panel down and taking the lock, another request may have
    // finished starting it, so the check is repeated inside the lock rather than trusted
    // from before it.
    if (flock($lock, LOCK_EX | LOCK_NB)) {
        if (!panelIsUp($upstream)) {
            $cmd = sprintf(
                'nohup %s serve --config %s >> %s 2>&1 &',
                escapeshellarg($binary),
                escapeshellarg($config),
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

if (!panelIsUp($upstream)) {
    if (!startPanel($binary, $config, $lockFile, $logFile, $upstream, $bootWait)) {
        http_response_code(503);
        header(PLAIN);
        header('Retry-After: 5');
        // Explicit about which of the several possible causes it is, because "503" on a
        // security tool invites the reader to assume the worst.
        $why = is_executable($binary)
            ? "the panel did not come up within {$bootWait}s. Check " . basename($logFile)
            : "the binary is missing or not executable at {$binary}";
        exit("SentinelHost bridge: {$why}.\n");
    }
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
$target = upstreamURL($upstream, upstreamPath($_SERVER['REQUEST_URI'] ?? '/', $_SERVER['SCRIPT_NAME'] ?? '/'));
if ($target === null) {
    http_response_code(400);
    header(PLAIN);
    exit("SentinelHost bridge: refusing a request whose path does not resolve to the panel.
");
}

$ch = curl_init($target);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

curl_setopt_array($ch, [
    CURLOPT_CUSTOMREQUEST  => $method,
    CURLOPT_HTTPHEADER     => forwardedHeaders(),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER         => true,
    CURLOPT_FOLLOWLOCATION => false, // the browser follows redirects, not the bridge
    CURLOPT_TIMEOUT        => 60,
    CURLOPT_CONNECTTIMEOUT => 5,
]);

if (!in_array($method, ['GET', 'HEAD'], true)) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
}

$response = curl_exec($ch);
if ($response === false) {
    $err = curl_error($ch);
    curl_close($ch);
    http_response_code(502);
    header(PLAIN);
    exit("SentinelHost bridge: could not reach the panel ({$err}).\n");
}

$headerLen = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$status    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

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
