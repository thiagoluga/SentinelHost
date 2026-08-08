<?php
/**
 * Is the panel alive, and if not, whose process is holding its port?
 *
 * In lib/ rather than index.php so it can be tested: index.php starts proxying the moment
 * it is included, so nothing defined in it is reachable from a test.
 *
 * The distinction this file exists for: a TCP connection that succeeds proves something
 * ACCEPTS on the port. It does not prove anything ANSWERS. The bridge decided the panel was
 * up on the strength of an fsockopen, and a wedged process still holds its listening socket,
 * so the probe passed — the bridge then proxied the visitor's request to it and waited until
 * the web server killed the request. Sixty seconds, no response, not even the bridge's own
 * 503 page.
 *
 * It is the failure this project is named after, in the plumbing rather than in a scan:
 * treating "I could not really check" as "everything is fine".
 */

declare(strict_types=1);

/** The panel answered an HTTP request. It is serving. */
const PANEL_ANSWERING = 'answering';

/**
 * The port accepts connections and nothing answered on it.
 *
 * Either the panel is wedged, or some other program of this account's took the port. The
 * two are told apart by the pid file, never by guessing — see ownedPanelPID().
 */
const PANEL_SILENT = 'silent';

/** Nothing is listening. The ordinary case: shared hosting reaped it, and a start fixes it. */
const PANEL_DOWN = 'down';

/**
 * Ask the panel, over HTTP, whether it is serving.
 *
 * GET /healthz, which the panel answers without touching its database, its configuration
 * lock or a session — so a panel busy with a scan still answers at once, and only a process
 * that cannot serve at all stays quiet. That matters because the caller kills what stays
 * quiet, and being wrong there costs a scan.
 *
 * HTTP/1.0 with Connection: close, because the whole exchange is one request and the socket
 * should not be kept alive by a probe.
 *
 * A reply that is not an HTTP status line counts as SILENT rather than as an answer: it
 * means something is on the port, but not the panel. The caller must not conclude "the panel
 * is up" from a stranger's greeting banner.
 */
function panelHealth(string $hostPort, float $timeout = 1.5): string
{
    $parts = explode(':', $hostPort, 2);
    if (count($parts) !== 2) {
        return PANEL_DOWN;
    }
    [$host, $port] = $parts;

    $errno = 0;
    $errstr = '';
    $sock = @fsockopen($host, (int) $port, $errno, $errstr, $timeout);
    if ($sock === false) {
        return PANEL_DOWN;
    }

    $seconds = (int) $timeout;
    $micros = (int) round(($timeout - $seconds) * 1000000);
    stream_set_timeout($sock, $seconds, $micros);

    $request = "GET /healthz HTTP/1.0\r\nHost: " . $host . "\r\n"
        . "User-Agent: SentinelHost-bridge\r\nConnection: close\r\n\r\n";
    $wrote = @fwrite($sock, $request);
    $line = $wrote === false ? false : @fgets($sock, 256);
    $meta = stream_get_meta_data($sock);
    fclose($sock);

    if (!empty($meta['timed_out']) || !is_string($line) || $line === '') {
        return PANEL_SILENT;
    }
    // An older panel with no /healthz answers 404, which is still an answer and still
    // proves it is serving. The status code is deliberately not inspected.
    return str_starts_with($line, 'HTTP/') ? PANEL_ANSWERING : PANEL_SILENT;
}

/**
 * The process id in the pid file, but only if that process really is this binary.
 *
 * Returns 0 for every doubt, and the caller must treat 0 as "do not signal anything". This
 * function decides what may be killed on somebody's hosting account, so every branch that
 * cannot prove ownership has to refuse.
 *
 * The check is not paranoia about a hostile pid file — that file is inside the account's own
 * directory, and anyone who can write it can write the config too. It is about a STALE one:
 * a process killed hard leaves its pid file behind, Linux reuses process ids, and the number
 * that meant the panel this morning can mean the account's cron job this afternoon.
 *
 * /proc/<pid>/cmdline is the evidence. Where it cannot be read — no procfs, or a host that
 * hides other processes — this refuses rather than signalling on the strength of a number.
 */
function ownedPanelPID(string $pidFile, string $binary, string $procRoot = '/proc'): int
{
    if ($pidFile === '' || !is_readable($pidFile)) {
        return 0;
    }
    $raw = @file_get_contents($pidFile);
    if ($raw === false) {
        return 0;
    }
    $pid = (int) trim($raw);
    // 1 is init and 0 means "every process in the group" to kill(2). Neither is ours.
    if ($pid <= 1) {
        return 0;
    }

    $cmdline = @file_get_contents($procRoot . '/' . $pid . '/cmdline');
    if ($cmdline === false || $cmdline === '') {
        return 0;
    }
    // Arguments are NUL-separated; the first is the program that was executed.
    $argv0 = explode("\0", $cmdline)[0];
    if ($argv0 === '' || $argv0 !== $binary) {
        return 0;
    }
    return $pid;
}

/**
 * Signal a process, whichever of PHP's two ways of doing it this host allows.
 *
 * posix_kill is the direct one and needs ext-posix, which shared hosting disables often
 * enough to matter. `kill` through exec() is the fallback; the pid is cast to an integer, so
 * nothing from the pid file reaches a shell as text.
 *
 * Returns false when neither is available, and the caller reports that instead of assuming
 * the process is gone.
 */
function signalPanel(int $pid, int $signal): bool
{
    if ($pid <= 1) {
        return false;
    }
    if (function_exists('posix_kill')) {
        return @posix_kill($pid, $signal);
    }
    if (function_exists('exec')) {
        $code = 1;
        $out = [];
        @exec('kill -' . (int) $signal . ' ' . (int) $pid . ' 2>/dev/null', $out, $code);
        return $code === 0;
    }
    return false;
}
