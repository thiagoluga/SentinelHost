<?php
/**
 * What the bridge's liveness probe answers, against real sockets.
 *
 * The defect this covers cost an account its panel for hours. The probe was an fsockopen:
 * it asked whether the port ACCEPTS. A wedged process still holds its listening socket, so
 * the kernel completed the handshake and the probe said "up" — the bridge then proxied the
 * visitor's request to it and waited until the web server killed the request. Sixty seconds
 * with no response at all, not even the bridge's own 503 page.
 *
 * So the middle case below is the whole point: a socket that is listening and never
 * accepted from is exactly the shape of a wedged panel, and it is reproducible in one
 * process with no timing tricks. A test that only covered "up" and "down" would have passed
 * against the broken probe.
 *
 * ownedPanelPID is tested harder than anything else here, because it decides what may be
 * KILLED on somebody's hosting account. Every case that cannot prove ownership must answer
 * 0, and 0 is never signalled.
 *
 * Run:  php contrib/php-bridge/tests/panel-health-test.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../lib/panel.php';

$failed = 0;

function check(string $description, $expected, $got): void
{
    global $failed;
    if ($expected !== $got) {
        $failed++;
        printf("FAIL  %s\n      wanted %s, got %s\n",
            $description, var_export($expected, true), var_export($got, true));
    }
}

/** A port that was free a moment ago. Bound, read back, released. */
function freePort(): int
{
    $s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($s === false) {
        fwrite(STDERR, "cannot bind a loopback socket: {$errstr}\n");
        exit(1);
    }
    $name = stream_socket_get_name($s, false);
    fclose($s);
    return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
}

// --- nothing listening -------------------------------------------------------------

$port = freePort();
check('a port with nothing on it', PANEL_DOWN, panelHealth('127.0.0.1:' . $port, 0.5));

check('a listen address that is not host:port', PANEL_DOWN, panelHealth('8787', 0.5));

// --- listening, never answering ----------------------------------------------------
//
// The wedged panel. The socket is never accepted from, so the connection completes in the
// kernel's backlog and the request goes nowhere. This is what used to read as "up".

$stuck = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($stuck === false) {
    fwrite(STDERR, "cannot bind the stuck listener: {$errstr}\n");
    exit(1);
}
$stuckName = (string) stream_socket_get_name($stuck, false);
$t0 = microtime(true);
check('a socket that accepts and never answers', PANEL_SILENT, panelHealth($stuckName, 0.5));
$elapsed = microtime(true) - $t0;
// The probe must give up on its own. If it can hang, it has simply moved the hang from the
// proxy into the check.
if ($elapsed > 3.0) {
    $failed++;
    printf("FAIL  the probe took %.2fs against a silent socket; it must respect its timeout\n",
        $elapsed);
}
fclose($stuck);

// --- listening and answering -------------------------------------------------------
//
// A separate process, because the probe blocks: nothing in this process could reply to it.
// It answers a bare status line rather than pretending to be the panel — the probe must
// accept any HTTP response, including the 404 an older panel with no /healthz would give.

$serverCode = <<<'CODE'
$port = (int) getenv('SH_TEST_PORT');
$crlf = chr(13) . chr(10);
$s = @stream_socket_server('tcp://127.0.0.1:' . $port);
if ($s === false) {
    exit(1);
}
while ($c = @stream_socket_accept($s, 20)) {
    @fread($c, 1024);
    @fwrite($c, 'HTTP/1.0 404 Not Found' . $crlf . 'Content-Length: 0' . $crlf . $crlf);
    @fclose($c);
}
CODE;

$answerPort = freePort();
$pipes = [];
$proc = proc_open(
    [PHP_BINARY, '-r', $serverCode],
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes,
    null,
    ['SH_TEST_PORT' => (string) $answerPort] + $_ENV
);
if (!is_resource($proc)) {
    fwrite(STDERR, "cannot start the answering listener\n");
    exit(1);
}

$answering = 'never came up';
$deadline = microtime(true) + 10.0;
while (microtime(true) < $deadline) {
    $answering = panelHealth('127.0.0.1:' . $answerPort, 1.0);
    if ($answering === PANEL_ANSWERING) {
        break;
    }
    usleep(100000);
}
check('a listener that answers with an HTTP status line', PANEL_ANSWERING, $answering);

foreach ($pipes as $p) {
    if (is_resource($p)) {
        fclose($p);
    }
}
proc_terminate($proc);
proc_close($proc);

// --- which process may be signalled -------------------------------------------------

$root = sys_get_temp_dir() . '/sh-pid-' . getmypid();
@mkdir($root . '/proc/4242', 0o700, true);
$binary = '/home/example/sentinelhost/bin/sentinelhost';
file_put_contents(
    $root . '/proc/4242/cmdline',
    $binary . "\0" . 'serve' . "\0" . '--config' . "\0" . '/home/example/config.toml' . "\0"
);
$pidFile = $root . '/panel.pid';

file_put_contents($pidFile, "4242\n");
check('a pid whose process really is this binary',
    4242, ownedPanelPID($pidFile, $binary, $root . '/proc'));

check('the same pid, checked against a different binary',
    0, ownedPanelPID($pidFile, '/home/example/other/sentinelhost', $root . '/proc'));

// The stale case, and the reason the /proc check exists: the panel was killed hard, its pid
// file survived, and the number now belongs to whatever the account started next.
file_put_contents($pidFile, "9999\n");
check('a pid with no process behind it',
    0, ownedPanelPID($pidFile, $binary, $root . '/proc'));

file_put_contents($pidFile, "1\n");
check('pid 1, which is init', 0, ownedPanelPID($pidFile, $binary, $root . '/proc'));

// kill(2) reads 0 as "every process in my group". A pid file that has been truncated to
// nothing parses as 0, so this is the difference between refusing and killing the web
// server's worker along with everything else the account is running.
file_put_contents($pidFile, "");
check('an empty pid file', 0, ownedPanelPID($pidFile, $binary, $root . '/proc'));

file_put_contents($pidFile, "not a number\n");
check('a pid file with rubbish in it', 0, ownedPanelPID($pidFile, $binary, $root . '/proc'));

file_put_contents($pidFile, "-1\n");
check('a negative pid, which kill(2) reads as a process group',
    0, ownedPanelPID($pidFile, $binary, $root . '/proc'));

check('no pid file at all', 0, ownedPanelPID($root . '/absent.pid', $binary, $root . '/proc'));
check('no pid file configured', 0, ownedPanelPID('', $binary, $root . '/proc'));

// A host with no procfs, or one that hides other processes. Nothing can be proved, so
// nothing may be killed.
file_put_contents($pidFile, "4242\n");
check('a host where /proc cannot be read',
    0, ownedPanelPID($pidFile, $binary, $root . '/no-such-proc'));

// signalPanel must refuse the same numbers, whatever the caller passes.
check('signalling pid 0', false, signalPanel(0, 15));
check('signalling pid 1', false, signalPanel(1, 15));
check('signalling a negative pid', false, signalPanel(-1, 15));

@unlink($root . '/proc/4242/cmdline');
@rmdir($root . '/proc/4242');
@rmdir($root . '/proc');
@unlink($pidFile);
@rmdir($root);

if ($failed > 0) {
    printf("\n%d check(s) failed\n", $failed);
    exit(1);
}
echo "panel health: all checks passed\n";
