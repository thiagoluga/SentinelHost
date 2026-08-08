# The panel on shared hosting, available whenever you open the URL

Shared hosting kills long-running user processes. On the account this was built against,
`sentinelhost serve` survived **fourteen minutes**. A panel that depends on a process
staying up cannot work there — and an SSH tunnel is out too when the provider has
disabled the shell, which is common.

WordPress does not have that problem, and the reason is worth being precise about: it is
not that WordPress is more robust. **WordPress never runs continuously either.** The web
server is what stays up, and the web server belongs to the host. PHP is started per
request, answers, and exits.

This bridge gives the panel the same shape. On every request it checks whether the panel
is answering on the loopback, starts it if it is not, and proxies. Nothing has to survive
in between. The panel dying stops being a failure — it is something the next visit fixes.

## Requirements

Check these before installing. One probe answers all of them:

```php
<?php
header('Content-Type: text/plain');
echo 'disable_functions: ' . (ini_get('disable_functions') ?: '(none)') . "\n";
foreach (['exec', 'fsockopen', 'curl_init'] as $f) {
    printf("%-11s %s\n", $f, function_exists($f) ? 'available' : 'BLOCKED');
}
$fp = @fsockopen('127.0.0.1', 8787, $e, $s, 3);
echo 'loopback socket: ' . ($fp ? "OPEN\n" : "FAILED ($e $s)\n");
```

- **`curl_init`** — required. Without it the bridge cannot talk to the panel at all.
- **`fsockopen`** — required. It is how the bridge learns whether the panel is up.
- **`exec`** — needed only to start the panel. Without it the bridge still proxies, but
  something else has to keep the panel alive (a cron that restarts it, say).
- **A loopback socket to `127.0.0.1:8787`.** Some hosts block even this.

Delete the probe once you have read it. A file that reports what your server allows is
not something to leave on a live site.

## Install

1. Put the binary and the data **outside the document root** — `~/sentinelhost/` is what
   the bridge expects:

   ```text
   ~/sentinelhost/
   ├── bin/sentinelhost      0755
   ├── config.toml           0600
   └── data/                 0700  (database, baseline, quarantine vault)
   ```

2. Copy `index.php` and `.htaccess` into a directory of your document root, for example
   `public_html/sentinel/`.

   Then **add that directory to `limits.exclude`** in your `config.toml`:

   ```toml
   [limits]
   exclude = ["/home/YOURUSER/public_html/sentinel/**"]
   ```

   The bridge has to live inside the document root, and it calls `exec()` because starting
   the panel is its whole job — which is exactly what a PHP malware scanner is built to
   notice. Without that line, AMWScan flags the bridge on every cycle.

   An earlier version of this recognised a marker file instead, so no configuration was
   needed. That was removed: writing a file inside the document root is the one thing an
   attacker who has uploaded a webshell has certainly already managed, and the marker let
   them switch off scanning for a directory with a single `touch`. The exclusion list
   lives in a file only you can write, which is the whole difference.

   SentinelHost now **reports** any `.sentinelhost-component` it finds, because nothing
   installs that file any more and its only documented effect was to hide a directory.

3. Open `index.php` and **set `$home` to your account's home directory** — the line is
   near the top and ships as `/home/YOURUSER`. It is spelled out rather than computed
   from the file's location on purpose: a `dirname(__DIR__, 3)` depends on how deep you
   installed the bridge, and being one level off points everything at the wrong place
   while looking like a broken panel. `php -r 'echo getenv("HOME");'` prints it, and
   cPanel shows it as *Home Directory*.

4. Edit `.htaccess` and uncomment the IP restriction.

5. Visit `https://your-site/sentinel/`. The first visit sets the panel password.

The scan is separate and unaffected. Schedule it with `sentinelhost cron-line`.

## Security

**This puts an administrative panel on a public URL.** That is the whole point, and it is
also the risk. Four things are not optional:

**The binary and the data stay outside the document root.** A Go binary served as a
download is a gift to anyone probing, and the quarantine vault holds the very files that
were removed from the site — reachable over the web, an attacker fetches their own
webshell back.

**Restrict by IP.** The panel's password is real protection: argon2id, sessions, and a
rate limiter that survives across processes (`DECISIONS.md` D-033). It should still not be
the only layer between the internet and a button that moves your files.

**Use HTTPS.** The bridge forwards `X-Forwarded-Proto` from what actually happened, and
the panel marks its session cookie `Secure` accordingly. Over plain HTTP the session
travels in the clear.

**Remove it when you stop using it.** An always-reachable admin endpoint is worth having
while you use it and not otherwise.

## How the starting works, and why there is a lock

Two requests arriving together would both find the panel down and both start one: two
processes against one SQLite database and one quarantine vault. The bridge takes a
non-blocking lock, and whichever request gets it starts the panel while the other simply
waits for it to answer.

Non-blocking on purpose — a request that cannot get the lock should not hold a PHP worker
open waiting for it. It waits for the panel, which is the thing it actually needs.

The panel is also re-checked after the lock is acquired: between finding it down and
getting the lock, the other request may already have finished.

## Why the check is an HTTP request, and not a connection

The bridge used to decide the panel was up by opening a TCP connection to its port. That
answers a different question: whether something **accepts**, not whether anything
**answers**.

A wedged process still holds its listening socket. The kernel completes the handshake on
its behalf, so the probe passed, the bridge proxied the visitor's request to it, and the
request hung until the web server gave up — sixty seconds with no response at all, not even
this bridge's own 503 page. It happened on the account this was built against.

That is worse than the panel being down. A down panel is answered in two seconds by a page
that retries itself, and the next visit starts a new one. A wedged panel holds a PHP worker
on an account with a small ceiling on them, and tells the person looking at the screen
nothing.

So the probe now sends `GET /healthz` and requires an HTTP response. The panel answers that
without touching its database, its configuration lock or a session, so a panel busy with a
scan still replies at once and only one that cannot serve at all stays quiet.

**When something is holding the port without answering, the bridge clears it.** Nothing else
can: the port is taken, so every start dies with *address already in use*; a wedged process
does not recover; and the account has no shell, which is the reason this bridge exists.

Two rules make that safe enough to do without asking:

- Only a process id written by the panel itself, and confirmed through `/proc` to still be
  running **this binary**, is ever signalled. A pid file outlives a process that died hard,
  and Linux reuses process ids — the number that meant the panel this morning can mean the
  account's cron job this afternoon. Every case that cannot prove ownership refuses, and the
  503 page says the port is held by something it could not identify, which is a fact you can
  act on.
- `TERM` first, `KILL` only if the port is still occupied two seconds later. A panel that is
  merely slow shuts down cleanly and finishes what it was doing.

This is why the bridge starts the panel with `--pidfile`, and why `$pidFile` sits beside
`$lockFile` at the top of `index.php`. It is configured in one place and passed from there,
so the two cannot drift apart.

**Upgrade the binary before this bridge.** `--pidfile` and `/healthz` arrived together with
it, and a binary older than that rejects the flag and exits — every start would die. If you
do it in the wrong order the panel will not come up, and the waiting page will say
`flag provided but not defined: -pidfile`, which is the whole diagnosis. Install the newer
binary and it starts working again; nothing is lost.

## What this does not do

It does not make the panel survive. The process still dies when the host decides to kill
it — usually after some minutes of idleness. The bridge makes that stop mattering, which
is a different and better thing than fighting it.
