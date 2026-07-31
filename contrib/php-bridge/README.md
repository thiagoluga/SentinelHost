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

3. Open `index.php` and check the paths at the top. `$home` is computed as three levels
   above the file; if you nested it differently, set it explicitly.

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

## What this does not do

It does not make the panel survive. The process still dies when the host decides to kill
it — usually after some minutes of idleness. The bridge makes that stop mattering, which
is a different and better thing than fighting it.
