# A first task: configure SentinelHost and see what this host can actually run.
#
# Copy this to task.sh, change the two paths at the top, upload it, and read run.log
# after the next tick. It changes nothing on your site: observation mode is on by
# default, so even a `confirmed` verdict only reports.
#
# The runner executes each distinct task.sh exactly once, so this will not repeat.

# --- change these two ---------------------------------------------------------
BASE=$HOME/sentinelhost          # where you put runner.sh and bin/sentinelhost
SITE=$HOME/public_html           # the site to watch
# ------------------------------------------------------------------------------

BIN=$BASE/bin/sentinelhost
CFG=$BASE/config.toml

echo "=== does the binary run here?"
"$BIN" version 2>&1

echo
echo "=== what this host provides"
# The php on a cPanel box is often php-cgi rather than the CLI: it rejects -r and parses
# arguments differently. Worth knowing, because AMWScan is a PHP program.
echo "php:    $(php -v 2>&1 | head -1)"
echo "php -r: $(php -r 'echo PHP_SAPI;' 2>&1 | head -1)"
echo "  (an error above means 'php' is php-cgi; the CLI is usually at" >&2
echo "   /opt/cpanel/ea-phpXX/root/usr/bin/php)" >&2
echo "yara:   $(command -v yara || echo 'not installed — php-malware-finder will abstain')"
echo "maldet: $(command -v maldet || echo 'not installed — that engine will abstain')"

echo
echo "=== configuration"
# --data-dir keeps the database, the baseline and the quarantine vault beside the
# configuration instead of in ~/.sentinelhost. Anywhere is fine EXCEPT inside the site:
# the vault holds the files that were removed from it, and if the web can reach them an
# attacker can fetch their own webshell back.
"$BIN" config init --root "$SITE" --config "$CFG" --data-dir "$BASE/data" 2>&1

echo
echo "=== install the engines that can be installed without root"
"$BIN" engines --install amwscan --config "$CFG" 2>&1
"$BIN" engines --install php-malware-finder --config "$CFG" 2>&1

echo
echo "=== diagnosis"
# Read the ENGINES table carefully. An engine listed as unavailable is not a failure —
# it abstains and the consensus proceeds without it — but it does mean this cycle sees
# less than a full one would, and the reason column tells you what to ask your host for.
"$BIN" doctor --config "$CFG" 2>&1

echo
echo "=== a first scan, which will not move anything"
"$BIN" scan --full --config "$CFG" 2>&1
echo "--- exit code: $?   (0 = nothing found, 1 = findings, other = the cycle failed)"
