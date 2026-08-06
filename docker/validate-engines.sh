#!/usr/bin/env bash
#
# Validation of the real engines on a simulated hosting account.
#
# This script deliberately does NOT stop at the first error: the goal is to raise
# ALL the problems at once, not to find one per run. Every step prints what it tried
# and what happened, and a verdict comes out at the end.
#
# What it answers, that the automated suite does not:
#   1. Do the flags the adapters assemble exist in the engines?
#   2. Does the engine accept the target list, or does it walk something else?
#   3. Does the real output match what Parse expects?
#   4. Does the consensus find the corpus samples with REAL engines?
#
# Question 2 is the most important one. A flag the engine accepts and ignores makes
# the scan walk the wrong target, Parse work, and the panel show "0 findings" with
# the engine marked as healthy.

set -uo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

FAILURES=0
WARNINGS=0

section() { printf '\n%s%s== %s ==%s\n' "$BOLD" "$BLUE" "$1" "$RESET"; }
ok()      { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
fail()    { printf '  %s✗%s %s\n' "$RED" "$RESET" "$1"; FAILURES=$((FAILURES+1)); }
warn()    { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1"; WARNINGS=$((WARNINGS+1)); }
info()    { printf '    %s\n' "$1"; }

SITE="$HOME/public_html"
CFG="$HOME/config.toml"

# ---------------------------------------------------------------------------
section "Environment"

printf '  %-14s %s\n' "sentinelhost" "$(sentinelhost version 2>&1 | head -1)"
printf '  %-14s %s\n' "php"          "$(php -v 2>&1 | head -1 || echo MISSING)"
printf '  %-14s %s\n' "yara"         "$(yara --version 2>&1 | head -1 || echo MISSING)"
printf '  %-14s %s\n' "user"         "$(id -un) (uid $(id -u))"
if [[ "$(id -u)" = "0" ]]; then
  warn "running as root: that hides the permission problems that only show up on a real account"
fi

# ---------------------------------------------------------------------------
section "Building the test site"

# A REAL WordPress, not a skeleton.
#
# With a fake wp-includes/version.php, wp-checksums finds 2997 missing core files
# and abstains — correct behaviour, but it leaves precisely the highest-weight
# engine (1.5) unexercised, the only one that on its own gets close to `confirmed`,
# and with it the entire quarantine path.
WP_VERSION="6.5.2"
mkdir -p "$SITE"
if curl --proto '=https' --proto-redir '=https' -fsSL \
     "https://wordpress.org/wordpress-${WP_VERSION}.tar.gz" -o /tmp/wp.tar.gz 2>/dev/null; then
  tar -xzf /tmp/wp.tar.gz -C /tmp
  cp -r /tmp/wordpress/. "$SITE/"
  rm -rf /tmp/wordpress /tmp/wp.tar.gz
  ok "real WordPress ${WP_VERSION} installed ($(find "$SITE" -type f | wc -l) files)"
  WP_REAL=1
else
  warn "could not download WordPress; falling back to a skeleton"
  warn "wp-checksums will abstain and will NOT be exercised in this run"
  mkdir -p "$SITE/wp-includes"
  cat > "$SITE/wp-includes/version.php" <<PHP
<?php
\$wp_version = '${WP_VERSION}';
PHP
  WP_REAL=0
fi

mkdir -p "$SITE"/wp-content/{plugins/cache-helper,themes/theme/inc,uploads/2026/{03,07}}

# The core tampering. Two files, on purpose:
#
#  - pluggable.php gets only one innocuous line: wp-checksums alone flags it.
#    1.50 over the ceiling of 2.0 = 0.75 → `likely`. One engine alone, even the
#    heaviest one, does NOT reach `confirmed` — that is the consensus's design
#    (D-003), and this sample exists to pin it.
#
#  - functions.php gets the content of a sample AMWScan recognizes. That makes two
#    votes: 1.50 (checksum) + 0.64 (heuristic) = 2.14, which saturates at 1.0 →
#    `confirmed`. It is the only path that authorizes an automatic quarantine, and
#    without it the path that justifies the tool's existence has no proof.
if [[ "$WP_REAL" = "1" ]]; then
  echo '// SENTINELHOST-SYNTHETIC-CORPUS: an extra line the official core does not have' \
    >> "$SITE/wp-includes/pluggable.php"
  ok "core tampered for the checksum only (wp-includes/pluggable.php → likely)"

  cat /corpus/synthetic/02-backdoor-eval-post.php >> "$SITE/wp-includes/functions.php"
  ok "core tampered for checksum + AMWScan (wp-includes/functions.php → confirmed)"
fi

# A filename holding a NEWLINE, planted where the engines will actually be asked about it.
#
# The scope goes to yara and maldet as one path per line, so `x<LF>.php` becomes two lines
# and neither exists — every engine reported zero findings on a live webshell, which is the
# failure this project exists to prevent, produced by one rename().
#
# That was fixed and unit-tested, and a unit test proves the orchestrator refuses the path.
# It does NOT prove what the real engines do with the list, which is the whole reason this
# script exists (D-022). Planted here so the refusal is exercised against yara and maldet
# rather than against my model of them.
#
# printf, not a shell literal: backslash-n inside quotes is two characters in some
# shells and a newline in others, and getting that wrong would plant an ordinary filename and prove
# nothing while looking identical.
EVASION_DIR="$SITE/wp-content/uploads/evasion"
mkdir -p "$EVASION_DIR"
EVASION_NAME="$(printf 'x
.php')"
if cp /corpus/synthetic/02-backdoor-eval-post.php "$EVASION_DIR/$EVASION_NAME" 2>/dev/null; then
  ok "planted a payload whose filename holds a newline"
  export SH_EVASION_PLANTED=1
else
  warn "this filesystem would not accept a newline in a filename; the evasion case is NOT covered"
  export SH_EVASION_PLANTED=0
fi

# A REAL plugin from the official directory, to exercise plugin integrity
# verification against the actual API.
#
# Every assumption about an external API in this session turned out wrong (the
# AMWScan release URL, the path of the php.yar rules, the report's format). The
# plugin checksums API has a different shape from the core's — arrays of hashes per
# file, indexed by directory slug — and none of that counts as verified until a real
# response passes through the parser.
PLUGIN_SLUG="classic-editor"
PLUGIN_VERSION="1.6.7"
if curl --proto '=https' --proto-redir '=https' -fsSL \
     "https://downloads.wordpress.org/plugin/${PLUGIN_SLUG}.${PLUGIN_VERSION}.zip" \
     -o /tmp/plugin.zip 2>/dev/null; then
  if command -v unzip >/dev/null && unzip -qo /tmp/plugin.zip -d "$SITE/wp-content/plugins/"; then
    ok "real plugin installed: ${PLUGIN_SLUG} ${PLUGIN_VERSION}"
    PLUGIN_REAL=1
    # Tamper with the plugin's main file: it is the finding only the plugin
    # verification catches — it does not show up in the core check.
    #
    # The main file, and not "any other PHP": this plugin has a single PHP file, and
    # the first version of this validation looked for `! -name classic-editor.php`,
    # found no target at all, and carried on without tampering with anything —
    # declaring success by not having tested.
    target="$SITE/wp-content/plugins/${PLUGIN_SLUG}/${PLUGIN_SLUG}.php"
    if [[ -f "$target" ]]; then
      echo '// SENTINELHOST-SYNTHETIC-CORPUS: a change in a plugin file' >> "$target"
      ok "plugin file tampered with: ${target#$SITE/}"
    else
      fail "could not find the plugin's main file to tamper with"
    fi
    # And a file that does not belong to the plugin: zero tolerance.
    echo '<?php // SENTINELHOST-SYNTHETIC-CORPUS: does not belong to the plugin' \
      > "$SITE/wp-content/plugins/${PLUGIN_SLUG}/extra-backdoor.php"
    ok "extra file planted inside the plugin"
  else
    warn "unzip unavailable or failed; the plugin verification will not be exercised"
    PLUGIN_REAL=0
  fi
  rm -f /tmp/plugin.zip
else
  warn "could not download the plugin; the plugin verification will not be exercised"
  PLUGIN_REAL=0
fi

cp /corpus/clean/base64-legitimate.php "$SITE/wp-content/plugins/legitimate.php"
cp /corpus/clean/util.min.js           "$SITE/wp-content/themes/theme/util.min.js"
cp /corpus/clean/legitimate-plugin.php "$SITE/wp-content/plugins/clean-corpus.php"

cp /corpus/synthetic/01-webshell-parameter.php      "$SITE/wp-content/uploads/2026/07/cache.php"
cp /corpus/synthetic/02-backdoor-eval-post.php      "$SITE/wp-content/plugins/cache-helper/init.php"
cp /corpus/synthetic/03-obfuscation-blob.php        "$SITE/wp-content/themes/theme/inc/loader.php"
cp /corpus/synthetic/04-uploader-no-validation.php  "$SITE/up.php"
cp /corpus/synthetic/06-phishing-harvest.php        "$SITE/login.php"
cp /corpus/synthetic/09-known-marker.php            "$SITE/wp-content/uploads/2026/07/x.php"
cp /corpus/synthetic/12-reverse-shell-described.php "$SITE/wp-content/uploads/2026/07/conn.php"

TOTAL=$(find "$SITE" -type f | wc -l)
ok "site built with $TOTAL files ($(find "$SITE" -name '*.php' | wc -l) PHP)"

sentinelhost config init --root "$SITE" --config "$CFG" >/dev/null 2>&1 \
  && ok "configuration created" \
  || fail "config init failed"

# ---------------------------------------------------------------------------
section "Probing the engines"

sentinelhost engines --config "$CFG" 2>&1 | sed 's/^/  /'

# ---------------------------------------------------------------------------
section "Installing the engines in the user's space"

for eng in amwscan php-malware-finder; do
  output=$(sentinelhost engines --install "$eng" --config "$CFG" 2>&1)
  if [[ $? -eq 0 ]]; then
    ok "$eng installed"
  else
    fail "$eng did NOT install"
    info "$output"
  fi
done

echo
info "installed files:"
find "$HOME/.sentinelhost/engines" -type f -printf '    %-60p %10s bytes\n' 2>/dev/null \
  || info "    (none)"

# ---------------------------------------------------------------------------
section "Do the adapters' flags exist in the engines?"

# This is the step the automated suite cannot do. Each flag is tested in isolation
# against the real engine.

PHAR="$HOME/.sentinelhost/engines/amwscan/scanner.phar"
YARA_RULES="$HOME/.sentinelhost/engines/pmf/php.yar"

if [[ -f "$PHAR" ]]; then
  # AMWScan dies silently (exit 255, zero output) when a PHP extension is missing.
  # If --help produces nothing, the flag checks below would give a false negative on
  # everything — so the engine's state comes first.
  help_amw=$(php "$PHAR" --help 2>&1)
  if [[ -z "$help_amw" ]]; then
    fail "AMWScan produces no output at all (exit $?): a PHP extension is probably missing"
    info "the most common cause is mbstring — install php-mbstring and try again"
  else
    ok "AMWScan runs on this PHP"
    # The flags the adapter actually assembles today.
    for flag in --report --report-format --path-report --no-colors --silent --filter-paths --max-filesize; do
      if grep -q -- "$flag" <<<"$help_amw"; then
        ok "amwscan accepts $flag"
      else
        fail "amwscan does NOT document $flag — the adapter assembles an invalid line"
      fi
    done
    # And the ones it does NOT have, to pin the regression that already happened once.
    for nonexistent in --format --filter-paths-list; do
      if grep -q -- "$nonexistent" <<<"$help_amw"; then
        warn "$nonexistent now exists; the adapter is worth re-evaluating"
      else
        ok "confirmed: $nonexistent does not exist (the adapter no longer uses it)"
      fi
    done
    if grep -qi 'json' <<<"$help_amw"; then
      warn "AMWScan now mentions JSON; the adapter reads txt today"
    else
      ok "confirmed: AMWScan has no JSON output (the adapter reads txt)"
    fi
  fi
else
  fail "AMWScan missing — the flags cannot be checked"
fi

echo
help_yara=$(yara --help 2>&1)
for flag in --no-warnings --max-strings-per-rule --scan-list; do
  if grep -q -- "$flag" <<<"$help_yara"; then
    ok "yara accepts $flag"
  else
    fail "yara does NOT document $flag — the pmf adapter assembles an invalid line"
  fi
done

echo
# maldet is installed by root, system-wide, and the adapter deliberately never tries
# to install it (Principle III). So here we check the invocation, not the install.
if command -v maldet >/dev/null 2>&1; then
  ok "maldet present: $(maldet --version 2>&1 | head -1)"
  help_maldet=$(maldet --help 2>&1)

  # Both configurations, because the adapter has to be right in each.
  #
  # maldet ships scan_user_access="0". Under that default it refuses every
  # unprivileged account — banner, refusal, exit 0 — from `--version` and `--help`
  # too. Probe used to read a version out of that banner and report the engine
  # HEALTHY on a host where it could never produce a finding, which is the mbstring
  # mistake repeated. So the refusal is asserted first, deliberately, and only then
  # is the gate opened to exercise the real scan path.
  if [[ -w /usr/local/maldetect/conf.maldet ]]; then
    sed -i 's/^scan_user_access=.*/scan_user_access="0"/' /usr/local/maldetect/conf.maldet
    probe_gated=$(sentinelhost engines --config "$CFG" 2>&1 | grep -i maldet || true)
    # Column 4 is AVAILABLE. Column 2 is ENABLED, and matching that instead is how the
    # first version of this check failed a correct adapter: `maldet yes 1.00 no <reason>`
    # is exactly the right answer, and it was being read as a defect.
    if [[ "$(awk '/^[[:space:]]*maldet[[:space:]]/{print $4; exit}' <<<"$probe_gated")" = "yes" ]]; then
      fail "Probe reports maldet AVAILABLE on a host where it cannot scan for this user"
      info "  $probe_gated"
      info "'the binary runs' is not 'the engine works' — see DECISIONS.md D-011"
    else
      ok "with scan_user_access=0, Probe refuses maldet instead of reporting it healthy"
    fi
    if sentinelhost engines --config "$CFG" 2>&1 | grep -qi 'scan_user_access'; then
      ok "the reason names scan_user_access: one line for the admin to change"
    else
      fail "the reason does not name scan_user_access, so it reads as a bug in our parser"
    fi

    sed -i 's/^scan_user_access=.*/scan_user_access="1"/' /usr/local/maldetect/conf.maldet
    help_maldet=$(maldet --help 2>&1)
  fi

  if grep -qiE 'public scanning (is currently disabled|support not enabled)' <<<"$help_maldet"; then
    MALDET_GATED=1
    warn "maldet still refuses this account, so its real scan path cannot be exercised here"
  else
    MALDET_GATED=0
    ok "with scan_user_access=1, maldet serves this unprivileged account"
  fi
fi

if command -v maldet >/dev/null 2>&1 && [[ "${MALDET_GATED:-1}" = "0" ]]; then
  for flag in --config-option --report --scan-all; do
    if grep -q -- "$flag" <<<"$help_maldet"; then
      ok "maldet accepts $flag"
    else
      fail "maldet does NOT document $flag — the adapter assembles an invalid line"
    fi
  done

  # `dump` is what actually prints a report to stdout, and it is NOT in --help:
  # only maldet's own internals/functions reveals it. Without it `--report <id>`
  # hands the session file to $EDITOR and the adapter reads nothing. Because it is
  # undocumented, the only honest check is to run it and see whether text comes out —
  # which is what the baseline below does.
  if grep -q 'dump' <<<"$help_maldet"; then
    ok "maldet now documents 'dump' in --help"
  else
    info "confirmed: 'dump' stays undocumented (DECISIONS.md D-025); it is exercised for real below"
  fi

  # The comma-separated form of --config-option. Passing the flag three times is what
  # the adapter used to do, and a dropped quarantine_hits=0 means maldet moves the
  # user's files into its own non-reversible quarantine — a Principle I violation
  # committed by us. So this asserts the syntax maldet documents.
  if grep -qE 'config-option.*VAR1=VALUE,VAR2=VALUE' <<<"$help_maldet"; then
    ok "confirmed: --config-option takes ONE comma-separated value"
  else
    warn "--config-option's documented syntax changed; re-check the adapter's argument list"
  fi
elif ! command -v maldet >/dev/null 2>&1; then
  warn "maldet is not installed in this image — its adapter can only be checked for absence"
fi

# ---------------------------------------------------------------------------
section "Running the engines directly (the baseline)"

# Run each engine by hand, the way it expects, to learn what IT thinks. It is
# against this number that the orchestrator's result has to match.

if [[ -f "$PHAR" ]] && [[ -n "${help_amw:-}" ]]; then
  php -d memory_limit=256M "$PHAR" --report --report-format txt \
      --path-report /tmp/direct --no-colors --silent "$SITE" >/dev/null 2>&1
  n_amw=$(grep -c '^File:' /tmp/direct.log 2>/dev/null || echo 0)
  info "AMWScan directly over the root: $n_amw file(s) flagged"
  ok "a real report is available at /tmp/direct.log (use it as a new fixture)"
fi

if [[ -f "$YARA_RULES" ]]; then
  n_yara=$(yara --no-warnings -r "$YARA_RULES" "$SITE" 2>/dev/null | wc -l)
  info "yara directly over the root: $n_yara matched-rule line(s)"
fi

if command -v maldet >/dev/null 2>&1 && [[ "${MALDET_GATED:-1}" = "0" ]]; then
  # The same line the adapter assembles, run by hand, over a NAMED SCOPE.
  #
  # `-f <list>` and not `-a "$SITE"`, for two reasons. It is the flag the adapter
  # actually uses now, so this is the command line under test; and maldet costs ~0.5s
  # per file, so `-a` over this 3,000-file site takes 28m36s — measured, not
  # guessed. This image's own header says a validation nobody has the patience to run
  # validates nothing, and a half-hour wait before the first maldet result is how that
  # happens.
  #
  # The scope is small and DELIBERATE: the planted marker file, which the image taught
  # maldet a signature for, plus a couple of clean files. So "maldet finds N on its own"
  # below is N over these paths, not over the whole site — the comparison further down
  # is written to respect that difference rather than paper over it.
  maldet_list=/tmp/maldet-targets.txt
  : > "$maldet_list"
  for f in \
      "$SITE/wp-content/uploads/2026/07/x.php" \
      "$SITE/wp-content/plugins/legitimate.php" \
      "$SITE/wp-content/plugins/clean-corpus.php"; do
    [[ -f "$f" ]] && printf '%s\n' "$f" >> "$maldet_list"
  done
  n_maldet_targets=$(grep -c . "$maldet_list")
  info "maldet baseline scope: $n_maldet_targets file(s) through --file-list"

  maldet_scan=$(maldet \
      --config-option quarantine_hits=0,quarantine_clean=0,quarantine_suspend_user=0 \
      -f "$maldet_list" 2>&1)
  scan_id=$(grep -oE '[0-9]{6}-[0-9]{4}\.[0-9]+' <<<"$maldet_scan" | head -1)

  if [[ -n "$scan_id" ]]; then
    ok "maldet ran and printed a scan id ($scan_id)"
    report=$(maldet --report "$scan_id" dump 2>&1)
    if [[ -n "$report" ]] && grep -q 'TOTAL HITS:' <<<"$report"; then
      ok "'--report <id> dump' really printed the report ($(wc -l <<<"$report") lines)"
      n_maldet=$(grep -E '^\{' <<<"$report" | wc -l)
      info "maldet over the named scope: $n_maldet hit(s)"

      # THE check that settles ScopeAware, and the one this whole file exists for.
      #
      # A flag the engine accepts and ignores is how `--filter-paths` fooled the
      # AMWScan adapter (D-018): the command line looks right, the engine walks the
      # whole root anyway, and nothing anywhere says so. maldet's own TOTAL FILES is
      # what makes it checkable — if `-f` were being ignored, this would read 3,000-odd
      # instead of a handful, and the adapter would be burning 28m36s of a shared
      # host's CPU every cycle while claiming to scan only what changed.
      reported_files=$(awk '/^TOTAL FILES:/{print $3; exit}' <<<"$report")
      if [[ "${reported_files:-0}" = "$n_maldet_targets" ]]; then
        ok "--file-list really restricts the walk: TOTAL FILES = $reported_files, exactly the list"
      else
        fail "--file-list was accepted and IGNORED: asked for $n_maldet_targets file(s), maldet scanned ${reported_files:-?}"
        info "ScopeAware=true is then a lie, and every cycle pays a full-root walk (D-018 again)"
      fi

      # The planted marker is the only file here maldet has a signature for. Zero hits
      # would mean the custom signature never loaded, and every maldet check downstream
      # would be passing over a scan that found nothing by construction.
      if [[ "$n_maldet" -eq 0 ]]; then
        fail "maldet found nothing even on the file it has a signature for"
        info "the image's custom signature did not load; nothing below really exercises maldet"
      fi
      cp /usr/local/maldetect/sess/session."$scan_id" /tmp/direct-maldet.txt 2>/dev/null \
        && ok "a real report is available at /tmp/direct-maldet.txt (use it as a new fixture)"

      # The format check the adapter applies, asserted against reality rather than
      # against what the docs suggested. It used to look for a line maldet never prints.
      for marker in 'SCAN ID:' 'TOTAL HITS:' 'TOTAL FILES:' 'FILE HIT LIST:'; do
        grep -q "$marker" <<<"$report" \
          && ok "the report contains '$marker'" \
          || warn "the report has NO '$marker' — the adapter's format check needs revisiting"
      done
      if grep -qi 'malware detect scan report' <<<"$report"; then
        warn "'malware detect scan report' now appears; the old format check would work again"
      else
        ok "confirmed: no 'malware detect scan report' line exists (D-025)"
      fi
    else
      fail "'--report <id> dump' printed nothing usable — the adapter would abstain every cycle"
      info "$(head -3 <<<"$report")"
    fi
  else
    warn "maldet printed no scan id; there is nothing to fetch (the adapter abstains, correctly)"
  fi
fi

# ---------------------------------------------------------------------------
section "A complete cycle through the orchestrator"

scan_output=$(sentinelhost scan --full --config "$CFG" 2>&1)
code=$?
echo "$scan_output" | sed 's/^/  /'

echo
case $code in
  0) warn "exit 0: the cycle found NOTHING. With 7 synthetic samples on the site, that is suspicious." ;;
  1) ok "exit 1: the cycle found findings" ;;
  *) fail "exit $code: the cycle failed" ;;
esac

# The test that really matters: did the engines run, or did they only abstain?
if grep -q '✓' <<<"$scan_output"; then
  ok "at least one engine really executed"
else
  fail "NO engine executed — all of them abstained"
  info "this is exactly what the automated suite cannot detect"
fi

# And the most dangerous of all: the engine runs, comes out green, and the
# orchestrator sees less than the engine saw on its own. It is the signature of an
# accepted-and-ignored flag, and it is how `--filter-paths` was caught.
#
# The comparison is against the BASELINE, not against zero: an engine that finds
# nothing because the corpus is too inert for its rules is right.
orch_amw=$(grep -oE '✓ amwscan +[0-9]+ finding' <<<"$scan_output" | grep -oE '[0-9]+' | head -1)
orch_amw=${orch_amw:-0}
if [[ "${n_amw:-0}" -gt 0 ]] && [[ "$orch_amw" -eq 0 ]]; then
  fail "AMWScan found $n_amw file(s) on its own and the orchestrator saw 0"
  info "the signature of an accepted-and-ignored flag: the engine walked something else"
elif [[ "${n_amw:-0}" -gt 0 ]]; then
  ok "the orchestrator saw what AMWScan saw on its own ($orch_amw vs $n_amw)"
fi

orch_pmf=$(grep -oE '✓ php-malware-finder +[0-9]+ finding' <<<"$scan_output" | grep -oE '[0-9]+' | head -1)
orch_pmf=${orch_pmf:-0}
if [[ "${n_yara:-0}" -gt 0 ]] && [[ "$orch_pmf" -eq 0 ]]; then
  fail "yara matched $n_yara rule(s) on its own and the orchestrator saw 0"
elif [[ "${n_yara:-0}" -eq 0 ]]; then
  warn "yara matched no rule even on its own: the synthetic corpus is too inert for the real php.yar"
  info "that is NOT an adapter bug, but it means pmf is not really being exercised here"
else
  ok "the orchestrator saw what yara saw on its own ($orch_pmf finding(s))"
fi

if command -v maldet >/dev/null 2>&1 && [[ "${MALDET_GATED:-1}" = "0" ]]; then
  orch_maldet=$(grep -oE '✓ maldet +[0-9]+ finding' <<<"$scan_output" | grep -oE '[0-9]+' | head -1)
  orch_maldet=${orch_maldet:-0}
  # Any status marker counts as "the orchestrator mentioned it". The first version of
  # this listed only ✓ ⊘ ✗ and so failed on `!`, the marker for a timeout abstention —
  # reporting a correctly-abstaining adapter as an unregistered one.
  if grep -qE '(✓|⊘|✗|!) +maldet' <<<"$scan_output"; then
    # The two counts are NOT expected to be equal, and saying so is the point: the
    # baseline above scanned a named handful of files while the cycle scanned the whole
    # site, so the orchestrator can legitimately see MORE. What would be a defect is
    # seeing fewer than what maldet found on its own over a subset of the same tree.
    if [[ "${n_maldet:-0}" -gt 0 ]] && [[ "$orch_maldet" -eq 0 ]]; then
      fail "maldet found ${n_maldet} hit(s) over a subset of this very site and the orchestrator saw 0"
      info "the signature of an accepted-and-ignored flag: the engine walked something else"
    elif [[ "${n_maldet:-0}" -gt 0 ]] && [[ "$orch_maldet" -lt "${n_maldet:-0}" ]]; then
      fail "the orchestrator saw $orch_maldet finding(s) where maldet alone found ${n_maldet} in a SUBSET"
      info "a wider scope cannot yield fewer hits; findings are being lost between Scan and Parse"
    elif [[ "${n_maldet:-0}" -eq 0 ]]; then
      warn "maldet matched nothing even on its own: its signatures do not cover the inert corpus"
      info "that is NOT an adapter bug, but maldet's detection is not really exercised here"
    else
      ok "the orchestrator saw at least what maldet saw on its own ($orch_maldet over the site vs ${n_maldet} over $n_maldet_targets file(s))"
    fi
  else
    fail "maldet is installed and the orchestrator did not even mention it"
    info "the adapter was probably never registered, or Probe() rejected a working engine"
  fi

  # THE check that justifies installing maldet here at all.
  #
  # This image leaves the host default quarantine_hits="1" ON, so maldet WILL move
  # every hit into /usr/local/maldetect/quarantine unless the adapter's own
  # --config-option turns it off. A file moved there is outside SentinelHost's
  # reversible vault: `sentinelhost quarantine restore` cannot bring it back, and
  # Principle I ("never destroys, always reversible") is broken by us, on a user's
  # site, silently. Counting the vault is the only way to prove the flag took effect.
  q_count=$(find /usr/local/maldetect/quarantine -type f 2>/dev/null | wc -l)
  if [[ "$q_count" -eq 0 ]]; then
    ok "maldet's own quarantine is empty: the adapter's flag really disabled it"
  else
    fail "maldet moved $q_count file(s) into ITS quarantine, outside the reversible vault"
    info "Principle I violated by the orchestrator itself; --config-option did not take effect"
    find /usr/local/maldetect/quarantine -type f 2>/dev/null | head -5 | sed 's/^/      /'
  fi
fi

echo
# The project's highest-weight engine. If it does not run, the path that leads to
# `confirmed` — and therefore to an automatic quarantine — is never exercised.
if [[ "${WP_REAL:-0}" = "1" ]]; then
  if grep -qE '✓ wp-checksums' <<<"$scan_output"; then
    ok "wp-checksums ran over a real WordPress"
    if grep -q 'core_file_modified' <<<"$scan_output"; then
      ok "the core tampering was detected (weight 1.50)"
    else
      fail "the tampered core was NOT detected by wp-checksums"
      info "it is the project's highest-weight signal; without it the consensus loses its strongest vote"
    fi

    # The consensus escalating as designed: one strong vote gives `likely`, two votes
    # give `confirmed`. If that distinction disappears, either the tool acts on its
    # own too early, or it never acts.
    if grep -q 'LIKELY.*pluggable.php' <<<"$scan_output"; then
      ok 'one strong vote alone stopped at likely (it did not escalate to confirmed)'
    else
      fail 'the verdict for pluggable.php is not likely: the consensus escalation changed'
    fi
    if grep -q 'CONFIRMED.*functions.php' <<<"$scan_output"; then
      ok 'two votes (checksum + heuristic) reached confirmed'
    else
      fail 'checksum + AMWScan on the same file did NOT reach confirmed'
      info "it is the only path that authorizes an automatic quarantine"
    fi
  else
    fail "wp-checksums abstained even with a real WordPress at the root"
  fi
fi

# PLUGIN integrity against the real API (FR-005, second half).
if [[ "${PLUGIN_REAL:-0}" = "1" ]]; then
  if grep -q 'plugin_file_modified' <<<"$scan_output"; then
    ok "a change in a plugin file was detected against the real API"
  else
    fail "the change in the plugin was NOT detected"
    info "it is the finding only the plugin verification catches: it does not show up in the core"
    info "check the response format of downloads.wordpress.org/plugin-checksums"
  fi
  if grep -q 'plugin_file_unexpected' <<<"$scan_output"; then
    ok "a file that does not belong to the plugin was detected"
  else
    fail "the extra file inside the plugin was NOT detected"
  fi
  # And most importantly: a plugin with no published checksum has to show up as NOT
  # verified, never as verified and clean.
  if grep -qE 'plugin_(without_checksum|verified)' <<<"$scan_output"; then
    ok "the verified/unverified plugin accounting shows up in the report"
  else
    warn "the report did not show the plugin accounting"
  fi
fi

# ---------------------------------------------------------------------------
section "Quarantine with real POSIX permissions"

# The round trip is already tested in the suite, but only here does it run on an
# unprivileged account, with the umask and the owner of a real hosting account.
# The TOML is written with indentation (enc.Indent = "  "), so a `^` anchor never
# matches. That is how observation mode stayed on and the quarantine never fired in
# the first rounds — a bug in the script, not in the product.
sed -i -E 's/^[[:space:]]*observation_mode[[:space:]]*=.*/  observation_mode = false/' "$CFG"
sed -i -E 's/^[[:space:]]*grace_period_days[[:space:]]*=.*/  grace_period_days = 0/' "$CFG"

if grep -qE 'observation_mode[[:space:]]*=[[:space:]]*false' "$CFG"; then
  ok "observation mode turned off to exercise the quarantine"
else
  fail "could not turn observation mode off in the TOML"
fi

sentinelhost scan --full --config "$CFG" >/dev/null 2>&1
listing=$(sentinelhost quarantine list --config "$CFG" 2>&1)

if grep -q 'vault is empty' <<<"$listing"; then
  if [[ "${WP_REAL:-0}" = "1" ]]; then
    # With a real WordPress and a tampered core, the consensus MUST reach
    # `confirmed` and the quarantine MUST happen. If it did not, the path that
    # justifies the tool's existence does not work.
    fail "nothing was quarantined even with a tampered core and the automatic action allowed"
    info "the verdict -> confirmed -> reversible quarantine path did not close"
  else
    warn "nothing was quarantined (expected without a real WordPress to tamper with)"
  fi
else
  echo "$listing" | sed 's/^/  /'
  ref=$(grep -oE 'q_[0-9]+_[0-9a-f]+' <<<"$listing" | head -1)
  if [[ -n "$ref" ]]; then
    original=$(sentinelhost quarantine list --config "$CFG" 2>/dev/null \
      | grep "$ref" | awk '{print $NF}')

    # Did the file leave its place?
    if [[ -n "$original" ]] && [[ ! -e "$original" ]]; then
      ok "the file was moved into the vault (it is no longer in place)"
    fi

    if sentinelhost quarantine verify --config "$CFG" >/dev/null 2>&1; then
      ok "the vault is intact (the hashes check out)"
    else
      fail "the vault has copies that do not check out"
    fi

    # A byte-for-byte round trip on an unprivileged account, with the umask and the
    # owner of a real hosting account. It is the promise that makes the automation
    # acceptable.
    if sentinelhost quarantine restore "$ref" --config "$CFG" >/dev/null 2>&1; then
      if [[ -n "$original" ]] && [[ -f "$original" ]]; then
        ok "the byte-for-byte restore worked on an unprivileged account"
        info "the file is back at $original"
      else
        fail "restore reported success but the file did not come back to $original"
      fi
    else
      fail "the RESTORE failed — the promise of reversibility does not hold here"
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "Resource limits"

if command -v nice >/dev/null && command -v ionice >/dev/null; then
  ok "nice and ionice are available (the executor will apply them)"
else
  warn "nice and/or ionice missing: the scan runs without lowering its priority"
fi

peak=$(/usr/bin/time -f '%M' sentinelhost scan --full --config "$CFG" 2>&1 >/dev/null | tail -1)
if [[ "$peak" =~ ^[0-9]+$ ]]; then
  mb=$((peak / 1024))
  if [[ "$mb" -le 128 ]]; then
    ok "the orchestrator's memory peak: ${mb} MB (promised limit: 128 MB)"
  else
    fail "a memory peak of ${mb} MB is above the 128 MB the plan promises"
  fi
fi

# ---------------------------------------------------------------------------
section "A filename the engines cannot be asked about"

# The orchestrator must COUNT it, not skip it quietly. A file nobody looked at has to be
# distinguishable from a file that was looked at and found clean — otherwise the fix
# replaced one silent coverage hole with another.
if [[ "${SH_EVASION_PLANTED:-0}" = "1" ]]; then
  ev_json=$(sentinelhost scan --config "$CONFIG" --full --json 2>/dev/null || true)
  ev_count=$(printf '%s' "$ev_json" | grep -o '"unscannable_path_name":[0-9]*' | head -1 | cut -d: -f2)
  if [[ -n "$ev_count" && "$ev_count" -ge 1 ]]; then
    ok "the unscannable path was counted ($ev_count), not dropped"
  else
    fail "a payload whose filename holds a newline was neither scanned nor counted — this is the silent coverage hole the count exists to prevent"
  fi

  # And it must not have been handed to an engine as two paths.
  if printf '%s' "$ev_json" | grep -q '"file_path":"[^"]*evasion/x"'; then
    fail "the split half of the filename reached a finding, so the list was written anyway"
  else
    ok "no half-path reached a finding"
  fi
else
  warn "the evasion payload was never planted, so this section proves nothing"
fi

section "Installer (Principle VII: installation in one command)"

# install.sh is exercised against a "release" served locally. Without this, the only
# proof that it works would be my having read the script itself — which is exactly
# the kind of verification that failed eight times in this session (D-022).
if [[ -f /opt/install.sh ]]; then
  REL=/tmp/release
  mkdir -p "$REL"
  cp /usr/local/bin/sentinelhost "$REL/sentinelhost-linux-amd64"
  ( cd "$REL" && sha256sum sentinelhost-linux-amd64 > SHA256SUMS )

  # A minimal static server, without depending on python or anything extra.
  ( cd "$REL" && exec busybox httpd -f -p 18080 ) >/dev/null 2>&1 &
  HTTPD=$!
  sleep 1

  if SENTINELHOST_BASE_URL="http://127.0.0.1:18080" \
     SENTINELHOST_PREFIX="$HOME/test-bin" \
     NO_COLOR=1 sh /opt/install.sh >/tmp/install.log 2>&1; then
    ok "install.sh installed it and the binary runs"
    grep -q "checksum matches" /tmp/install.log \
      && ok "the installer checked the checksum" \
      || fail "the installer did NOT check the checksum of what it downloaded"
  else
    fail "install.sh failed"
    sed 's/^/      /' /tmp/install.log | head -15
  fi

  # And the test that matters most: a tampered binary has to be REFUSED.
  printf 'tampered binary' > "$REL/sentinelhost-linux-amd64"
  if SENTINELHOST_BASE_URL="http://127.0.0.1:18080" \
     SENTINELHOST_PREFIX="$HOME/bad-bin" \
     NO_COLOR=1 sh /opt/install.sh >/tmp/install-bad.log 2>&1; then
    fail "the installer ACCEPTED a binary that does not match the checksum"
  else
    ok "the tampered binary was refused"
  fi

  kill "$HTTPD" 2>/dev/null || true
else
  warn "install.sh is not in the image; the installer was not exercised"
fi

# ---------------------------------------------------------------------------
section "Verdict"

if [[ "$FAILURES" -eq 0 ]] && [[ "$WARNINGS" -eq 0 ]]; then
  printf '\n  %s%sEverything passed.%s The real engines work with the adapters.\n\n' "$BOLD" "$GREEN" "$RESET"
  exit 0
fi

printf '\n  %d failure(s), %d warning(s).\n' "$FAILURES" "$WARNINGS"
if [[ "$FAILURES" -gt 0 ]]; then
  printf '  %sThe project is NOT ready for production.%s\n\n' "$RED" "$RESET"
  exit 1
fi
printf '  No failures, but check the warnings above.\n\n'
exit 0
