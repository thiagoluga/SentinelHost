#!/bin/sh
# SentinelHost task runner for a cPanel account with no interactive shell.
#
# The cron calls THIS file and nothing else. What actually runs lives in task.sh,
# which you replace whenever there is new work to do.
#
# It runs a given task.sh EXACTLY ONCE. The cron can stay installed forever without
# repeating the same commands every fifteen minutes: the runner remembers a fingerprint
# of the last task it executed and exits silently when nothing changed. Upload a new
# task.sh and it runs on the next tick.
#
# Layout it expects:
#
#   ~/sentinelhost/
#   |-- runner.sh      this file            (chmod 0700)
#   |-- task.sh        the work to do       (chmod 0600)
#   |-- run.log        output, newest first (created here)
#   |-- .last-task     fingerprint bookkeeping
#   |-- bin/sentinelhost
#   `-- data/
#
# POSIX sh on purpose: cPanel's jailshell is not bash.
#
# SECURITY. This file is executed by cron on a schedule, and task.sh is executed by it.
# Anyone who can write to either has arbitrary code execution on this account. That is
# the whole point of the mechanism and also its whole risk. Two consequences:
#
#   - Keep both out of the document root. Under public_html they are reachable over the
#     web, and a file the web can reach that cron will execute is a backdoor with a URL.
#   - Delete the cron entry when the work is done. A permanently installed execution
#     channel is worth having only while someone is actually using it.

set -u

BASE=$(cd "$(dirname "$0")" && pwd)
TASK="$BASE/task.sh"
LOG="$BASE/run.log"
STAMP="$BASE/.last-task"
LOCK="$BASE/.runner.lock"

# Nothing to do.
[ -f "$TASK" ] || exit 0

# Fingerprint the task so the same one does not run on every tick.
#
# This answers "is this the same file I already ran?", not "can I trust this file?" —
# trust comes from the 0600 permissions and from the account it lives in. sha256sum all
# the same: it is present wherever sha1sum is, costs nothing here, and a weak-hash
# warning in a security tool's own tooling is a distraction nobody should have to
# re-litigate later.
#
# The fallback exists because a stripped-down shared host may have neither. Size plus
# mtime is a weaker fingerprint, and enough: the only thing that changes this file is
# you uploading a new one.
if command -v sha256sum >/dev/null 2>&1; then
  FINGERPRINT=$(sha256sum "$TASK" | cut -d' ' -f1)
else
  FINGERPRINT=$(ls -ln "$TASK" | awk '{print $5}')-$(ls -ln --time-style=+%s "$TASK" 2>/dev/null | awk '{print $6}')
fi

if [ -f "$STAMP" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$FINGERPRINT" ]; then
  exit 0
fi

# One at a time. A task that outlives its fifteen-minute window must not have a second
# copy of itself start on top of it — two scans sharing one SQLite database and one
# quarantine vault is not a situation worth debugging remotely.
if ! mkdir "$LOCK" 2>/dev/null; then
  printf '%s  a previous task is still running; skipping this tick\n' "$(date)" >> "$LOG"
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM

# Record the fingerprint BEFORE running, not after.
#
# If the task crashes the account or hits a resource limit, it must not run again on the
# next tick and crash it again. A task that failed has still been attempted, and
# repeating it automatically turns one bad command into a loop.
printf '%s' "$FINGERPRINT" > "$STAMP"

{
  printf '\n===============================================================\n'
  printf 'task started : %s\n' "$(date)"
  printf 'fingerprint  : %s\n' "$FINGERPRINT"
  printf 'shell        : %s\n' "${SHELL:-unknown}"
  printf 'user         : %s\n' "$(id -un 2>/dev/null || echo unknown)"
  printf '===============================================================\n'
} >> "$LOG"

# The task runs from BASE so it can use short relative paths, with stdout and stderr
# both captured. Silence is not evidence of success, so the exit code is always recorded
# even when the task printed nothing at all.
cd "$BASE" || exit 1
sh "$TASK" >> "$LOG" 2>&1
CODE=$?

{
  printf '\n--- task finished with exit code %d at %s\n' "$CODE" "$(date)"
} >> "$LOG"

# Keep the log from growing without bound. This account is not being monitored for disk
# use by anyone watching it closely, and a runaway log on shared hosting is its own
# small outage.
if [ -f "$LOG" ]; then
  LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  if [ "$LINES" -gt 4000 ]; then
    tail -n 2000 "$LOG" > "$LOG.trim" 2>/dev/null && mv "$LOG.trim" "$LOG"
    printf '(log trimmed to the last 2000 lines)\n' >> "$LOG"
  fi
fi

exit 0
