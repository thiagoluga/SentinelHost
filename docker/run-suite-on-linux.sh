#!/usr/bin/env bash
# Run the Go suite on Linux and prove the POSIX-only tests were not skipped.
#
# `go test ./...` passing is not the question. The question is whether the tests that only
# mean something on Linux actually executed — and without -v, a skip and a pass are the
# same line. This repository has already shipped two defects that a green Windows suite
# said nothing about (an unrestorable quarantine vault, and .gitignore swallowing
# cmd/sentinelhost/), so "it passed" is not an answer on its own.
set -euo pipefail

IMAGE=sentinelhost-suite
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Docker needs a path IT understands. On Git Bash for Windows `pwd` prints /c/repos/…,
# which the daemon reads as a relative Linux path and mounts as an empty directory — the
# suite then fails with "directory prefix . does not contain main module", which reads as
# a broken checkout rather than as a path that never arrived.
if command -v cygpath >/dev/null 2>&1; then
  MOUNT_SRC="$(cygpath -m "$REPO_ROOT")"
else
  MOUNT_SRC="$REPO_ROOT"
fi

# The tests that skip on Windows, named. Adding one here is what makes it impossible to
# lose again: if the name stops matching a test, the grep below fails the run rather than
# quietly checking nothing.
POSIX_ONLY=(
  TestAHardLinkedFileIsNotQuarantinedSilently
  TestASymlinkIsRefusedRatherThanUnlinked
  TestAPathOutsideTheRootsIsRefused
)

echo "==> building $IMAGE"
docker build -q -f "$REPO_ROOT/docker/Dockerfile.test" -t "$IMAGE" "$REPO_ROOT" >/dev/null

# A named volume for the caches: without it every run re-downloads the module cache, and a
# check that is slow is a check that gets skipped.
docker volume create sentinelhost-suite-cache >/dev/null

run() {
  docker run --rm \
    -v "$MOUNT_SRC:/src:ro" \
    -v sentinelhost-suite-cache:/home/suite/.cache \
    "$IMAGE" "$1"
}

echo "==> the whole suite, on Linux"
run "go test ./... -count=1"

echo
echo "==> the tests that skip on a Windows workstation"
log=$(run "go test ./internal/quarantine/ -count=1 -v -run '$(IFS='|'; echo "${POSIX_ONLY[*]}")'")
echo "$log" | grep -E '^(---|=== RUN)' || true

failed=0
for name in "${POSIX_ONLY[@]}"; do
  if grep -q -- "--- PASS: $name" <<<"$log"; then
    echo "  ok      $name"
  elif grep -q -- "--- SKIP: $name" <<<"$log"; then
    echo "  SKIPPED $name — on Linux this should not happen; the environment is wrong"
    failed=1
  else
    echo "  MISSING $name — the test was renamed or removed, and this check has been"
    echo "          silently verifying nothing since"
    failed=1
  fi
done

if [[ $failed -ne 0 ]]; then
  echo
  echo "The POSIX-only tests did not all run. A green suite that skipped them is exactly"
  echo "the evidence this script exists to refuse."
  exit 1
fi

echo
echo "The suite passed on Linux, and the POSIX-only tests ran rather than skipping."
