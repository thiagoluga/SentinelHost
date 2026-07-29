#!/bin/sh
# SentinelHost installer.
#
#   curl -fsSL https://raw.githubusercontent.com/thiagoluga/SentinelHost/main/install.sh | sh
#
# Principle VII: installation in one command. No root, no package manager, no
# dependency beyond `curl` (or `wget`) and `sha256sum` — which is what a shared
# hosting account has.
#
# POSIX sh on purpose: the `sh` of many hosting accounts is dash or busybox, not
# bash. An installer that requires bash fails in precisely the environment this
# project exists to serve.
#
# The checksum verification is NOT optional. A security tool's installer that runs
# what it downloaded without checking would be a contradiction — and `curl | sh`
# already asks for enough trust without that.

set -eu

REPO="thiagoluga/SentinelHost"
BIN="sentinelhost"

# Overridable for testing: this is how the validation container exercises this
# script without depending on a published release.
BASE_URL="${SENTINELHOST_BASE_URL:-https://github.com/${REPO}/releases/latest/download}"
PREFIX="${SENTINELHOST_PREFIX:-$HOME/bin}"

# --- output -----------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  GREEN=$(printf '\033[0;32m'); RED=$(printf '\033[0;31m')
  YELLOW=$(printf '\033[0;33m'); RESET=$(printf '\033[0m')
else
  GREEN=''; RED=''; YELLOW=''; RESET=''
fi

ok()    { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }
err()   { printf '  %s✗%s %s\n' "$RED" "$RESET" "$1" >&2; }
die()   { err "$1"; exit 1; }

# --- prerequisites ----------------------------------------------------------

download() {
  # $1 = url, $2 = destination
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    die "I need curl or wget to download the binary"
  fi
}

checksum_of() {
  # Prints the sha256 of $1. The command's name varies between distributions.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    echo ""
  fi
}

# --- architecture -----------------------------------------------------------

printf '\nSentinelHost — installer\n\n'

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
  die "this installer only covers Linux (detected: $OS).
    To develop on another system, build with: make build"
fi

case "$(uname -m)" in
  x86_64 | amd64)         ARCH=amd64 ;;
  aarch64 | arm64)        ARCH=arm64 ;;
  *) die "there is no published binary for the $(uname -m) architecture.
    Build from source with: make build" ;;
esac
ok "linux/$ARCH"

FILE="${BIN}-linux-${ARCH}"

# --- download ---------------------------------------------------------------

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t sentinelhost)
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT INT TERM

printf '  downloading %s...\n' "$FILE"
download "${BASE_URL}/${FILE}" "${TMP}/${BIN}" \
  || die "the download failed. Has the release been published at
    https://github.com/${REPO}/releases ?"

SIZE=$(wc -c < "${TMP}/${BIN}" | tr -d ' ')
[ "$SIZE" -gt 1000000 ] \
  || die "the downloaded file is only ${SIZE} bytes: it is probably an error
    page, not the binary"
ok "downloaded ($((SIZE / 1024 / 1024)) MB)"

# --- verification -----------------------------------------------------------

# Verifying what you are about to run is the minimum for a security tool. If
# SHA256SUMS is not available, the installation STOPS: carrying on with an unchecked
# binary would ask the user for exactly the blind trust the project says it does not
# ask for.
if ! download "${BASE_URL}/SHA256SUMS" "${TMP}/SHA256SUMS" 2>/dev/null; then
  die "could not download SHA256SUMS.
    Installing without checking the binary is not an option in a security tool.
    Download it manually from https://github.com/${REPO}/releases and check by hand."
fi

EXPECTED=$(grep " ${FILE}\$" "${TMP}/SHA256SUMS" | cut -d' ' -f1 || true)
[ -n "$EXPECTED" ] || die "SHA256SUMS does not list ${FILE}"

GOT=$(checksum_of "${TMP}/${BIN}")
if [ -z "$GOT" ]; then
  # With no hashing tool there is no way to check. Warn loudly instead of
  # pretending it was checked.
  warn "no sha256sum nor shasum: the binary could NOT be checked"
  warn "expected hash: ${EXPECTED}"
elif [ "$GOT" != "$EXPECTED" ]; then
  die "the binary does NOT match the published checksum.
    expected: ${EXPECTED}
    got:      ${GOT}
    Do not install it. This means the download was corrupted or tampered with."
else
  ok "checksum matches"
fi

# --- installation -----------------------------------------------------------

mkdir -p "$PREFIX" || die "could not create $PREFIX"
chmod +x "${TMP}/${BIN}"

# Move it and check that it runs. An installed binary that does not run (an
# incompatible glibc, noexec on the directory) has to fail here, not on the first
# cron run.
mv "${TMP}/${BIN}" "${PREFIX}/${BIN}" || die "could not install into $PREFIX"
if ! "${PREFIX}/${BIN}" version >/dev/null 2>&1; then
  die "the binary was installed but does not run at ${PREFIX}/${BIN}.
    A common cause: the directory is mounted with noexec. Try another path:
      SENTINELHOST_PREFIX=\$HOME/.local/bin sh install.sh"
fi
ok "installed at ${PREFIX}/${BIN} ($("${PREFIX}/${BIN}" version))"

# --- PATH -------------------------------------------------------------------

case ":${PATH}:" in
  *":${PREFIX}:"*) ;;
  *)
    warn "${PREFIX} is not on your PATH"
    printf '    add this to ~/.bashrc or ~/.profile:\n'
    printf '      export PATH="%s:$PATH"\n' "$PREFIX"
    ;;
esac

# --- next steps -------------------------------------------------------------

cat <<END_MSG

Next steps:

  ${BIN} config init --root ~/public_html
  ${BIN} doctor          # shows WHY each engine is or is not available
  ${BIN} scan            # exit 0 = nothing; 1 = found; 2 = error; 3 = already running

The defaults are conservative: observation mode on and a 7-day grace period, so the
tool reports before it touches any file of yours.

To leave it running without SSH:

  ${BIN} cron-line       # a line ready for the cPanel cron

END_MSG
