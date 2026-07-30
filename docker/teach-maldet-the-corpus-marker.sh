#!/usr/bin/env bash
#
# Teach the installed maldet ONE signature for this repository's own inert marker file.
#
# Why this exists: maldet loads ~51,000 real signatures and finds NOTHING in
# tests/testdata/corpus. The samples are inert by construction, and Principle VI forbids
# putting real executable malware in the repository to change that. With zero hits, the
# half of the adapter that matters is never reached — no hit-line parsing, no `{MD5}`
# type mapping, and above all no proof that `--config-option quarantine_hits=0` really
# stops maldet from moving the user's files somewhere our vault cannot restore from.
#
# maldet's detection quality is not under test here. Its behaviour when it DOES hit
# something is.
#
# MD5 and not HEX, because MD5 is the path maldet resolves itself:
#
#	val_hash=`grep -m1 $hash $sig_user_md5_file $sig_md5_file`
#
# HEX matching goes through a perl fifo and, in this image, a ClamAV that is not
# installed: a custom hex string is loaded, counted in maldet's "1 USER" total, and never
# matched. Loaded-but-never-matched is this project's own worst failure mode wearing
# maldet's clothes.
set -euo pipefail

SAMPLE="${1:-/corpus/synthetic/09-known-marker.php}"
SIGS=/usr/local/maldetect/sigs/custom.md5.dat

if [[ ! -f "$SAMPLE" ]]; then
  echo "the marker sample is missing: $SAMPLE" >&2
  exit 1
fi

# The format is maldet's own, from the shipped sigs/md5v2.dat:
#
#	<md5>:<size>:{MD5}<name>
#
# MD5 here is a wire format, not a security choice. Nothing is authenticated with it, the
# file it identifies is a synthetic marker committed to this repository, and a stronger
# digest would simply never match anything maldet compares.
md5=$(md5sum "$SAMPLE" | cut -d' ' -f1)  # NOSONAR - maldet's signature format mandates MD5
size=$(stat -c%s "$SAMPLE")

printf '%s:%s:{MD5}php.corpus.marker.v1\n' "$md5" "$size" > "$SIGS"
chmod 0644 "$SIGS"

echo "taught maldet: $(cat "$SIGS")"
