<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a WordPress core file that does NOT match the official checksum.
// It is the highest-weight case in the consensus (wp-checksums, weight 1.5): a
// tampered core is almost certainly a compromise.
exit("inert sample from the SentinelHost corpus\n");

// The file's name in the manifest places it under wp-includes/. The content
// imitates a core snippet with one alteration — with no effect at all, because
// nothing runs.

function corpus_synthetic_core_function($text)
{
    return trim((string) $text);
}

// The "tampering": an extra constant the official core does not have.
const CORPUS_SYNTHETIC_UNOFFICIAL_ALTERATION = true;
