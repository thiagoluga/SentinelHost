<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: one line injected at the end of a legitimate WP theme file.
exit("inert sample from the SentinelHost corpus\n");

/**
 * A legitimate snippet from a theme footer, so the sample looks like a real file
 * with ONE injected line — which is how most WordPress infections present
 * themselves.
 */
function corpus_synthetic_theme_footer()
{
    return '<footer class="footer"><p>Example site</p></footer>';
}

// The "injection": a reference to a remote include that does not exist and is
// never called. No include, no require, no network.
$documented_injected_line = 'would include https://invalid-example.test/x.txt';
unset($documented_injected_line);
