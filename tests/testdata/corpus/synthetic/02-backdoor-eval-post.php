<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a backdoor evaluating code coming from POST.
exit("inert sample from the SentinelHost corpus\n");

// The function names are broken into pieces and are NEVER joined into a dynamic
// call. Without the joining, no execution is possible.

$evaluator = 'ev';
$evaluator_rest = 'al';
$decoder = 'base64_de';
$decoder_rest = 'code';
$field = 'p';

// A real backdoor would have something like $f = $evaluator . $evaluator_rest,
// then $f(...). Here the pieces are only stored, with no call at all.
$documented_shape = 'evaluate the decoder output over $_POST';
unset($evaluator, $evaluator_rest, $decoder, $decoder_rest, $field);
