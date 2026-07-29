<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a webshell taking a command from a request parameter.
exit("inert sample from the SentinelHost corpus\n");

// Nothing below this line runs. Beyond that, the fragments are never concatenated
// into a call: they exist as loose strings, so the STRUCTURE of the pattern is
// present without there being a working webshell.

$expected_parameter = 'cmd';
$execution_fragment = 'sys' . 'tem';
$alternative_fragment = 'she' . 'll_exec';
$command_source = '$_REQUEST[' . $expected_parameter . ']';

// A real webshell would make the call here. This sample only describes the shape:
$description = 'would call ' . $execution_fragment . ' with ' . $command_source;
unset($description, $alternative_fragment);
