<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a reverse shell. This is the sample that needs the most care, so it
// is the one with the least code: only the configuration DATA that characterizes
// the pattern, with no network or process primitive at all.
exit("inert sample from the SentinelHost corpus\n");

// There is no socket, no fsockopen, no proc_open, no redirected file descriptor.
// A reverse shell needs all three; none of them appears here, not even broken into
// pieces.

$documented_address = '203.0.113.10'; // TEST-NET-3 range, not routable
$documented_port = 4444;
$description = 'would connect back to the operator and hand over a shell';

unset($documented_address, $documented_port, $description);
