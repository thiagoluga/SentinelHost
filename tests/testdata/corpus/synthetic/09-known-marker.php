<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a file with a KNOWN signature, the case where an engine votes with
// confidence=signature. It is the EICAR equivalent for this project's corpus: an
// agreed marker, with no behaviour at all.
exit("inert sample from the SentinelHost corpus\n");

// This marker is not a real malware signature. It exists so the test adapters have
// something deterministic to "recognize", the same way EICAR exists to test an
// antivirus without using a virus.
const SENTINELHOST_CORPUS_SIGNATURE_MARKER = 'SENTINELHOST-CORPUS-SIGNATURE-TEST-FILE';

$simulated_family = 'FictitiousFamily.Corpus.A';
unset($simulated_family);
