<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a file with 0777 permissions in a web root. The signal is the
// PERMISSION, not the content — it exercises the suspicious_perms category.
exit("inert sample from the SentinelHost corpus\n");

// The real permission is applied by the test at runtime (Git only versions the
// execute bit, not 0777), and the test skips that check on Windows. See
// DECISIONS.md D-002.

$comment = 'banal content; the finding comes from the file mode';
unset($comment);
