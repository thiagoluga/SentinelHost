<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a PHP file inside wp-content/uploads, where executable code should
// never live. The signal here is the LOCATION, not the content.
exit("inert sample from the SentinelHost corpus\n");

// The content is deliberately banal: the finding has to come from the fact that a
// .php exists in a media folder, and not from any malicious pattern in the text.
// That exercises the schema's suspicious_location category.

$comment = 'a file with nothing wrong in its content, but in the wrong place';
unset($comment);
