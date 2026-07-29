<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: an upload form with no validation whatsoever (a dropper).
exit("inert sample from the SentinelHost corpus\n");

// A real dropper would move the uploaded file into the web root without checking
// its type or extension. Here the move call does not exist: only a description of
// it.

$file_field = 'file';
$intended_destination = './';
$move_function = 'move_uploaded' . '_file';

// No call. No form HTML. No writing to disk.
$description = sprintf(
    'would move %s to %s using %s, without validating the extension',
    $file_field,
    $intended_destination,
    $move_function
);
unset($description, $file_field, $intended_destination, $move_function);
