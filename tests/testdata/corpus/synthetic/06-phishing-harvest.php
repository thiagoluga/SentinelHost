<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: a phishing page that harvests credentials and sends them out.
exit("inert sample from the SentinelHost corpus\n");

// The real pattern: it clones a bank's login screen, captures the username and
// password and sends them by e-mail or HTTP to the operator. This sample prints no
// HTML, reads no input and makes no network call.

$target_fields = array('username', 'password', 'branch', 'account');
$exfiltration_destination = 'operator@invalid-example.test';
$documented_subject = 'new result';
$imitated_brand = 'Generic Bank (fictitious)';

// The sending function is not even referenced by its full name.
$send_fragment = 'ma' . 'il';
unset($target_fields, $exfiltration_destination, $documented_subject, $imitated_brand, $send_fragment);
