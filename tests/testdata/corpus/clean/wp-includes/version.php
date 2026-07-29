<?php
/**
 * SENTINELHOST-SYNTHETIC-CORPUS (CLEAN file — official core)
 *
 * This file represents a WordPress core file whose sha256 MATCHES the official
 * WordPress.org checksum. In the SC-001 test, the test wp-checksums adapter
 * declares this file's hash in `clean_files`.
 *
 * It exists to prove the verdict engine's fixed rule: a file identical to the
 * official checksum is NEVER quarantined, no matter how many engines flag it.
 * Engines produce false positives on legitimate files often, and one false positive
 * in the core takes the whole site down.
 *
 * The test does exactly that: it makes two engines flag this file with signature
 * confidence (which would give `confirmed`) and verifies that the verdict comes out
 * `clean` with clean_reason=official_checksum_match.
 */

$wp_version = '6.5.2';
$wp_db_version = 57155;
$tinymce_version = '49110-20201110';
$required_php_version = '7.0.0';
$required_mysql_version = '5.5.5';
