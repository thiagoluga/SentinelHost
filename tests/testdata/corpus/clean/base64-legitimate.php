<?php
/**
 * SENTINELHOST-SYNTHETIC-CORPUS (CLEAN file)
 *
 * Legitimate PHP that uses base64_encode for what it is meant for: embedding a
 * small image as a data URI. A malware scanner tends to flag any base64 as
 * suspicious, and that is one of the most common false positives on real sites.
 *
 * Flagging this file as `confirmed` fails SC-001.
 */

function corpus_clean_data_uri($image_path)
{
    if (!is_readable($image_path)) {
        return '';
    }

    $content = file_get_contents($image_path);
    if ($content === false) {
        return '';
    }

    $type = 'image/png';
    return 'data:' . $type . ';base64,' . base64_encode($content);
}

function corpus_clean_sign_payload(array $data, $secret)
{
    $json = json_encode($data, JSON_UNESCAPED_SLASHES);
    return base64_encode(hash_hmac('sha256', $json, $secret, true));
}
