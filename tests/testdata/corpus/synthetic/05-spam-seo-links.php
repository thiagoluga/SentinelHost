<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// INERT synthetic sample. See ../SAMPLES.md and ../README.md.
// Simulates: SEO spam injection conditioned on the crawler's user agent.
exit("inert sample from the SentinelHost corpus\n");

// The real pattern: it shows spam links only when the visitor is the search
// engine's crawler, hiding them from the site's owner. Here there is no output and
// no conditional that runs — only the data that characterizes the pattern.

$cloaking_targets = array('googlebot', 'bingbot', 'yandexbot');
$spam_links = array(
    'https://invalid-example.test/generic-product-1',
    'https://invalid-example.test/generic-product-2',
    'https://invalid-example.test/generic-product-3',
);
$hiding_style = 'position:absolute;left:-9999px';

// No echo, no comparison against $_SERVER, no writing.
unset($cloaking_targets, $spam_links, $hiding_style);
