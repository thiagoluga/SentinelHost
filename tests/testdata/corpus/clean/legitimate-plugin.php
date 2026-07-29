<?php
/**
 * SENTINELHOST-SYNTHETIC-CORPUS (CLEAN file)
 *
 * An ordinary WordPress plugin, with nothing wrong in it. It serves as the
 * baseline: if the consensus flags this file, the problem is in the engine, not in
 * the scanners.
 *
 * Plugin Name: Clean Corpus
 * Description: An example plugin used in SentinelHost's test corpus.
 * Version: 1.0.0
 * License: MIT
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', 'corpus_clean_register_type');

function corpus_clean_register_type()
{
    register_post_type('corpus_example', array(
        'label'        => 'Example',
        'public'       => false,
        'show_ui'      => true,
        'supports'     => array('title', 'editor'),
        'has_archive'  => false,
    ));
}

add_filter('the_content', 'corpus_clean_filter_content');

function corpus_clean_filter_content($content)
{
    if (!is_singular('corpus_example')) {
        return $content;
    }
    return $content . "\n" . '<p class="example-footer">Example content.</p>';
}
