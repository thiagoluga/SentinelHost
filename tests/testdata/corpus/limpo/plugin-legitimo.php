<?php
/**
 * SENTINELHOST-SYNTHETIC-CORPUS (arquivo LIMPO)
 *
 * Plugin WordPress comum, sem nada de errado. Serve de linha de base: se o
 * consenso apontar este arquivo, o problema esta no motor, nao nos engines.
 *
 * Plugin Name: Corpus Limpo
 * Description: Plugin de exemplo usado no corpus de teste do SentinelHost.
 * Version: 1.0.0
 * License: MIT
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', 'corpus_limpo_registrar_tipo');

function corpus_limpo_registrar_tipo()
{
    register_post_type('corpus_exemplo', array(
        'label'        => 'Exemplo',
        'public'       => false,
        'show_ui'      => true,
        'supports'     => array('title', 'editor'),
        'has_archive'  => false,
    ));
}

add_filter('the_content', 'corpus_limpo_filtrar_conteudo');

function corpus_limpo_filtrar_conteudo($conteudo)
{
    if (!is_singular('corpus_exemplo')) {
        return $conteudo;
    }
    return $conteudo . "\n" . '<p class="rodape-exemplo">Conteudo de exemplo.</p>';
}
