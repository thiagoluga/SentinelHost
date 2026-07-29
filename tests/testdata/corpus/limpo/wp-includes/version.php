<?php
/**
 * SENTINELHOST-SYNTHETIC-CORPUS (arquivo LIMPO — core oficial)
 *
 * Este arquivo representa um arquivo do core do WordPress cujo sha256 BATE com
 * o checksum oficial do WordPress.org. No teste do SC-001, o adaptador
 * wp-checksums de teste declara o hash deste arquivo em `clean_files`.
 *
 * Ele existe para provar a regra fixa do motor de veredito: arquivo identico ao
 * checksum oficial NUNCA e quarentenado, independente de quantos engines o
 * apontem. Engines dao falso positivo em arquivo legitimo com frequencia, e um
 * falso positivo no core derruba o site inteiro.
 *
 * O teste faz justamente isso: manda dois engines apontarem este arquivo com
 * confianca de assinatura (o que daria `confirmed`) e verifica que o veredito
 * sai `clean` com clean_reason=official_checksum_match.
 */

$wp_version = '6.5.2';
$wp_db_version = 57155;
$tinymce_version = '49110-20201110';
$required_php_version = '7.0.0';
$required_mysql_version = '5.5.5';
