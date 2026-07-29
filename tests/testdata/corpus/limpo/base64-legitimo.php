<?php
/**
 * SENTINELHOST-SYNTHETIC-CORPUS (arquivo LIMPO)
 *
 * PHP legitimo que usa base64_encode para o que ele serve: embutir uma imagem
 * pequena como data URI. Scanner de malware costuma marcar qualquer base64
 * como suspeito, e esse e um dos falsos positivos mais comuns em sites reais.
 *
 * Apontar este arquivo como `confirmed` reprova o SC-001.
 */

function corpus_limpo_data_uri($caminho_da_imagem)
{
    if (!is_readable($caminho_da_imagem)) {
        return '';
    }

    $conteudo = file_get_contents($caminho_da_imagem);
    if ($conteudo === false) {
        return '';
    }

    $tipo = 'image/png';
    return 'data:' . $tipo . ';base64,' . base64_encode($conteudo);
}

function corpus_limpo_assinar_payload(array $dados, $segredo)
{
    $json = json_encode($dados, JSON_UNESCAPED_SLASHES);
    return base64_encode(hash_hmac('sha256', $json, $segredo, true));
}
