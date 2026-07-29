<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: formulario de upload sem nenhuma validacao (dropper).
exit("amostra inerte do corpus do SentinelHost\n");

// Um dropper real moveria o arquivo enviado para dentro da raiz web sem
// checar tipo nem extensao. Aqui a chamada de movimentacao nao existe: so a
// descricao dela.

$campo_de_arquivo = 'arquivo';
$destino_pretendido = './';
$funcao_de_movimentacao = 'move_uploaded' . '_file';

// Sem chamada. Sem HTML de formulario. Sem escrita em disco.
$descricao = sprintf(
    'moveria %s para %s usando %s, sem validar extensao',
    $campo_de_arquivo,
    $destino_pretendido,
    $funcao_de_movimentacao
);
unset($descricao, $campo_de_arquivo, $destino_pretendido, $funcao_de_movimentacao);
