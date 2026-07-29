<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: injecao de uma linha no fim de um arquivo legitimo de tema WP.
exit("amostra inerte do corpus do SentinelHost\n");

/**
 * Trecho legitimo de um footer de tema, para que a amostra pareca um arquivo
 * real com UMA linha injetada — que e como a maioria das infeccoes de
 * WordPress se apresenta.
 */
function corpus_sintetico_rodape_do_tema()
{
    return '<footer class="rodape"><p>Site de exemplo</p></footer>';
}

// A "injecao": referencia a um include remoto que nao existe e nunca e
// chamado. Sem include, sem require, sem rede.
$linha_injetada_documentada = 'incluiria https://exemplo-invalido.test/x.txt';
unset($linha_injetada_documentada);
