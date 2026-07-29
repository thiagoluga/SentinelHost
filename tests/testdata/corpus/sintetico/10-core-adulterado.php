<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: arquivo do core do WordPress que NAO bate com o checksum oficial.
// E o caso de maior peso no consenso (wp-checksums, peso 1.5): core adulterado
// e quase certeza de comprometimento.
exit("amostra inerte do corpus do SentinelHost\n");

// O nome do arquivo no manifesto o coloca em wp-includes/. O conteudo imita um
// trecho de core com uma alteracao — sem nenhum efeito, porque nada executa.

function corpus_sintetico_funcao_de_core($texto)
{
    return trim((string) $texto);
}

// A "adulteracao": uma constante extra que o core oficial nao tem.
const CORPUS_SINTETICO_ALTERACAO_NAO_OFICIAL = true;
