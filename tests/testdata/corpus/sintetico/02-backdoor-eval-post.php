<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: backdoor que avalia codigo vindo de POST.
exit("amostra inerte do corpus do SentinelHost\n");

// Os nomes de funcao estao quebrados em pedacos e NUNCA sao reunidos numa
// chamada dinamica. Sem a reuniao, nao ha execucao possivel.

$avaliador = 'ev';
$avaliador_resto = 'al';
$decodificador = 'base64_de';
$decodificador_resto = 'code';
$campo = 'p';

// Um backdoor real teria algo como $f = $avaliador.$avaliador_resto; $f(...).
// Aqui os pedacos so ficam guardados, sem nenhuma chamada.
$formato_documentado = 'avaliar o retorno do decodificador sobre $_POST';
unset($avaliador, $avaliador_resto, $decodificador, $decodificador_resto, $campo);
