<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: webshell que recebe comando por parametro de requisicao.
exit("amostra inerte do corpus do SentinelHost\n");

// Nada abaixo desta linha executa. Alem disso, os fragmentos nunca sao
// concatenados numa chamada: eles existem como strings soltas, para que a
// ESTRUTURA do padrao esteja presente sem que exista um webshell funcional.

$parametro_esperado = 'cmd';
$fragmento_execucao = 'sys' . 'tem';
$fragmento_alternativo = 'she' . 'll_exec';
$origem_do_comando = '$_REQUEST[' . $parametro_esperado . ']';

// Um webshell real faria a chamada aqui. Esta amostra so descreve o formato:
$descricao = 'chamaria ' . $fragmento_execucao . ' com ' . $origem_do_comando;
unset($descricao, $fragmento_alternativo);
