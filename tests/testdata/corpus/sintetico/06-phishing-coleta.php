<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: pagina de phishing que coleta credenciais e envia para fora.
exit("amostra inerte do corpus do SentinelHost\n");

// O padrao real: clona a tela de login de um banco, captura usuario e senha e
// manda por e-mail ou HTTP para o operador. Esta amostra nao imprime HTML, nao
// le entrada e nao faz rede.

$campos_alvo = array('usuario', 'senha', 'agencia', 'conta');
$destino_exfiltracao = 'operador@exemplo-invalido.test';
$assunto_documentado = 'novo resultado';
$marca_imitada = 'Banco Generico (fictício)';

// A funcao de envio nem sequer e referenciada por nome completo.
$fragmento_envio = 'ma' . 'il';
unset($campos_alvo, $destino_exfiltracao, $assunto_documentado, $marca_imitada, $fragmento_envio);
