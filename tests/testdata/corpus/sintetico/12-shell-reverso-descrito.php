<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: shell reverso. Esta e a amostra que mais precisa de cuidado, entao e
// a que menos codigo tem: apenas os DADOS de configuracao que caracterizam o
// padrao, sem nenhuma primitiva de rede ou de processo.
exit("amostra inerte do corpus do SentinelHost\n");

// Nao ha socket, nao ha fsockopen, nao ha proc_open, nao ha descritor de
// arquivo redirecionado. Um shell reverso precisa das tres coisas; nenhuma
// delas aparece aqui, nem quebrada em pedacos.

$endereco_documentado = '203.0.113.10'; // faixa TEST-NET-3, nao roteavel
$porta_documentada = 4444;
$descricao = 'conectaria de volta ao operador e entregaria um shell';

unset($endereco_documentado, $porta_documentada, $descricao);
