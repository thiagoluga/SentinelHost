<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: arquivo com permissao 0777 numa raiz web. O sinal e a PERMISSAO,
// nao o conteudo — exercita a categoria suspicious_perms.
exit("amostra inerte do corpus do SentinelHost\n");

// A permissao real e aplicada pelo teste em tempo de execucao (o Git so
// versiona o bit de execucao, nao 0777), e o teste pula essa verificacao no
// Windows. Ver DECISIONS.md D-002.

$comentario = 'conteudo banal; o achado vem do modo do arquivo';
unset($comentario);
