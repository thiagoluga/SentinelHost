<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: arquivo PHP dentro de wp-content/uploads, onde nunca deveria haver
// codigo executavel. O sinal aqui e a LOCALIZACAO, nao o conteudo.
exit("amostra inerte do corpus do SentinelHost\n");

// O conteudo e deliberadamente banal: o achado tem que vir do fato de existir
// um .php numa pasta de midia, e nao de nenhum padrao malicioso no texto.
// Isso exercita a categoria suspicious_location do esquema.

$comentario = 'arquivo sem nada de errado no conteudo, mas no lugar errado';
unset($comentario);
