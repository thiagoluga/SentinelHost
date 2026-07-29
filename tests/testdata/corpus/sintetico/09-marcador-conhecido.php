<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: arquivo com assinatura CONHECIDA, o caso em que um engine vota com
// confidence=signature. E o equivalente ao EICAR para o corpus deste projeto:
// um marcador acordado, sem nenhum comportamento.
exit("amostra inerte do corpus do SentinelHost\n");

// Este marcador nao e uma assinatura de malware real. Ele existe para que os
// adaptadores de teste tenham algo deterministico para "reconhecer", do mesmo
// jeito que o EICAR existe para testar antivirus sem usar virus.
const SENTINELHOST_CORPUS_MARCADOR_ASSINATURA = 'SENTINELHOST-CORPUS-SIGNATURE-TEST-FILE';

$familia_simulada = 'FamiliaFicticia.Corpus.A';
unset($familia_simulada);
