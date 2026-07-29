<?php
// SENTINELHOST-SYNTHETIC-CORPUS
// Amostra sintetica INERTE. Ver ../AMOSTRAS.md e ../README.md.
// Simula: injecao de spam de SEO condicionada ao user-agent do buscador.
exit("amostra inerte do corpus do SentinelHost\n");

// O padrao real: mostra links de spam so quando o visitante e o robo do
// buscador, escondendo do dono do site. Aqui nao ha saida nem condicional
// executada — so os dados que caracterizam o padrao.

$alvos_de_cloaking = array('googlebot', 'bingbot', 'yandexbot');
$links_de_spam = array(
    'https://exemplo-invalido.test/produto-generico-1',
    'https://exemplo-invalido.test/produto-generico-2',
    'https://exemplo-invalido.test/produto-generico-3',
);
$estilo_de_ocultacao = 'position:absolute;left:-9999px';

// Nenhum echo, nenhuma comparacao com $_SERVER, nenhuma escrita.
unset($alvos_de_cloaking, $links_de_spam, $estilo_de_ocultacao);
