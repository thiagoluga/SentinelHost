#!/usr/bin/env bash
#
# Validação dos engines reais numa hospedagem simulada.
#
# Este script NÃO para no primeiro erro de propósito: o objetivo é levantar
# TODOS os problemas de uma vez, não descobrir um por execução. Cada etapa
# imprime o que tentou e o que aconteceu, e no fim sai um veredito.
#
# O que ele responde, que a suíte automatizada não responde:
#   1. As flags que os adaptadores montam existem nos engines?
#   2. O engine aceita a lista de alvos, ou varre outra coisa?
#   3. A saída real bate com o que o Parse espera?
#   4. O consenso encontra as amostras do corpus com engines DE VERDADE?
#
# A pergunta 2 é a mais importante. Uma flag que o engine aceita e ignora faz
# o scan varrer o alvo errado, o Parse funcionar, e o painel mostrar
# "0 achados" com o engine marcado como saudável.

set -uo pipefail

VERMELHO=$'\033[0;31m'; VERDE=$'\033[0;32m'; AMARELO=$'\033[0;33m'
AZUL=$'\033[0;34m'; NEGRITO=$'\033[1m'; FIM=$'\033[0m'

FALHAS=0
AVISOS=0

secao()  { printf '\n%s%s== %s ==%s\n' "$NEGRITO" "$AZUL" "$1" "$FIM"; }
ok()     { printf '  %s✓%s %s\n' "$VERDE" "$FIM" "$1"; }
falha()  { printf '  %s✗%s %s\n' "$VERMELHO" "$FIM" "$1"; FALHAS=$((FALHAS+1)); }
aviso()  { printf '  %s!%s %s\n' "$AMARELO" "$FIM" "$1"; AVISOS=$((AVISOS+1)); }
info()   { printf '    %s\n' "$1"; }

SITE="$HOME/public_html"
CFG="$HOME/config.toml"

# ---------------------------------------------------------------------------
secao "Ambiente"

printf '  %-14s %s\n' "sentinelhost" "$(sentinelhost version 2>&1 | head -1)"
printf '  %-14s %s\n' "php"          "$(php -v 2>&1 | head -1 || echo AUSENTE)"
printf '  %-14s %s\n' "yara"         "$(yara --version 2>&1 | head -1 || echo AUSENTE)"
printf '  %-14s %s\n' "usuário"      "$(id -un) (uid $(id -u))"
if [ "$(id -u)" = "0" ]; then
  aviso "rodando como root: isso esconde problemas de permissão que só aparecem numa conta real"
fi

# ---------------------------------------------------------------------------
secao "Montando o site de teste"

# WordPress DE VERDADE, não um esqueleto.
#
# Com um wp-includes/version.php falso, o wp-checksums encontra 2997 arquivos
# de core ausentes e se abstém — comportamento correto, mas que deixa sem
# exercício justamente o engine de maior peso (1.5), o único que sozinho chega
# perto de `confirmed`, e com ele o caminho inteiro de quarentena.
WP_VERSAO="6.5.2"
mkdir -p "$SITE"
if curl -fsSL "https://wordpress.org/wordpress-${WP_VERSAO}.tar.gz" -o /tmp/wp.tar.gz 2>/dev/null; then
  tar -xzf /tmp/wp.tar.gz -C /tmp
  cp -r /tmp/wordpress/. "$SITE/"
  rm -rf /tmp/wordpress /tmp/wp.tar.gz
  ok "WordPress ${WP_VERSAO} real instalado ($(find "$SITE" -type f | wc -l) arquivos)"
  WP_REAL=1
else
  aviso "não foi possível baixar o WordPress; caindo para um esqueleto"
  aviso "o wp-checksums vai se abster e NÃO será exercitado nesta execução"
  mkdir -p "$SITE/wp-includes"
  cat > "$SITE/wp-includes/version.php" <<PHP
<?php
\$wp_version = '${WP_VERSAO}';
PHP
  WP_REAL=0
fi

mkdir -p "$SITE"/wp-content/{plugins/cache-helper,themes/tema/inc,uploads/2026/{03,07}}

# A adulteração do core. Dois arquivos, de propósito:
#
#  - pluggable.php recebe só uma linha inócua: apenas o wp-checksums o aponta.
#    1,50 sobre o teto 2,0 = 0,75 → `likely`. Um engine sozinho, mesmo o de
#    maior peso, NÃO chega a `confirmed` — é o desenho do consenso (D-003), e
#    esta amostra existe para travar isso.
#
#  - functions.php recebe o conteúdo de uma amostra que o AMWScan reconhece.
#    Aí são dois votos: 1,50 (checksum) + 0,64 (heurística) = 2,14, que satura
#    em 1,0 → `confirmed`. É o único caminho que autoriza quarentena
#    automática, e sem ele o caminho que justifica a ferramenta existir fica
#    sem prova.
if [ "$WP_REAL" = "1" ]; then
  echo '// SENTINELHOST-SYNTHETIC-CORPUS: linha extra que o core oficial nao tem' \
    >> "$SITE/wp-includes/pluggable.php"
  ok "core adulterado só para o checksum (wp-includes/pluggable.php → likely)"

  cat /corpus/sintetico/02-backdoor-eval-post.php >> "$SITE/wp-includes/functions.php"
  ok "core adulterado para checksum + AMWScan (wp-includes/functions.php → confirmed)"
fi

cp /corpus/limpo/base64-legitimo.php  "$SITE/wp-content/plugins/legitimo.php"
cp /corpus/limpo/util.min.js          "$SITE/wp-content/themes/tema/util.min.js"
cp /corpus/limpo/plugin-legitimo.php  "$SITE/wp-content/plugins/corpus-limpo.php"

cp /corpus/sintetico/01-webshell-parametro.php    "$SITE/wp-content/uploads/2026/07/cache.php"
cp /corpus/sintetico/02-backdoor-eval-post.php    "$SITE/wp-content/plugins/cache-helper/init.php"
cp /corpus/sintetico/03-ofuscacao-blob.php        "$SITE/wp-content/themes/tema/inc/loader.php"
cp /corpus/sintetico/04-uploader-sem-validacao.php "$SITE/up.php"
cp /corpus/sintetico/06-phishing-coleta.php       "$SITE/login.php"
cp /corpus/sintetico/09-marcador-conhecido.php    "$SITE/wp-content/uploads/2026/07/x.php"
cp /corpus/sintetico/12-shell-reverso-descrito.php "$SITE/wp-content/uploads/2026/07/conn.php"

TOTAL=$(find "$SITE" -type f | wc -l)
ok "site montado com $TOTAL arquivos ($(find "$SITE" -name '*.php' | wc -l) PHP)"

sentinelhost config init --root "$SITE" --config "$CFG" >/dev/null 2>&1 \
  && ok "configuração criada" \
  || falha "config init falhou"

# ---------------------------------------------------------------------------
secao "Probe dos engines"

sentinelhost engines --config "$CFG" 2>&1 | sed 's/^/  /'

# ---------------------------------------------------------------------------
secao "Instalação dos engines no espaço do usuário"

for eng in amwscan php-malware-finder; do
  saida=$(sentinelhost engines --install "$eng" --config "$CFG" 2>&1)
  if [ $? -eq 0 ]; then
    ok "$eng instalado"
  else
    falha "$eng NÃO instalou"
    info "$saida"
  fi
done

echo
info "arquivos instalados:"
find "$HOME/.sentinelhost/engines" -type f -printf '    %-60p %10s bytes\n' 2>/dev/null \
  || info "    (nenhum)"

# ---------------------------------------------------------------------------
secao "As flags dos adaptadores existem nos engines?"

# Esta é a etapa que a suíte automatizada não consegue fazer. Cada flag é
# testada isoladamente contra o engine real.

PHAR="$HOME/.sentinelhost/engines/amwscan/scanner.phar"
YARA_RULES="$HOME/.sentinelhost/engines/pmf/php.yar"

if [ -f "$PHAR" ]; then
  # O AMWScan morre em silêncio (exit 255, zero saída) quando falta uma
  # extensão do PHP. Se o --help não produzir nada, a checagem de flags abaixo
  # daria falso negativo em tudo — então o estado do engine vem primeiro.
  ajuda=$(php "$PHAR" --help 2>&1)
  if [ -z "$ajuda" ]; then
    falha "o AMWScan não produz saída nenhuma (exit $?): provável extensão do PHP faltando"
    info "a causa mais comum é mbstring — instale php-mbstring e repita"
  else
    ok "o AMWScan executa neste PHP"
    # As flags que o adaptador realmente monta hoje.
    for flag in --report --report-format --path-report --no-colors --silent --filter-paths --max-filesize; do
      if grep -q -- "$flag" <<<"$ajuda"; then
        ok "amwscan aceita $flag"
      else
        falha "amwscan NÃO documenta $flag — o adaptador monta uma linha inválida"
      fi
    done
    # E as que ele NÃO tem, para travar a regressão que já aconteceu uma vez.
    for inexistente in --format --filter-paths-list; do
      if grep -q -- "$inexistente" <<<"$ajuda"; then
        aviso "$inexistente passou a existir; vale reavaliar o adaptador"
      else
        ok "confirmado: $inexistente não existe (o adaptador não a usa mais)"
      fi
    done
    if grep -qi 'json' <<<"$ajuda"; then
      aviso "o AMWScan passou a mencionar JSON; o adaptador hoje lê txt"
    else
      ok "confirmado: o AMWScan não tem saída JSON (o adaptador lê txt)"
    fi
  fi
else
  falha "AMWScan ausente — não dá para conferir as flags"
fi

echo
ajuda_yara=$(yara --help 2>&1)
for flag in --no-warnings --max-strings-per-rule --scan-list; do
  if grep -q -- "$flag" <<<"$ajuda_yara"; then
    ok "yara aceita $flag"
  else
    falha "yara NÃO documenta $flag — o adaptador pmf monta uma linha inválida"
  fi
done

# ---------------------------------------------------------------------------
secao "Execução direta dos engines (linha de base)"

# Roda cada engine na mão, do jeito que ele espera, para saber o que ELE acha.
# É contra este número que o resultado do orquestrador precisa bater.

if [ -f "$PHAR" ] && [ -n "${ajuda:-}" ]; then
  php -d memory_limit=256M "$PHAR" --report --report-format txt \
      --path-report /tmp/direto --no-colors --silent "$SITE" >/dev/null 2>&1
  n_amw=$(grep -c '^File:' /tmp/direto.log 2>/dev/null || echo 0)
  info "AMWScan direto sobre a raiz: $n_amw arquivo(s) apontado(s)"
  ok "relatório real disponível em /tmp/direto.log (use como fixture nova)"
fi

if [ -f "$YARA_RULES" ]; then
  n_yara=$(yara --no-warnings -r "$YARA_RULES" "$SITE" 2>/dev/null | wc -l)
  info "yara direto sobre a raiz: $n_yara linha(s) de regra casada"
fi

# ---------------------------------------------------------------------------
secao "Ciclo completo pelo orquestrador"

saida_scan=$(sentinelhost scan --full --config "$CFG" 2>&1)
codigo=$?
echo "$saida_scan" | sed 's/^/  /'

echo
case $codigo in
  0) aviso "exit 0: o ciclo não encontrou NADA. Com 7 amostras sintéticas no site, isso é suspeito." ;;
  1) ok "exit 1: o ciclo encontrou achados" ;;
  *) falha "exit $codigo: o ciclo falhou" ;;
esac

# O teste que realmente importa: os engines rodaram, ou só se abstiveram?
if grep -q '✓' <<<"$saida_scan"; then
  ok "ao menos um engine executou de verdade"
else
  falha "NENHUM engine executou — todos se abstiveram"
  info "é exatamente isto que a suíte automatizada não consegue detectar"
fi

# E o mais perigoso de todos: o engine roda, sai verde, e o orquestrador vê
# menos do que o próprio engine viu sozinho. É a assinatura de uma flag
# aceita-e-ignorada, e foi assim que o `--filter-paths` foi pego.
#
# A comparação é contra a LINHA DE BASE, não contra zero: um engine que não
# acha nada porque o corpus é inerte demais para as regras dele está certo.
orq_amw=$(grep -oE '✓ amwscan +[0-9]+ achado' <<<"$saida_scan" | grep -oE '[0-9]+' | head -1)
orq_amw=${orq_amw:-0}
if [ "${n_amw:-0}" -gt 0 ] && [ "$orq_amw" -eq 0 ]; then
  falha "o AMWScan achou $n_amw arquivo(s) sozinho e o orquestrador viu 0"
  info "assinatura de flag aceita-e-ignorada: o engine varreu outra coisa"
elif [ "${n_amw:-0}" -gt 0 ]; then
  ok "o orquestrador viu o que o AMWScan viu sozinho ($orq_amw vs $n_amw)"
fi

orq_pmf=$(grep -oE '✓ php-malware-finder +[0-9]+ achado' <<<"$saida_scan" | grep -oE '[0-9]+' | head -1)
orq_pmf=${orq_pmf:-0}
if [ "${n_yara:-0}" -gt 0 ] && [ "$orq_pmf" -eq 0 ]; then
  falha "o yara casou $n_yara regra(s) sozinho e o orquestrador viu 0"
elif [ "${n_yara:-0}" -eq 0 ]; then
  aviso "o yara não casou nenhuma regra nem sozinho: o corpus sintético é inerte demais para o php.yar real"
  info "isso NÃO é bug do adaptador, mas significa que o pmf não está sendo exercitado de verdade aqui"
else
  ok "o orquestrador viu o que o yara viu sozinho ($orq_pmf achado(s))"
fi

# O engine de maior peso do projeto. Se ele não roda, o caminho que leva a
# `confirmed` — e portanto à quarentena automática — nunca é exercitado.
if [ "${WP_REAL:-0}" = "1" ]; then
  if grep -qE '✓ wp-checksums' <<<"$saida_scan"; then
    ok "wp-checksums executou sobre um WordPress real"
    if grep -q 'core_file_modified' <<<"$saida_scan"; then
      ok "a adulteração do core foi detectada (peso 1.50)"
    else
      falha "o core adulterado NÃO foi detectado pelo wp-checksums"
      info "é o sinal de maior peso do projeto; sem ele o consenso perde seu voto mais forte"
    fi

    # O consenso escalonando como projetado: um voto forte dá `likely`, dois
    # votos dão `confirmed`. Se essa distinção sumir, ou a ferramenta age
    # sozinha cedo demais, ou nunca age.
    if grep -q 'LIKELY.*pluggable.php' <<<"$saida_scan"; then
      ok 'um voto forte sozinho parou em likely (nao escalou para confirmed)'
    else
      falha 'o veredito de pluggable.php nao e likely: o escalonamento do consenso mudou'
    fi
    if grep -q 'CONFIRMED.*functions.php' <<<"$saida_scan"; then
      ok 'dois votos (checksum + heuristica) chegaram a confirmed'
    else
      falha 'checksum + AMWScan no mesmo arquivo NAO chegou a confirmed'
      info "é o único caminho que autoriza quarentena automática"
    fi
  else
    falha "wp-checksums se absteve mesmo com um WordPress real na raiz"
  fi
fi

# ---------------------------------------------------------------------------
secao "Quarentena com permissões POSIX de verdade"

# O round-trip já é testado na suíte, mas só aqui ele roda numa conta sem
# privilégio, com o umask e o dono de uma hospedagem real.
# O TOML é gravado com indentação (enc.Indent = "  "), então uma âncora `^`
# nunca casa. Foi assim que o modo observação continuou ligado e a quarentena
# nunca disparou nas primeiras rodadas — bug do script, não do produto.
sed -i -E 's/^[[:space:]]*observation_mode[[:space:]]*=.*/  observation_mode = false/' "$CFG"
sed -i -E 's/^[[:space:]]*grace_period_days[[:space:]]*=.*/  grace_period_days = 0/' "$CFG"

if grep -qE 'observation_mode[[:space:]]*=[[:space:]]*false' "$CFG"; then
  ok "modo observação desligado para exercitar a quarentena"
else
  falha "não foi possível desligar o modo observação no TOML"
fi

sentinelhost scan --full --config "$CFG" >/dev/null 2>&1
lista=$(sentinelhost quarantine list --config "$CFG" 2>&1)

if grep -q 'cofre esta vazio' <<<"$lista"; then
  if [ "${WP_REAL:-0}" = "1" ]; then
    # Com WordPress real e core adulterado, o consenso DEVE chegar a
    # `confirmed` e a quarentena DEVE acontecer. Se não aconteceu, o caminho
    # que justifica a ferramenta existir não funciona.
    falha "nada foi quarentenado mesmo com core adulterado e ação automática liberada"
    info "o caminho veredito -> confirmed -> quarentena reversível não fechou"
  else
    aviso "nada foi quarentenado (esperado sem um WordPress real para adulterar)"
  fi
else
  echo "$lista" | sed 's/^/  /'
  ref=$(grep -oE 'q_[0-9]+_[0-9a-f]+' <<<"$lista" | head -1)
  if [ -n "$ref" ]; then
    original=$(sentinelhost quarantine list --config "$CFG" 2>/dev/null \
      | grep "$ref" | awk '{print $NF}')

    # O arquivo saiu do lugar?
    if [ -n "$original" ] && [ ! -e "$original" ]; then
      ok "o arquivo foi movido para o cofre (não está mais no lugar)"
    fi

    if sentinelhost quarantine verify --config "$CFG" >/dev/null 2>&1; then
      ok "cofre íntegro (hashes conferem)"
    else
      falha "o cofre tem cópias que não conferem"
    fi

    # Round-trip byte a byte numa conta sem privilégio, com o umask e o dono
    # de uma hospedagem real. É a promessa que torna a automação aceitável.
    antes=""
    [ -n "$original" ] && antes=$(sentinelhost quarantine list --all --config "$CFG" 2>/dev/null | grep -c "$ref")
    if sentinelhost quarantine restore "$ref" --config "$CFG" >/dev/null 2>&1; then
      if [ -n "$original" ] && [ -f "$original" ]; then
        ok "restauração byte a byte funcionou numa conta sem privilégio"
        info "arquivo de volta em $original"
      else
        falha "o restore reportou sucesso mas o arquivo não voltou para $original"
      fi
    else
      falha "a RESTAURAÇÃO falhou — a promessa de reversibilidade não se sustenta aqui"
    fi
  fi
fi

# ---------------------------------------------------------------------------
secao "Limites de recurso"

if command -v nice >/dev/null && command -v ionice >/dev/null; then
  ok "nice e ionice disponíveis (o executor vai aplicá-los)"
else
  aviso "nice e/ou ionice ausentes: o scan roda sem rebaixar prioridade"
fi

pico=$(/usr/bin/time -f '%M' sentinelhost scan --full --config "$CFG" 2>&1 >/dev/null | tail -1)
if [[ "$pico" =~ ^[0-9]+$ ]]; then
  mb=$((pico / 1024))
  if [ "$mb" -le 128 ]; then
    ok "pico de memória do orquestrador: ${mb} MB (limite prometido: 128 MB)"
  else
    falha "pico de memória ${mb} MB acima dos 128 MB prometidos no plano"
  fi
fi

# ---------------------------------------------------------------------------
secao "Veredito"

if [ "$FALHAS" -eq 0 ] && [ "$AVISOS" -eq 0 ]; then
  printf '\n  %s%sTudo passou.%s Os engines reais funcionam com os adaptadores.\n\n' "$NEGRITO" "$VERDE" "$FIM"
  exit 0
fi

printf '\n  %d falha(s), %d aviso(s).\n' "$FALHAS" "$AVISOS"
if [ "$FALHAS" -gt 0 ]; then
  printf '  %sO projeto NÃO está pronto para produção.%s\n\n' "$VERMELHO" "$FIM"
  exit 1
fi
printf '  Nenhuma falha, mas confira os avisos acima.\n\n'
exit 0
