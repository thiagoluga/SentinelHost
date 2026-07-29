#!/bin/sh
# Instalador do SentinelHost.
#
#   curl -fsSL https://raw.githubusercontent.com/thiagoluga/SentinelHost/main/install.sh | sh
#
# Princípio VII: instalação em um comando. Sem root, sem gerenciador de
# pacotes, sem dependência além de `curl` (ou `wget`) e `sha256sum` — que é o
# que uma conta de hospedagem compartilhada tem.
#
# POSIX sh de propósito: o `sh` de muitas hospedagens é dash ou busybox, não
# bash. Um instalador que exige bash falha justamente no ambiente que este
# projeto existe para atender.
#
# A verificação de checksum NÃO é opcional. Um instalador de ferramenta de
# segurança que executa o que baixou sem conferir seria uma contradição — e
# `curl | sh` já pede confiança suficiente sem isso.

set -eu

REPO="thiagoluga/SentinelHost"
BIN="sentinelhost"

# Sobreponíveis para teste: é assim que o container de validação exercita este
# script sem depender de um release publicado.
BASE_URL="${SENTINELHOST_BASE_URL:-https://github.com/${REPO}/releases/latest/download}"
PREFIX="${SENTINELHOST_PREFIX:-$HOME/bin}"

# --- saída ------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  VERDE=$(printf '\033[0;32m'); VERMELHO=$(printf '\033[0;31m')
  AMARELO=$(printf '\033[0;33m'); FIM=$(printf '\033[0m')
else
  VERDE=''; VERMELHO=''; AMARELO=''; FIM=''
fi

ok()    { printf '  %s✓%s %s\n' "$VERDE" "$FIM" "$1"; }
aviso() { printf '  %s!%s %s\n' "$AMARELO" "$FIM" "$1"; }
erro()  { printf '  %s✗%s %s\n' "$VERMELHO" "$FIM" "$1" >&2; }
morrer() { erro "$1"; exit 1; }

# --- pré-requisitos ---------------------------------------------------------

baixar() {
  # $1 = url, $2 = destino
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    morrer "preciso de curl ou wget para baixar o binario"
  fi
}

somar() {
  # Imprime o sha256 de $1. Nome do comando varia entre distribuições.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    echo ""
  fi
}

# --- arquitetura ------------------------------------------------------------

printf '\nSentinelHost — instalador\n\n'

SO=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$SO" != "linux" ]; then
  morrer "este instalador so cobre Linux (detectado: $SO).
    Para desenvolver em outro sistema, compile com: make build"
fi

case "$(uname -m)" in
  x86_64 | amd64)         ARCH=amd64 ;;
  aarch64 | arm64)        ARCH=arm64 ;;
  *) morrer "arquitetura $(uname -m) nao tem binario publicado.
    Compile do fonte com: make build" ;;
esac
ok "linux/$ARCH"

ARQUIVO="${BIN}-linux-${ARCH}"

# --- download ---------------------------------------------------------------

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t sentinelhost)
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT INT TERM

printf '  baixando %s...\n' "$ARQUIVO"
baixar "${BASE_URL}/${ARQUIVO}" "${TMP}/${BIN}" \
  || morrer "download falhou. A release ja foi publicada em
    https://github.com/${REPO}/releases ?"

TAMANHO=$(wc -c < "${TMP}/${BIN}" | tr -d ' ')
[ "$TAMANHO" -gt 1000000 ] \
  || morrer "o arquivo baixado tem so ${TAMANHO} bytes: provavelmente e uma
    pagina de erro, nao o binario"
ok "baixado ($((TAMANHO / 1024 / 1024)) MB)"

# --- verificação ------------------------------------------------------------

# Verificar o que se vai executar é o mínimo para uma ferramenta de segurança.
# Se o SHA256SUMS não estiver disponível, a instalação PARA: seguir em frente
# com um binário não conferido seria pedir ao usuário exatamente a confiança
# cega que o projeto diz não pedir.
if ! baixar "${BASE_URL}/SHA256SUMS" "${TMP}/SHA256SUMS" 2>/dev/null; then
  morrer "nao foi possivel baixar SHA256SUMS.
    Instalar sem conferir o binario nao e uma opcao numa ferramenta de seguranca.
    Baixe manualmente de https://github.com/${REPO}/releases e confira a mao."
fi

ESPERADO=$(grep " ${ARQUIVO}\$" "${TMP}/SHA256SUMS" | cut -d' ' -f1 || true)
[ -n "$ESPERADO" ] || morrer "SHA256SUMS nao lista ${ARQUIVO}"

OBTIDO=$(somar "${TMP}/${BIN}")
if [ -z "$OBTIDO" ]; then
  # Sem ferramenta de hash não dá para conferir. Avisa alto em vez de fingir
  # que conferiu.
  aviso "sem sha256sum nem shasum: NAO foi possivel conferir o binario"
  aviso "hash esperado: ${ESPERADO}"
elif [ "$OBTIDO" != "$ESPERADO" ]; then
  morrer "o binario NAO confere com o checksum publicado.
    esperado: ${ESPERADO}
    obtido:   ${OBTIDO}
    Nao instale. Isso indica download corrompido ou adulterado."
else
  ok "checksum confere"
fi

# --- instalação -------------------------------------------------------------

mkdir -p "$PREFIX" || morrer "nao foi possivel criar $PREFIX"
chmod +x "${TMP}/${BIN}"

# Move e verifica que executa. Um binário instalado que não roda (glibc
# incompatível, noexec no diretório) precisa falhar aqui, não no primeiro cron.
mv "${TMP}/${BIN}" "${PREFIX}/${BIN}" || morrer "nao foi possivel instalar em $PREFIX"
if ! "${PREFIX}/${BIN}" version >/dev/null 2>&1; then
  morrer "o binario foi instalado mas nao executa em ${PREFIX}/${BIN}.
    Causa comum: o diretorio esta montado com noexec. Tente outro caminho:
      SENTINELHOST_PREFIX=\$HOME/.local/bin sh install.sh"
fi
ok "instalado em ${PREFIX}/${BIN} ($("${PREFIX}/${BIN}" version))"

# --- PATH -------------------------------------------------------------------

case ":${PATH}:" in
  *":${PREFIX}:"*) ;;
  *)
    aviso "${PREFIX} nao esta no seu PATH"
    printf '    acrescente ao ~/.bashrc ou ~/.profile:\n'
    printf '      export PATH="%s:$PATH"\n' "$PREFIX"
    ;;
esac

# --- próximos passos --------------------------------------------------------

cat <<FIM_MSG

Proximos passos:

  ${BIN} config init --root ~/public_html
  ${BIN} doctor          # mostra POR QUE cada engine esta ou nao disponivel
  ${BIN} scan            # exit 0 = nada; 1 = achou; 2 = erro; 3 = ja rodando

Os padroes sao conservadores: modo observacao ligado e periodo de graca de 7
dias, para a ferramenta relatar antes de mexer em qualquer arquivo seu.

Para deixar rodando sem SSH:

  ${BIN} cron-line       # linha pronta para o cron do cPanel

FIM_MSG
