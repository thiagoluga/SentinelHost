# Quickstart

Do zero ao primeiro scan numa conta de hospedagem compartilhada, sem root.

## Requisitos

- Uma conta Linux (cPanel ou similar) com acesso a **cron** — SSH ajuda, mas
  não é obrigatório.
- Nada mais. O SentinelHost é um binário estático único; ele não precisa de
  glibc compatível, systemd, root nem runtime instalado.

Os *engines* que ele orquestra têm requisitos próprios (PHP CLI para o AMWScan,
binário `yara` para o php-malware-finder). Nenhum deles é obrigatório: o
`wp-checksums` é nativo e funciona só com rede, e cada engine ausente é
reportado com o motivo em vez de sumir em silêncio.

## 1. Instalar

```bash
curl -fsSL https://github.com/thiagoluga/SentinelHost/releases/latest/download/sentinelhost-linux-amd64 -o ~/bin/sentinelhost
chmod +x ~/bin/sentinelhost
```

Em ARM (alguns planos de hospedagem), troque `amd64` por `arm64`. Se `~/bin`
não existir, crie com `mkdir -p ~/bin` e acrescente ao `PATH`:

```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

Confira os checksums publicados junto do release:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## 2. Configurar

```bash
sentinelhost config init --root ~/public_html
```

Isso cria `~/.sentinelhost/config.toml` com padrões deliberadamente
conservadores:

| Padrão | Por quê |
|---|---|
| Modo observação **ligado** | A ferramenta relata, mas não move nada. |
| Período de graça de **7 dias** | Tempo para você calibrar pesos e whitelist antes de qualquer ação automática. |
| `nice 19`, pausa entre lotes, timeout por engine | Para o scanner nunca causar a suspensão da sua conta por abuso de recursos. |
| Purga automática **desligada** | Apagar arquivo seu é sempre decisão sua. |
| Painel em `127.0.0.1` | Acesso por túnel SSH, não exposto à internet. |

## 3. Ver o que está disponível

```bash
sentinelhost doctor
```

Mostra o ambiente, as raízes, o diretório de dados e — o mais útil — **por que**
cada engine está ou não disponível. "Indisponível" sem motivo transformaria um
problema resolvível (instalar o PHP CLI) em mistério.

Para instalar os engines que rodam no seu espaço de usuário:

```bash
sentinelhost engines --install amwscan
sentinelhost engines --install php-malware-finder   # exige o binário `yara`
```

## 4. Primeiro scan

```bash
sentinelhost scan
```

O relatório mostra, nesta ordem: quais engines rodaram (e quais se abstiveram),
os vereditos com **os votos que os produziram**, e o resumo por nível.

Códigos de saída — use no cron para distinguir "achou malware" de "quebrou":

| Código | Significa |
|---|---|
| `0` | Nada a relatar |
| `1` | O ciclo encontrou achados. **Não é erro.** |
| `2` | Erro de execução |
| `3` | Outra instância já está rodando |

## 5. Deixar rodando

### Sem SSH (cron do cPanel)

```bash
sentinelhost cron-line
```

Copie as linhas geradas para o gerenciador de cron. O lock de instância única
impede que dois ciclos se atropelem: o segundo sai com código 3 sem fazer nada.

### Com SSH

```bash
sentinelhost daemon
```

O daemon é conforto, não requisito — tudo que ele faz também funciona só com o
cron.

## 6. Painel

```bash
sentinelhost serve
```

O painel escuta em `127.0.0.1:8787`. Para acessar da sua máquina, **não exponha
a porta** — abra um túnel:

```bash
ssh -L 8787:127.0.0.1:8787 usuario@servidor
```

Depois abra `http://127.0.0.1:8787`. No primeiro acesso o painel pede que você
defina a senha — ela é a única coisa entre a internet e um botão que move
arquivos do seu site.

## 7. Ligar a ação automática

Depois de alguns dias vendo o que a ferramenta acha, e tendo colocado na
whitelist o que for falso positivo:

```toml
# ~/.sentinelhost/config.toml
[general]
observation_mode = false
```

A partir daí, e depois de o período de graça expirar, vereditos `confirmed`
passam a ser quarentenados automaticamente. Níveis abaixo disso continuam
sempre aguardando sua decisão.

## Restaurar algo

Nada é apagado. Todo item do cofre volta byte a byte:

```bash
sentinelhost quarantine list
sentinelhost quarantine restore q_20260723150405_a1b2c3d4
```

Para conferir que o cofre inteiro ainda está íntegro — antes da hora em que
você precisar dele:

```bash
sentinelhost quarantine verify
```

## Alertas

```bash
sentinelhost alert --test-email
sentinelhost alert --test-webhook meu-hook
```

O resultado mostrado é o **erro real** do servidor. Descobrir que a sua
hospedagem bloqueia a porta 587 é o propósito inteiro desses comandos.

## Onde ficam as coisas

```text
~/.sentinelhost/
├── config.toml        configuração (fonte da verdade, compartilhada com o painel)
├── sentinelhost.db    vereditos, quarentena, entregas, log estruturado
├── baseline.json      hashes para os ciclos incrementais
├── quarantine/        o cofre — arquivos neutralizados, todos restauráveis
├── raw/               saída bruta dos engines, para auditoria
└── engines/           engines instalados no seu espaço de usuário
```

## Desinstalar

```bash
sentinelhost quarantine list        # restaure o que quiser antes
rm ~/bin/sentinelhost
rm -rf ~/.sentinelhost              # apaga o cofre junto; confira antes
```
