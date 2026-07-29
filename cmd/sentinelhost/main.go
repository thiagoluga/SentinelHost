// Comando sentinelhost: orquestrador de scanners de malware para hospedagem
// compartilhada.
//
// Um binario unico, estatico, sem dependencias obrigatorias (Principio VII).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Codigos de saida. Estaveis, porque cron e scripts do usuario dependem deles.
const (
	exitOK = 0
	// exitFindings: o ciclo rodou e encontrou algo que merece atencao. NAO e
	// erro: e o comportamento normal de um scanner que achou coisa. Separar
	// dos codigos de erro permite ao cron do usuario distinguir "achou
	// malware" de "a ferramenta quebrou".
	exitFindings = 1
	exitError    = 2
	// exitLocked: outra instancia esta rodando. Codigo proprio para que o
	// cron nao trate concorrencia normal como falha.
	exitLocked = 3
	exitUsage  = 64
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage()
		return exitUsage
	}

	// Ctrl-C e SIGTERM (a hospedagem matando o processo) cancelam o contexto
	// em vez de matar na hora: o ciclo precisa fechar o relatorio, liberar o
	// lock e nao deixar arquivo no meio do caminho entre disco e cofre.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "scan":
		return cmdScan(ctx, args)
	case "serve":
		err = cmdServe(ctx, args)
	case "daemon":
		err = cmdDaemon(ctx, args)
	case "quarantine":
		err = cmdQuarantine(ctx, args)
	case "config":
		err = cmdConfig(ctx, args)
	case "engines":
		err = cmdEngines(ctx, args)
	case "alert":
		err = cmdAlert(ctx, args)
	case "cron-line":
		err = cmdCronLine(args)
	case "doctor":
		err = cmdDoctor(ctx, args)
	case "version", "--version", "-v":
		fmt.Printf("sentinelhost %s (commit %s, build %s)\n", version, commit, buildDate)
		return exitOK
	case "help", "--help", "-h":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n", cmd)
		usage()
		return exitUsage
	}

	if err != nil {
		if errors.Is(err, errLocked) {
			fmt.Fprintln(os.Stderr, err)
			return exitLocked
		}
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		return exitError
	}
	return exitOK
}

func usage() {
	fmt.Fprint(os.Stderr, `SentinelHost — orquestrador de scanners de malware para hospedagem compartilhada.

Ele nao tem motor de deteccao proprio: executa os engines disponiveis no seu
ambiente, normaliza as saidas e consolida tudo num veredito por consenso.

USO
  sentinelhost <comando> [opcoes]

COMANDOS
  scan          Roda um ciclo agora e mostra o relatorio
  daemon        Fica rodando ciclos no intervalo configurado
  serve         Sobe o painel web (127.0.0.1 por padrao)
  quarantine    Lista, restaura e purga itens do cofre
  engines       Mostra os engines, disponibilidade e motivo
  config        Mostra, valida e inicializa a configuracao
  alert         Envia entrega de teste por e-mail ou webhook
  cron-line     Imprime a linha de cron pronta para colar no cPanel
  doctor        Diagnostica o ambiente e o que falta para cada engine
  version       Mostra a versao

OPCOES GLOBAIS
  --config <arquivo>   Caminho do TOML (padrao: ~/.sentinelhost/config.toml)

CODIGOS DE SAIDA
  0   nada a relatar
  1   o ciclo encontrou achados (nao e erro)
  2   erro de execucao
  3   outra instancia ja esta rodando
  64  uso incorreto

Comece por:  sentinelhost config init --root ~/public_html
`)
}
