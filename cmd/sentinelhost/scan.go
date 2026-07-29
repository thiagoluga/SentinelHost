package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/cycle"
	"github.com/thiagoluga/SentinelHost/internal/schema"
)

func cmdScan(ctx context.Context, args []string) int {
	fs, cfgPath := flagSet("scan")
	full := fs.Bool("full", false, "escaneia tudo em vez de so o que mudou desde o ultimo ciclo")
	dryRun := fs.Bool("dry-run", false, "calcula os vereditos sem executar nenhuma acao")
	asJSON := fs.Bool("json", false, "imprime o relatorio em JSON")
	quiet := fs.Bool("quiet", false, "so imprime se houver achados")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `sentinelhost scan — roda um ciclo agora.

Sonda os engines disponiveis, executa os que estiverem prontos, normaliza as
saidas e consolida um veredito por arquivo.

Sai com codigo 1 quando encontra achados. Isso NAO e erro: e o comportamento
normal de um scanner que achou coisa. Use no cron para distinguir "achou
malware" de "a ferramenta quebrou".

OPCOES
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	a, err := openApp(ctx, *cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		return exitError
	}
	defer a.Close()

	modo := schema.ModeIncremental
	if *full {
		modo = schema.ModeFull
	}

	runner := cycle.New(a.cfg, a.store, a.registry, a.vault)
	sum, err := runner.Run(ctx, cycle.Options{Mode: modo, DryRun: *dryRun})
	if err != nil {
		if errors.Is(err, errLocked) {
			fmt.Fprintln(os.Stderr, err)
			return exitLocked
		}
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		return exitError
	}

	// Marca o primeiro ciclo, que inicia a contagem do periodo de graca.
	if a.cfg.General.FirstRunAt.IsZero() {
		a.cfg.General.FirstRunAt = sum.StartedAt
		if err := a.cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "aviso: nao foi possivel registrar a data do primeiro ciclo: %v\n", err)
		}
	}

	achados := contarAcionaveis(sum)

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(relatorioJSON(sum)); err != nil {
			fmt.Fprintf(os.Stderr, "erro serializando relatorio: %v\n", err)
			return exitError
		}
	case *quiet && achados == 0:
		// silencio proposital
	default:
		imprimirRelatorio(os.Stdout, sum)
	}

	if achados > 0 {
		return exitFindings
	}
	return exitOK
}

func contarAcionaveis(sum cycle.Summary) int {
	return sum.LevelCounts[schema.LevelConfirmed] +
		sum.LevelCounts[schema.LevelLikely] +
		sum.LevelCounts[schema.LevelSuspicious]
}

func relatorioJSON(sum cycle.Summary) map[string]any {
	out := sum.Event()
	out["verdicts_detail"] = sum.Verdicts
	return out
}

// imprimirRelatorio escreve o relatorio em texto.
//
// A ordem nao e decorativa: primeiro o que exige acao, depois o que o usuario
// precisa saber sobre a COBERTURA do scan. Um relatorio que diz "0 achados"
// sem dizer que 3 dos 4 engines falharam e uma mentira por omissao.
func imprimirRelatorio(w *os.File, sum cycle.Summary) {
	fmt.Fprintf(w, "\nSentinelHost — ciclo %s (%s)\n", sum.ScanID, sum.Mode)
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 64))
	fmt.Fprintf(w, "Duracao: %s | Considerados: %d | Escaneados: %d\n",
		sum.FinishedAt.Sub(sum.StartedAt).Round(time.Millisecond),
		sum.FilesConsidered, sum.FilesScanned)

	// Engines: cobertura real deste ciclo.
	fmt.Fprintf(w, "\nENGINES\n")
	for _, e := range sum.Engines {
		switch {
		case !e.Available:
			fmt.Fprintf(w, "  ✗ %-20s indisponivel — %s\n", e.Slug, e.Reason)
		case e.Status != schema.StatusCompleted:
			fmt.Fprintf(w, "  ! %-20s %s (abstencao) — %s\n", e.Slug, e.Status, e.Reason)
		default:
			fmt.Fprintf(w, "  ✓ %-20s %d achado(s) em %s\n", e.Slug, e.Findings, e.Duration.Round(time.Millisecond))
		}
	}
	// Abstencao de engine que nem chegou a ser sondado (habilitado na
	// configuracao mas sem adaptador neste binario) tambem entra na lista: o
	// numero de abstencoes tem que bater com os motivos exibidos, senao o
	// usuario ve "4 se abstiveram" e so 3 explicacoes.
	listados := map[string]bool{}
	for _, e := range sum.Engines {
		listados[e.Slug] = true
	}
	for _, slug := range ordenar(sum.Abstentions) {
		if !listados[slug] {
			fmt.Fprintf(w, "  ✗ %-20s %s\n", slug, sum.Abstentions[slug])
		}
	}
	if len(sum.Abstentions) > 0 {
		fmt.Fprintf(w, "\n  %d engine(s) se abstiveram: a cobertura deste ciclo esta reduzida.\n", len(sum.Abstentions))
	}

	// Vereditos.
	acionaveis := ordenarPorGravidade(sum.Verdicts)
	fmt.Fprintf(w, "\nVEREDITOS\n")
	if len(acionaveis) == 0 {
		fmt.Fprintf(w, "  Nada a relatar.\n")
	}
	for _, v := range acionaveis {
		fmt.Fprintf(w, "\n  [%s] score %.2f — %s\n", strings.ToUpper(string(v.Level)), v.Score, v.FilePath)
		for _, voto := range v.Votes {
			fmt.Fprintf(w, "      voto: %-20s peso %.2f x %-9s = %.2f  (regra %s)\n",
				voto.Engine, voto.Weight, voto.Confidence, voto.EffectiveWeight, voto.Rule)
		}
		if len(v.Abstentions) > 0 {
			fmt.Fprintf(w, "      abstencoes: %s\n", strings.Join(v.Abstentions, ", "))
		}
		if v.CleanReason != "" {
			fmt.Fprintf(w, "      veto: %s\n", v.CleanReason)
		}
		fmt.Fprintf(w, "      acao: %s", v.ActionTaken)
		if v.ActionError != "" {
			fmt.Fprintf(w, " (%s)", v.ActionError)
		}
		fmt.Fprintln(w)
	}

	// Resumo por nivel.
	fmt.Fprintf(w, "\nRESUMO  ")
	for _, l := range []schema.Level{schema.LevelConfirmed, schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		fmt.Fprintf(w, "%s=%d  ", l, sum.LevelCounts[l])
	}
	fmt.Fprintln(w)

	if sum.ObservationReason != "" {
		fmt.Fprintf(w, "\nNenhuma acao automatica foi executada: %s\n", sum.ObservationReason)
	}
	if n := sum.SkippedCounts["truncated"]; n > 0 {
		fmt.Fprintf(w, "\nATENCAO: o limite de arquivos por ciclo foi atingido. Parte do site nao foi olhada.\n")
	}
	if len(sum.SkippedCounts) > 0 {
		fmt.Fprintf(w, "\nPulados: %s\n", formatarPulados(sum.SkippedCounts))
	}
	fmt.Fprintln(w)
}

// ordenarPorGravidade coloca o que exige acao no topo e esconde os limpos.
func ordenarPorGravidade(vs []schema.Verdict) []schema.Verdict {
	var out []schema.Verdict
	for _, v := range vs {
		if v.Level != schema.LevelClean {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Level.Rank() != out[j].Level.Rank() {
			return out[i].Level.Rank() > out[j].Level.Rank()
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func ordenar(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func formatarPulados(m map[string]int) string {
	chaves := make([]string, 0, len(m))
	for k := range m {
		chaves = append(chaves, k)
	}
	sort.Strings(chaves)
	partes := make([]string, 0, len(chaves))
	for _, k := range chaves {
		partes = append(partes, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(partes, ", ")
}
