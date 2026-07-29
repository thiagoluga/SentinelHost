package email

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// Os templates sao montados em Go, sem html/template, porque sao poucos e
// fixos. A regra que importa: TODO dado vindo do sistema de arquivos ou de um
// engine passa por html.EscapeString antes de entrar no HTML.
//
// Isso nao e formalidade. O caminho de um arquivo malicioso e escolhido pelo
// atacante — um arquivo chamado `<img src=x onerror=...>.php` transformaria o
// e-mail de alerta num vetor de ataque contra quem o abre.

// VerdictMessage monta o alerta de um veredito.
func VerdictMessage(v schema.Verdict, panelURL string, acaoRecomendada bool) Message {
	nivel := strings.ToUpper(string(v.Level))
	acao := "Quarentenado automaticamente"
	switch {
	case acaoRecomendada:
		acao = "AÇÃO RECOMENDADA — nada foi movido"
	case v.ActionTaken == schema.ActionSkippedWhitelist:
		acao = "Protegido pela whitelist — nada foi movido"
	case v.ActionTaken == schema.ActionFailed:
		acao = "NÃO foi possível neutralizar: " + v.ActionError
	case v.ActionTaken != schema.ActionQuarantined:
		acao = "Nenhuma ação automática"
	}

	assunto := fmt.Sprintf("[SentinelHost] %s: %s", nivel, curtoCaminho(v.FilePath))

	var texto strings.Builder
	fmt.Fprintf(&texto, "Veredito: %s (score %.2f)\n", nivel, v.Score)
	fmt.Fprintf(&texto, "Arquivo:  %s\n", v.FilePath)
	fmt.Fprintf(&texto, "Hash:     %s\n", v.FileSHA256)
	fmt.Fprintf(&texto, "Ação:     %s\n\n", acao)

	// Os votos SAO a explicacao. Um alerta sem eles obriga o usuario a
	// confiar cegamente na ferramenta (Principio V).
	texto.WriteString("Por que este veredito:\n")
	for _, voto := range v.Votes {
		fmt.Fprintf(&texto, "  • %s — peso %.2f × %s = %.2f (regra: %s)\n",
			voto.Engine, voto.Weight, voto.Confidence, voto.EffectiveWeight, voto.Rule)
	}
	if len(v.Abstentions) > 0 {
		fmt.Fprintf(&texto, "\nEngines que se abstiveram: %s\n", strings.Join(v.Abstentions, ", "))
		texto.WriteString("(a cobertura deste ciclo foi reduzida)\n")
	}
	if v.CleanReason != "" {
		fmt.Fprintf(&texto, "\nVeto aplicado: %s\n", v.CleanReason)
	}
	if v.QuarantineRef != "" {
		fmt.Fprintf(&texto, "\nO arquivo está no cofre (ref %s) e pode ser restaurado a qualquer momento.\n", v.QuarantineRef)
	}
	if panelURL != "" {
		fmt.Fprintf(&texto, "\nDecidir no painel: %s\n", panelURL)
	}

	var htmlB strings.Builder
	fmt.Fprintf(&htmlB, `<div style="font-family:system-ui,-apple-system,sans-serif;max-width:640px">`)
	fmt.Fprintf(&htmlB, `<h2 style="margin:0 0 4px">%s <span style="color:%s">%s</span></h2>`,
		"Veredito", corDoNivel(v.Level), html.EscapeString(nivel))
	fmt.Fprintf(&htmlB, `<p style="margin:0 0 16px;color:#666">score %.2f</p>`, v.Score)
	fmt.Fprintf(&htmlB, `<table cellpadding="6" style="border-collapse:collapse;width:100%%">`)
	linhaHTML(&htmlB, "Arquivo", v.FilePath)
	linhaHTML(&htmlB, "Hash", v.FileSHA256)
	linhaHTML(&htmlB, "Ação", acao)
	fmt.Fprintf(&htmlB, `</table>`)

	fmt.Fprintf(&htmlB, `<h3>Por que este veredito</h3><ul>`)
	for _, voto := range v.Votes {
		fmt.Fprintf(&htmlB, `<li><strong>%s</strong> — peso %.2f × %s = %.2f <em>(regra: %s)</em></li>`,
			html.EscapeString(voto.Engine), voto.Weight, html.EscapeString(string(voto.Confidence)),
			voto.EffectiveWeight, html.EscapeString(voto.Rule))
	}
	fmt.Fprintf(&htmlB, `</ul>`)
	if len(v.Abstentions) > 0 {
		fmt.Fprintf(&htmlB, `<p style="color:#a60"><strong>%d engine(s) se abstiveram</strong> (%s): a cobertura deste ciclo foi reduzida.</p>`,
			len(v.Abstentions), html.EscapeString(strings.Join(v.Abstentions, ", ")))
	}
	if v.QuarantineRef != "" {
		fmt.Fprintf(&htmlB, `<p>O arquivo está no cofre (ref <code>%s</code>) e pode ser restaurado a qualquer momento.</p>`,
			html.EscapeString(v.QuarantineRef))
	}
	if panelURL != "" {
		fmt.Fprintf(&htmlB, `<p><a href="%s">Decidir no painel</a></p>`, html.EscapeString(panelURL))
	}
	fmt.Fprintf(&htmlB, `</div>`)

	return Message{Subject: assunto, Text: texto.String(), HTML: htmlB.String()}
}

// DigestMessage monta o resumo periodico.
func DigestMessage(inicio, fim time.Time, contagem map[schema.Level]int, acoes map[schema.ActionTaken]int, pendentes []schema.Verdict, panelURL string) Message {
	assunto := fmt.Sprintf("[SentinelHost] Resumo de %s", fim.Format("02/01/2006"))

	var t strings.Builder
	fmt.Fprintf(&t, "Resumo do período %s a %s\n\n",
		inicio.Format("02/01 15:04"), fim.Format("02/01 15:04"))
	fmt.Fprintf(&t, "Vereditos:\n")
	for _, l := range []schema.Level{schema.LevelConfirmed, schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		fmt.Fprintf(&t, "  %-12s %d\n", l, contagem[l])
	}
	fmt.Fprintf(&t, "\nAções:\n")
	for a, n := range acoes {
		fmt.Fprintf(&t, "  %-26s %d\n", a, n)
	}
	if len(pendentes) > 0 {
		fmt.Fprintf(&t, "\nAguardando sua decisão (%d):\n", len(pendentes))
		for _, v := range pendentes {
			fmt.Fprintf(&t, "  [%s] %s (score %.2f)\n", v.Level, v.FilePath, v.Score)
		}
	}
	if panelURL != "" {
		fmt.Fprintf(&t, "\nPainel: %s\n", panelURL)
	}

	var h strings.Builder
	fmt.Fprintf(&h, `<div style="font-family:system-ui,-apple-system,sans-serif;max-width:640px">`)
	fmt.Fprintf(&h, `<h2>Resumo do SentinelHost</h2><p style="color:#666">%s a %s</p>`,
		html.EscapeString(inicio.Format("02/01 15:04")), html.EscapeString(fim.Format("02/01 15:04")))
	fmt.Fprintf(&h, `<table cellpadding="6" style="border-collapse:collapse">`)
	for _, l := range []schema.Level{schema.LevelConfirmed, schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		fmt.Fprintf(&h, `<tr><td style="color:%s"><strong>%s</strong></td><td>%d</td></tr>`,
			corDoNivel(l), html.EscapeString(string(l)), contagem[l])
	}
	fmt.Fprintf(&h, `</table>`)
	if len(pendentes) > 0 {
		fmt.Fprintf(&h, `<h3>Aguardando sua decisão (%d)</h3><ul>`, len(pendentes))
		for _, v := range pendentes {
			fmt.Fprintf(&h, `<li>[%s] %s — score %.2f</li>`,
				html.EscapeString(string(v.Level)), html.EscapeString(v.FilePath), v.Score)
		}
		fmt.Fprintf(&h, `</ul>`)
	}
	if panelURL != "" {
		fmt.Fprintf(&h, `<p><a href="%s">Abrir o painel</a></p>`, html.EscapeString(panelURL))
	}
	fmt.Fprintf(&h, `</div>`)

	return Message{Subject: assunto, Text: t.String(), HTML: h.String()}
}

// EngineFailedMessage avisa que um engine parou de funcionar.
//
// Existe porque a degradacao silenciosa de cobertura e o modo de falha mais
// perigoso de um orquestrador: o usuario continua vendo "0 achados" e acha que
// esta protegido.
func EngineFailedMessage(engine, motivo, scanID string) Message {
	assunto := fmt.Sprintf("[SentinelHost] Engine %s parou de funcionar", engine)
	texto := fmt.Sprintf(
		"O engine %s não conseguiu rodar no ciclo %s.\n\nMotivo: %s\n\n"+
			"A cobertura do seu site está reduzida até isso ser resolvido: os demais "+
			"engines continuam rodando, mas o consenso perdeu um voto.\n",
		engine, scanID, motivo)
	htmlBody := fmt.Sprintf(
		`<div style="font-family:system-ui,sans-serif;max-width:640px">`+
			`<h2>Engine %s parou de funcionar</h2>`+
			`<p><strong>Motivo:</strong> %s</p>`+
			`<p>A cobertura do seu site está reduzida: os demais engines continuam `+
			`rodando, mas o consenso perdeu um voto.</p></div>`,
		html.EscapeString(engine), html.EscapeString(motivo))
	return Message{Subject: assunto, Text: texto, HTML: htmlBody}
}

// TestMessage e a entrega de teste.
func TestMessage() Message {
	return Message{
		Subject: "[SentinelHost] Teste de configuração de e-mail",
		Text: "Se você recebeu esta mensagem, o SentinelHost consegue enviar alertas " +
			"por este servidor SMTP.\n\nNenhuma ação é necessária.\n",
		HTML: `<div style="font-family:system-ui,sans-serif">` +
			`<h2>Teste de e-mail</h2>` +
			`<p>Se você recebeu esta mensagem, o SentinelHost consegue enviar alertas por este servidor SMTP.</p>` +
			`<p>Nenhuma ação é necessária.</p></div>`,
	}
}

func linhaHTML(b *strings.Builder, rotulo, valor string) {
	fmt.Fprintf(b, `<tr><td style="color:#666;white-space:nowrap">%s</td><td><code>%s</code></td></tr>`,
		html.EscapeString(rotulo), html.EscapeString(valor))
}

func corDoNivel(l schema.Level) string {
	switch l {
	case schema.LevelConfirmed:
		return "#c0392b"
	case schema.LevelLikely:
		return "#d35400"
	case schema.LevelSuspicious:
		return "#b7950b"
	default:
		return "#27ae60"
	}
}

func curtoCaminho(p string) string {
	if len(p) <= 60 {
		return p
	}
	return "…" + p[len(p)-59:]
}
