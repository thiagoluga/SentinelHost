package email

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/schema"
)

// The templates are built in Go, without html/template, because there are few of
// them and they are fixed. The rule that matters: EVERY piece of data coming from
// the filesystem or from an engine goes through html.EscapeString before entering
// the HTML.
//
// That is not a formality. A malicious file's path is chosen by the attacker — a
// file named `<img src=x onerror=...>.php` would turn the alert e-mail into an
// attack vector against whoever opens it.

// VerdictMessage builds a verdict's alert.
func VerdictMessage(v schema.Verdict, panelURL string, actionRecommended bool) Message {
	level := strings.ToUpper(string(v.Level))
	action := "Quarantined automatically"
	switch {
	case actionRecommended:
		action = "ACTION RECOMMENDED — nothing was moved"
	case v.ActionTaken == schema.ActionSkippedWhitelist:
		action = "Protected by the whitelist — nothing was moved"
	case v.ActionTaken == schema.ActionFailed:
		action = "Could NOT neutralize: " + v.ActionError
	case v.ActionTaken != schema.ActionQuarantined:
		action = "No automatic action"
	}

	subject := fmt.Sprintf("[SentinelHost] %s: %s", level, shortPath(v.FilePath))

	var text strings.Builder
	fmt.Fprintf(&text, "Verdict: %s (score %.2f)\n", level, v.Score)
	fmt.Fprintf(&text, "File:    %s\n", v.FilePath)
	fmt.Fprintf(&text, "Hash:    %s\n", v.FileSHA256)
	fmt.Fprintf(&text, "Action:  %s\n\n", action)

	// The votes ARE the explanation. An alert without them forces the user to
	// trust the tool blindly (Principle V).
	text.WriteString("Why this verdict:\n")
	for _, vote := range v.Votes {
		fmt.Fprintf(&text, "  • %s — weight %.2f × %s = %.2f (rule: %s)\n",
			vote.Engine, vote.Weight, vote.Confidence, vote.EffectiveWeight, vote.Rule)
	}
	if len(v.Abstentions) > 0 {
		fmt.Fprintf(&text, "\nEngines that abstained: %s\n", strings.Join(v.Abstentions, ", "))
		text.WriteString("(this cycle's coverage was reduced)\n")
	}
	if v.CleanReason != "" {
		fmt.Fprintf(&text, "\nVeto applied: %s\n", v.CleanReason)
	}
	if v.QuarantineRef != "" {
		fmt.Fprintf(&text, "\nThe file is in the vault (ref %s) and can be restored at any time.\n", v.QuarantineRef)
	}
	if panelURL != "" {
		fmt.Fprintf(&text, "\nDecide in the panel: %s\n", panelURL)
	}

	var htmlB strings.Builder
	fmt.Fprintf(&htmlB, `<div style="font-family:system-ui,-apple-system,sans-serif;max-width:640px">`)
	fmt.Fprintf(&htmlB, `<h2 style="margin:0 0 4px">%s <span style="color:%s">%s</span></h2>`,
		"Verdict", levelColor(v.Level), html.EscapeString(level))
	fmt.Fprintf(&htmlB, `<p style="margin:0 0 16px;color:#666">score %.2f</p>`, v.Score)
	fmt.Fprintf(&htmlB, `<table cellpadding="6" style="border-collapse:collapse;width:100%%">`)
	htmlRow(&htmlB, "File", v.FilePath)
	htmlRow(&htmlB, "Hash", v.FileSHA256)
	htmlRow(&htmlB, "Action", action)
	fmt.Fprintf(&htmlB, `</table>`)

	fmt.Fprintf(&htmlB, `<h3>Why this verdict</h3><ul>`)
	for _, vote := range v.Votes {
		fmt.Fprintf(&htmlB, `<li><strong>%s</strong> — weight %.2f × %s = %.2f <em>(rule: %s)</em></li>`,
			html.EscapeString(vote.Engine), vote.Weight, html.EscapeString(string(vote.Confidence)),
			vote.EffectiveWeight, html.EscapeString(vote.Rule))
	}
	fmt.Fprintf(&htmlB, `</ul>`)
	if len(v.Abstentions) > 0 {
		fmt.Fprintf(&htmlB, `<p style="color:#a60"><strong>%d engine(s) abstained</strong> (%s): this cycle's coverage was reduced.</p>`,
			len(v.Abstentions), html.EscapeString(strings.Join(v.Abstentions, ", ")))
	}
	if v.QuarantineRef != "" {
		fmt.Fprintf(&htmlB, `<p>The file is in the vault (ref <code>%s</code>) and can be restored at any time.</p>`,
			html.EscapeString(v.QuarantineRef))
	}
	if panelURL != "" {
		fmt.Fprintf(&htmlB, `<p><a href="%s">Decide in the panel</a></p>`, html.EscapeString(panelURL))
	}
	fmt.Fprintf(&htmlB, `</div>`)

	return Message{Subject: subject, Text: text.String(), HTML: htmlB.String()}
}

// DigestMessage builds the periodic summary.
func DigestMessage(start, end time.Time, counts map[schema.Level]int, actions map[schema.ActionTaken]int, pending []schema.Verdict, panelURL string) Message {
	subject := fmt.Sprintf("[SentinelHost] Summary for %s", end.Format("2006-01-02"))

	var t strings.Builder
	fmt.Fprintf(&t, "Summary for the period %s to %s\n\n",
		start.Format("2006-01-02 15:04"), end.Format("2006-01-02 15:04"))
	fmt.Fprintf(&t, "Verdicts:\n")
	for _, l := range []schema.Level{schema.LevelConfirmed, schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		fmt.Fprintf(&t, "  %-12s %d\n", l, counts[l])
	}
	fmt.Fprintf(&t, "\nActions:\n")
	for a, n := range actions {
		fmt.Fprintf(&t, "  %-26s %d\n", a, n)
	}
	if len(pending) > 0 {
		fmt.Fprintf(&t, "\nWaiting for your decision (%d):\n", len(pending))
		for _, v := range pending {
			fmt.Fprintf(&t, "  [%s] %s (score %.2f)\n", v.Level, v.FilePath, v.Score)
		}
	}
	if panelURL != "" {
		fmt.Fprintf(&t, "\nPanel: %s\n", panelURL)
	}

	var h strings.Builder
	fmt.Fprintf(&h, `<div style="font-family:system-ui,-apple-system,sans-serif;max-width:640px">`)
	fmt.Fprintf(&h, `<h2>SentinelHost summary</h2><p style="color:#666">%s to %s</p>`,
		html.EscapeString(start.Format("2006-01-02 15:04")), html.EscapeString(end.Format("2006-01-02 15:04")))
	fmt.Fprintf(&h, `<table cellpadding="6" style="border-collapse:collapse">`)
	for _, l := range []schema.Level{schema.LevelConfirmed, schema.LevelLikely, schema.LevelSuspicious, schema.LevelClean} {
		fmt.Fprintf(&h, `<tr><td style="color:%s"><strong>%s</strong></td><td>%d</td></tr>`,
			levelColor(l), html.EscapeString(string(l)), counts[l])
	}
	fmt.Fprintf(&h, `</table>`)
	if len(pending) > 0 {
		fmt.Fprintf(&h, `<h3>Waiting for your decision (%d)</h3><ul>`, len(pending))
		for _, v := range pending {
			fmt.Fprintf(&h, `<li>[%s] %s — score %.2f</li>`,
				html.EscapeString(string(v.Level)), html.EscapeString(v.FilePath), v.Score)
		}
		fmt.Fprintf(&h, `</ul>`)
	}
	if panelURL != "" {
		fmt.Fprintf(&h, `<p><a href="%s">Open the panel</a></p>`, html.EscapeString(panelURL))
	}
	fmt.Fprintf(&h, `</div>`)

	return Message{Subject: subject, Text: t.String(), HTML: h.String()}
}

// EngineFailedMessage warns that an engine stopped working.
//
// It exists because silent coverage degradation is an orchestrator's most
// dangerous failure mode: the user keeps seeing "0 findings" and believes they are
// protected.
func EngineFailedMessage(engine, reason, scanID string) Message {
	subject := fmt.Sprintf("[SentinelHost] Engine %s stopped working", engine)
	text := fmt.Sprintf(
		"The engine %s could not run in cycle %s.\n\nReason: %s\n\n"+
			"Your site's coverage is reduced until this is resolved: the other engines "+
			"keep running, but the consensus lost a vote.\n",
		engine, scanID, reason)
	htmlBody := fmt.Sprintf(
		`<div style="font-family:system-ui,sans-serif;max-width:640px">`+
			`<h2>Engine %s stopped working</h2>`+
			`<p><strong>Reason:</strong> %s</p>`+
			`<p>Your site's coverage is reduced: the other engines keep running, `+
			`but the consensus lost a vote.</p></div>`,
		html.EscapeString(engine), html.EscapeString(reason))
	return Message{Subject: subject, Text: text, HTML: htmlBody}
}

// TestMessage is the test delivery.
func TestMessage() Message {
	return Message{
		Subject: "[SentinelHost] E-mail configuration test",
		Text: "If you received this message, SentinelHost can send alerts " +
			"through this SMTP server.\n\nNo action is required.\n",
		HTML: `<div style="font-family:system-ui,sans-serif">` +
			`<h2>E-mail test</h2>` +
			`<p>If you received this message, SentinelHost can send alerts through this SMTP server.</p>` +
			`<p>No action is required.</p></div>`,
	}
}

func htmlRow(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, `<tr><td style="color:#666;white-space:nowrap">%s</td><td><code>%s</code></td></tr>`,
		html.EscapeString(label), html.EscapeString(value))
}

func levelColor(l schema.Level) string {
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

func shortPath(p string) string {
	if len(p) <= 60 {
		return p
	}
	return "…" + p[len(p)-59:]
}
