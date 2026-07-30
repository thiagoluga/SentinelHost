package webhook

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// Slack's and Discord's incoming webhooks do not accept an arbitrary payload:
// Slack wants {"text": ...} or blocks, Discord wants {"content": ...} or embeds.
// Posting this project's envelope to either one is rejected or arrives as an empty
// message, so "integrates with Slack/Discord" (US4) was a promise the generic
// webhook could not keep. This file keeps it.
//
// Two rules shape everything here:
//
//  1. The message says WHY, not just WHAT. A chat notification that reads "threat
//     confirmed" and nothing else forces the user into the panel to learn anything
//     — and the votes are the whole point of a consensus verdict (Principle V).
//  2. Everything that reaches the message is escaped or fenced. The file paths
//     come from the ATTACKER; a path holding `<!channel>` or Slack markup would
//     otherwise turn our own alert into their megaphone.

// maxChatBody caps what we send to a chat destination.
//
// Slack truncates a text block around 3000 characters and Discord rejects content
// over 2000 outright — a rejected delivery would retry five times and then be
// recorded as failed, so the cap has to be ours, not theirs.
const maxChatBody = 1800

// Body renders the envelope for a destination.
//
// The returned bytes are what actually gets POSTed and signed. Signing a Slack
// body is mechanically fine but means little: neither Slack nor Discord verifies a
// signature, which is why the configuration warns about a secret on a non-raw
// format.
func Body(format string, env Envelope) ([]byte, error) {
	switch format {
	case config.FormatSlack:
		return json.Marshal(map[string]any{
			"text": chatMessage(env, slackEscape),
		})
	case config.FormatDiscord:
		return json.Marshal(map[string]any{
			"content": chatMessage(env, discordEscape),
		})
	case config.FormatRaw, "":
		return json.Marshal(env)
	default:
		// An unknown format must never fall back to raw silently: the user asked for
		// a shape this build cannot produce, and a delivery that "worked" in the
		// wrong shape is the kind of quiet wrongness this project treats as a
		// defect.
		return nil, fmt.Errorf("unknown webhook format %q", format)
	}
}

// escaper makes attacker-chosen text safe for one destination's markup.
type escaper func(string) string

// slackEscape neutralizes Slack's control characters.
//
// `<` and `>` delimit Slack links and special mentions (`<!channel>`), and `&`
// starts an entity. A file called `<!here>.php` is a legitimate filename and a
// perfectly good way to make our alert ping an entire workspace.
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// discordEscape neutralizes Discord's markdown and mentions.
//
// Discord has no entity encoding, so the only reliable defence is a backslash
// before each markup character. `@` is broken with a zero-width space because
// `\@everyone` still pings.
func discordEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '~', '|', '>', '[', ']', '(', ')', '#', '-':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '@':
			// A zero-width space after the @ keeps the text readable and stops
			// @everyone / @here from resolving.
			b.WriteRune('@')
			b.WriteRune('​')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// chatMessage renders one event as a chat message.
func chatMessage(env Envelope, esc escaper) string {
	var b strings.Builder

	data := asMap(env.Data)
	site := esc(firstNonEmpty(env.Instance.Root, env.Instance.Hostname, env.Instance.ID))

	switch env.Event {
	case "verdict.confirmed", "verdict.likely", "verdict.suspicious":
		level := strings.ToUpper(str(data["level"]))
		if level == "" {
			level = strings.ToUpper(strings.TrimPrefix(env.Event, "verdict."))
		}
		fmt.Fprintf(&b, "%s SentinelHost: %s\n", icon(env.Event), level)
		fmt.Fprintf(&b, "site: %s\n", site)
		fmt.Fprintf(&b, "file: %s\n", esc(str(data["file_path"])))
		if score, ok := num(data["score"]); ok {
			fmt.Fprintf(&b, "score: %.2f\n", score)
		}

		// The votes are the message. Without them the user has to open the panel to
		// learn anything at all.
		if votes := asSlice(data["votes"]); len(votes) > 0 {
			b.WriteString("why:\n")
			for _, raw := range votes {
				v := asMap(raw)
				w, _ := num(v["weight"])
				eff, _ := num(v["effective_weight"])
				fmt.Fprintf(&b, "  - %s %.2f x %s = %.2f (rule %s)\n",
					esc(str(v["engine"])), w, esc(str(v["confidence"])), eff, esc(str(v["rule"])))
			}
		}
		if abst := asStrings(data["abstentions"]); len(abst) > 0 {
			fmt.Fprintf(&b, "abstained: %s (this cycle's coverage was reduced)\n",
				esc(strings.Join(abst, ", ")))
		}
		if reason := str(data["clean_reason"]); reason != "" {
			fmt.Fprintf(&b, "veto: %s — this file will never be quarantined\n", esc(reason))
		}
		if action := str(data["action_taken"]); action != "" && action != "none" {
			line := action
			if err := str(data["action_error"]); err != "" {
				line += " — " + err
			}
			fmt.Fprintf(&b, "action: %s\n", esc(line))
		}
		if ref := str(data["quarantine_ref"]); ref != "" {
			fmt.Fprintf(&b, "the file is in the vault (ref %s) and can be restored at any time\n", esc(ref))
		}

	case "quarantine.action":
		fmt.Fprintf(&b, "%s SentinelHost: quarantine %s\n", icon(env.Event), esc(str(data["action"])))
		fmt.Fprintf(&b, "site: %s\n", site)
		fmt.Fprintf(&b, "file: %s\n", esc(str(data["original_path"])))
		if ref := str(data["quarantine_ref"]); ref != "" {
			fmt.Fprintf(&b, "ref: %s\n", esc(ref))
		}
		if err := str(data["error"]); err != "" {
			fmt.Fprintf(&b, "error: %s\n", esc(err))
		}
		if rev, ok := data["reversible"].(bool); ok && rev {
			b.WriteString("reversible: yes — nothing was deleted\n")
		}

	case "scan.completed":
		fmt.Fprintf(&b, "%s SentinelHost: cycle finished\n", icon(env.Event))
		fmt.Fprintf(&b, "site: %s\n", site)
		fmt.Fprintf(&b, "status: %s (%s)\n", esc(str(data["status"])), esc(str(data["mode"])))
		if scanned, ok := num(data["files_scanned"]); ok {
			considered, _ := num(data["files_considered"])
			fmt.Fprintf(&b, "files: %.0f scanned of %.0f considered\n", scanned, considered)
		}
		if v := asMap(data["verdicts"]); len(v) > 0 {
			fmt.Fprintf(&b, "verdicts: %s\n", esc(counts(v)))
		}
		// An abstention always travels with the summary. A cycle in which half the
		// engines failed must not read as a clean cycle (Principle VI).
		if ab := asSlice(data["engines_abstained"]); len(ab) > 0 {
			b.WriteString("abstained:\n")
			for _, raw := range ab {
				e := asMap(raw)
				fmt.Fprintf(&b, "  - %s: %s\n", esc(str(e["engine"])), esc(str(e["reason"])))
			}
		}

	case "engine.failed":
		fmt.Fprintf(&b, "%s SentinelHost: engine %s stopped working\n",
			icon(env.Event), esc(str(data["engine"])))
		fmt.Fprintf(&b, "site: %s\n", site)
		fmt.Fprintf(&b, "status: %s\n", esc(str(data["status"])))
		if err := str(data["error"]); err != "" {
			fmt.Fprintf(&b, "reason: %s\n", esc(err))
		}
		b.WriteString("your site's coverage is reduced until this is resolved\n")

	default:
		// An event this build does not know about still gets delivered. Dropping it
		// would be a silent gap exactly where the user asked to be told.
		fmt.Fprintf(&b, "%s SentinelHost: %s\n", icon(env.Event), esc(env.Event))
		fmt.Fprintf(&b, "site: %s\n", site)
	}

	return truncate(strings.TrimRight(b.String(), "\n"))
}

func icon(event string) string {
	switch event {
	case "verdict.confirmed":
		return "🚨"
	case "verdict.likely":
		return "⚠️"
	case "verdict.suspicious":
		return "🔎"
	case "quarantine.action":
		return "🗄️"
	case "engine.failed":
		return "🛠️"
	default:
		return "🛡️"
	}
}

// truncate keeps the message under the destinations' limits.
//
// It says it truncated. A message silently cut at a boundary would hide the very
// votes it exists to show.
func truncate(s string) string {
	if len(s) <= maxChatBody {
		return s
	}
	cut := s[:maxChatBody]
	if i := strings.LastIndexByte(cut, '\n'); i > maxChatBody/2 {
		cut = cut[:i]
	}
	return cut + "\n… truncated; the full detail is in the panel"
}

// asMap normalizes a value into a map, whether it arrived as a struct or as JSON
// already decoded from a persisted delivery.
//
// The round trip through JSON is what makes the same formatter work in both cases:
// a first attempt hands over a schema.Verdict, and a retry hands over whatever
// json.Unmarshal produced from the stored payload.
func asMap(v any) map[string]any {
	switch t := v.(type) {
	case nil:
		return map[string]any{}
	case map[string]any:
		return t
	}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func asSlice(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out []any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func asStrings(v any) []string {
	items := asSlice(v)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s := str(it); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// counts renders a level→count map in a stable order.
func counts(m map[string]any) string {
	order := []string{"confirmed", "likely", "suspicious", "clean"}
	rank := map[string]int{}
	for i, k := range order {
		rank[k] = i
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, oki := rank[keys[i]]
		rj, okj := rank[keys[j]]
		switch {
		case oki && okj:
			return ri < rj
		case oki:
			return true
		case okj:
			return false
		default:
			return keys[i] < keys[j]
		}
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		n, _ := num(m[k])
		parts = append(parts, fmt.Sprintf("%s=%.0f", k, n))
	}
	return strings.Join(parts, " ")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return "unknown"
}
