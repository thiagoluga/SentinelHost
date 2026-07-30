package webhook

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The shape each destination accepts is documented, not guessed:
//
//   - Slack incoming webhooks: a JSON object whose `text` is the message
//     (https://api.slack.com/messaging/webhooks).
//   - Discord webhooks: a JSON object whose `content` is the message, capped at
//     2000 characters (https://discord.com/developers/docs/resources/webhook).
//
// D-022 is the reason these tests assert the envelope's own key is ABSENT rather
// than only that ours is present: posting our envelope was the bug, and a
// formatter that added `text` while still sending `schema_version` alongside it
// would pass a weaker test and still read wrong in the channel.

func sampleEnvelope() Envelope {
	return Envelope{
		SchemaVersion: "1.0",
		Event:         "verdict.confirmed",
		DeliveryID:    "d_20260730_0001",
		OccurredAt:    time.Unix(1785815082, 0),
		Instance:      Instance{ID: "i_a1b2", Hostname: "srv12.hosting.test", Root: "/home/user/public_html"},
		Data: map[string]any{
			"level":          "confirmed",
			"score":          0.95,
			"file_path":      "/home/user/public_html/wp-content/uploads/2026/07/cache.php",
			"action_taken":   "quarantined",
			"quarantine_ref": "q_1",
			"abstentions":    []any{"php-malware-finder"},
			"votes": []any{
				map[string]any{
					"engine": "maldet", "weight": 1.0, "confidence": "signature",
					"effective_weight": 1.0, "rule": "php.corpus.marker.v1",
				},
				map[string]any{
					"engine": "amwscan", "weight": 0.8, "confidence": "signature",
					"effective_weight": 0.8, "rule": "Signature",
				},
			},
		},
	}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("the body is not a JSON object: %v\n%s", err, b)
	}
	return m
}

func TestSlackBodyUsesTextAndNothingElse(t *testing.T) {
	b, err := Body("slack", sampleEnvelope())
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	m := decode(t, b)

	text, ok := m["text"].(string)
	if !ok || text == "" {
		t.Fatalf("Slack needs a non-empty `text`, got %v", m)
	}
	// The bug this closes: posting our envelope. If it is still in there, the
	// message arrives wrong even though `text` exists.
	for _, k := range []string{"schema_version", "event", "delivery_id", "instance", "data"} {
		if _, present := m[k]; present {
			t.Errorf("the envelope key %q leaked into the Slack body", k)
		}
	}
}

func TestDiscordBodyUsesContentAndRespectsTheLimit(t *testing.T) {
	b, err := Body("discord", sampleEnvelope())
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	m := decode(t, b)

	content, ok := m["content"].(string)
	if !ok || content == "" {
		t.Fatalf("Discord needs a non-empty `content`, got %v", m)
	}
	// Discord rejects content over 2000 characters outright, and a rejected
	// delivery retries five times before being recorded as failed.
	if len([]rune(content)) > 2000 {
		t.Errorf("the content has %d characters; Discord rejects over 2000", len([]rune(content)))
	}
	for _, k := range []string{"schema_version", "event", "delivery_id", "instance", "data"} {
		if _, present := m[k]; present {
			t.Errorf("the envelope key %q leaked into the Discord body", k)
		}
	}
}

func TestTheChatMessageCarriesTheVotes(t *testing.T) {
	// A chat alert that says "threat confirmed" and nothing else forces the user
	// into the panel to learn anything — and the votes are the whole point of a
	// consensus verdict (Principle V).
	b, _ := Body("slack", sampleEnvelope())
	text := decode(t, b)["text"].(string)

	for _, want := range []string{
		"CONFIRMED",
		"cache.php",
		"0.95",
		"maldet",
		"amwscan",
		"php.corpus.marker.v1",
		"php-malware-finder", // the abstention
		"q_1",                // the quarantine ref: the file is restorable
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the message does not mention %q:\n%s", want, text)
		}
	}
	// The coverage travels with the alert, as everywhere else in this project.
	if !strings.Contains(text, "coverage was reduced") {
		t.Errorf("the abstention did not carry its consequence:\n%s", text)
	}
}

func TestRawFormatStillSendsTheEnvelope(t *testing.T) {
	// Every webhook configured before the format field existed has no format.
	// Changing their body shape would break deliveries that work today.
	for _, format := range []string{"raw", ""} {
		b, err := Body(format, sampleEnvelope())
		if err != nil {
			t.Fatalf("Body(%q): %v", format, err)
		}
		m := decode(t, b)
		if m["schema_version"] != "1.0" || m["event"] != "verdict.confirmed" {
			t.Errorf("Body(%q) is not the envelope: %v", format, m)
		}
		if _, present := m["text"]; present {
			t.Errorf("Body(%q) should not be chat-shaped", format)
		}
	}
}

func TestAnUnknownFormatIsAnErrorRatherThanAQuietFallback(t *testing.T) {
	// Falling back to raw would deliver successfully in the wrong shape — the kind
	// of quiet wrongness this project treats as a defect.
	if _, err := Body("teams", sampleEnvelope()); err == nil {
		t.Fatal("an unknown format should be an error")
	}
}

// Escaping ---------------------------------------------------------------------

func TestSlackMentionsInAFilePathCannotPingTheWorkspace(t *testing.T) {
	// The file path is chosen by the ATTACKER. `<!channel>.php` is a legitimate
	// filename and a perfectly good way to make our own alert ping everyone.
	env := sampleEnvelope()
	env.Data = map[string]any{
		"level":     "confirmed",
		"file_path": "/site/<!channel>.php",
	}
	b, _ := Body("slack", env)
	text := decode(t, b)["text"].(string)

	if strings.Contains(text, "<!channel>") {
		t.Errorf("the Slack mention survived escaping:\n%s", text)
	}
	if !strings.Contains(text, "&lt;!channel&gt;") {
		t.Errorf("the path was not escaped as expected:\n%s", text)
	}
}

func TestDiscordMentionsAndMarkupInAFilePathAreNeutralized(t *testing.T) {
	env := sampleEnvelope()
	env.Data = map[string]any{
		"level":     "confirmed",
		"file_path": "/site/@everyone_**x**.php",
	}
	b, _ := Body("discord", env)
	content := decode(t, b)["content"].(string)

	if strings.Contains(content, "@everyone") {
		t.Errorf("@everyone survived escaping and would ping the server:\n%s", content)
	}
	if strings.Contains(content, "**x**") {
		t.Errorf("the markdown survived escaping:\n%s", content)
	}
}

func TestAVeryLongMessageIsTruncatedAndSaysSo(t *testing.T) {
	// A message silently cut at a boundary would hide the very votes it exists to
	// show.
	votes := make([]any, 0, 200)
	for i := 0; i < 200; i++ {
		votes = append(votes, map[string]any{
			"engine": strings.Repeat("engine", 4), "weight": 1.0,
			"confidence": "signature", "effective_weight": 1.0,
			"rule": strings.Repeat("rule", 10),
		})
	}
	env := sampleEnvelope()
	env.Data = map[string]any{"level": "confirmed", "file_path": "/site/x.php", "votes": votes}

	b, _ := Body("discord", env)
	content := decode(t, b)["content"].(string)
	if len([]rune(content)) > 2000 {
		t.Fatalf("still over Discord's limit: %d characters", len([]rune(content)))
	}
	if !strings.Contains(content, "truncated") {
		t.Errorf("the truncation was silent:\n%s", content)
	}
}

// Every event reaches the channel ----------------------------------------------

func TestEveryContractEventProducesAMessage(t *testing.T) {
	// An event the formatter does not know about still has to be delivered:
	// dropping it would be a silent gap exactly where the user asked to be told.
	cases := map[string]any{
		"verdict.confirmed":  map[string]any{"level": "confirmed", "file_path": "/site/a.php"},
		"verdict.likely":     map[string]any{"level": "likely", "file_path": "/site/b.php"},
		"verdict.suspicious": map[string]any{"level": "suspicious", "file_path": "/site/c.php"},
		"quarantine.action": map[string]any{
			"action": "quarantined", "original_path": "/site/d.php",
			"quarantine_ref": "q_2", "reversible": true,
		},
		"scan.completed": map[string]any{
			"status": "completed", "mode": "incremental",
			"files_scanned": 412, "files_considered": 18234,
			"verdicts": map[string]any{"confirmed": 1, "likely": 0, "suspicious": 3, "clean": 408},
			"engines_abstained": []any{
				map[string]any{"engine": "maldet", "reason": "the binary was not found on PATH"},
			},
		},
		"engine.failed": map[string]any{
			"engine": "amwscan", "status": "timeout", "error": "timeout after 300s",
		},
		"something.new": map[string]any{},
	}

	for event, data := range cases {
		for _, format := range []string{"slack", "discord"} {
			env := sampleEnvelope()
			env.Event = event
			env.Data = data

			b, err := Body(format, env)
			if err != nil {
				t.Errorf("%s/%s: %v", event, format, err)
				continue
			}
			m := decode(t, b)
			key := "text"
			if format == "discord" {
				key = "content"
			}
			msg, _ := m[key].(string)
			if msg == "" {
				t.Errorf("%s/%s produced an empty message", event, format)
			}
			if !strings.Contains(msg, "SentinelHost") {
				t.Errorf("%s/%s does not identify the sender:\n%s", event, format, msg)
			}
		}
	}
}

func TestAnAbstainedCycleNeverReadsAsClean(t *testing.T) {
	// Principle VI in the channel: a cycle in which engines failed must not look
	// like a clean cycle.
	env := sampleEnvelope()
	env.Event = "scan.completed"
	env.Data = map[string]any{
		"status": "completed", "mode": "incremental",
		"verdicts": map[string]any{"confirmed": 0, "likely": 0, "suspicious": 0, "clean": 500},
		"engines_abstained": []any{
			map[string]any{"engine": "amwscan", "reason": "PHP CLI not found"},
			map[string]any{"engine": "maldet", "reason": "the binary was not found on PATH"},
		},
	}
	b, _ := Body("slack", env)
	text := decode(t, b)["text"].(string)

	if !strings.Contains(text, "abstained") {
		t.Errorf("the abstentions are missing from the summary:\n%s", text)
	}
	for _, want := range []string{"amwscan", "PHP CLI not found", "maldet"} {
		if !strings.Contains(text, want) {
			t.Errorf("the summary does not name %q:\n%s", want, text)
		}
	}
}

// A retry has to render identically -------------------------------------------

func TestARetryRendersTheSameMessageAsTheFirstAttempt(t *testing.T) {
	// The first attempt hands over a typed struct; a retry hands over whatever
	// json.Unmarshal produced from the persisted payload. If the formatter only
	// worked for one of them, every retry to Slack would arrive degraded — and a
	// retry is exactly the path nobody watches.
	first := sampleEnvelope()
	firstBody, err := Body("slack", first)
	if err != nil {
		t.Fatalf("first attempt: %v", err)
	}

	stored, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var revived Envelope
	if err := json.Unmarshal(stored, &revived); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	retryBody, err := Body("slack", revived)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}

	if decode(t, firstBody)["text"] != decode(t, retryBody)["text"] {
		t.Errorf("the retry rendered differently:\nfirst: %s\nretry: %s", firstBody, retryBody)
	}
}

func TestTheSignatureCoversTheBodyThatWasActuallySent(t *testing.T) {
	// Signing the envelope while POSTing a Slack body would produce a signature
	// nobody could ever verify. Neither Slack nor Discord checks one, but a
	// signature that does not match its own body is a lie in a header.
	env := sampleEnvelope()
	body, err := Body("slack", env)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	ts := env.OccurredAt.Unix()
	sig := Sign("secret", ts, body)
	if !Verify("secret", ts, body, sig) {
		t.Fatal("the signature does not verify against the body it was computed over")
	}

	envelopeBody, _ := Body("raw", env)
	if Verify("secret", ts, envelopeBody, sig) {
		t.Fatal("the signature verifies against a different body")
	}
}
