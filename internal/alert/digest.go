package alert

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/alert/email"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

// SendDigestIfDue sends the periodic summary when the configured time has arrived
// and nothing has been sent yet in this period.
//
// The digest's state is read from SQLite on the spot, with nothing accumulated in
// memory: losing the process (the hosting kills long processes) must not lose the
// day's summary. It returns true when it sent.
func (d *Dispatcher) SendDigestIfDue(ctx context.Context) (bool, error) {
	e := d.cfg.Alerts.Email
	if !e.Enabled || !e.DigestEnabled {
		return false, nil
	}

	now := d.now()
	at, err := parseTimeOfDay(e.DigestAt)
	if err != nil {
		return false, fmt.Errorf("invalid alerts.email.digest_at: %w", err)
	}

	last, err := d.lastDigestAt(ctx)
	if err != nil {
		return false, err
	}

	// The digest's window closes at today's configured time. If the time has not
	// arrived yet, or if we already sent after it, there is nothing to do.
	closes := time.Date(now.Year(), now.Month(), now.Day(),
		at.hour, at.minute, 0, 0, now.Location())
	if now.Before(closes) {
		return false, nil
	}
	if !last.IsZero() && !last.Before(closes) {
		return false, nil
	}

	start := closes.AddDate(0, 0, -1)
	if !last.IsZero() && last.After(start) {
		start = last
	}

	sent, err := d.sendDigest(ctx, start, now)
	if err != nil {
		return false, err
	}
	if sent {
		if err := d.store.SetSetting(ctx, store.KeyLastDigestAt, now.UTC().Format(time.RFC3339)); err != nil {
			return true, err
		}
	}
	return sent, nil
}

// SendDigestNow sends the summary for the period asked for, ignoring the schedule.
// Used by the panel's button and by the CLI.
func (d *Dispatcher) SendDigestNow(ctx context.Context, since time.Time) error {
	_, err := d.sendDigest(ctx, since, d.now())
	return err
}

func (d *Dispatcher) sendDigest(ctx context.Context, start, end time.Time) (bool, error) {
	// The window goes to the database, not to a loop afterwards.
	//
	// This used to fetch the 2000 most recent verdicts and compare dates in Go. A window
	// holding more than 2000 was reported as if the subset were the whole; and because the
	// 2000 were the most recent OVERALL, verdicts newer than `end` consumed the budget
	// first — so a summary of yesterday, sent today, could report nothing at all for a day
	// that had hundreds. An empty digest and a digest that never looked read identically.
	const cap = 5000
	vs, err := d.store.ListVerdicts(ctx, store.VerdictFilter{
		IncludeClean: true,
		Since:        start,
		Until:        end,
		Limit:        cap,
	})
	if err != nil {
		return false, err
	}
	// A cap still exists, because a digest is an e-mail and not a database dump. When it
	// bites, the mail says so: silent truncation is the failure this project is built to
	// avoid, and a count that quietly means "at least" is exactly that.
	truncated := len(vs) == cap

	counts := map[schema.Level]int{}
	actions := map[schema.ActionTaken]int{}
	var pending []schema.Verdict
	relevant := 0

	for _, v := range vs {
		counts[v.Level]++
		actions[v.ActionTaken]++
		if v.Level != schema.LevelClean {
			relevant++
		}
		if !v.AcknowledgedByUser && v.Level.AtLeast(schema.LevelSuspicious) &&
			(v.ActionTaken == schema.ActionNone || v.ActionTaken == schema.ActionRecommended) {
			pending = append(pending, v)
		}
	}

	// The digest goes out even with no critical incident, as long as there are
	// suspicions piled up (scenario 2 of US4). An empty summary every day would
	// train the user not to open the e-mail.
	if relevant == 0 {
		return false, nil
	}

	msg := email.DigestMessage(start, end, counts, actions, pending, d.cfg.Alerts.Email.PanelURL)
	if truncated {
		notice := fmt.Sprintf("\n\nThis summary covers the most recent %d verdicts of the "+
			"period; there were more. Open the panel for the complete list.\n", cap)
		msg.Text += notice
		if msg.HTML != "" {
			msg.HTML += "<p><strong>" + html.EscapeString(strings.TrimSpace(notice)) + "</strong></p>"
		}
	}
	if err := d.mailer.Send(ctx, msg); err != nil {
		return false, fmt.Errorf("sending the digest: %w", err)
	}
	return true, nil
}

func (d *Dispatcher) lastDigestAt(ctx context.Context) (time.Time, error) {
	s, err := d.store.GetSetting(ctx, store.KeyLastDigestAt)
	if err != nil {
		return time.Time{}, err
	}
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

type timeOfDay struct{ hour, minute int }

func parseTimeOfDay(s string) (timeOfDay, error) {
	if s == "" {
		s = "08:00"
	}
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return timeOfDay{}, fmt.Errorf("use the HH:MM format, got %q", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return timeOfDay{}, fmt.Errorf("time out of range: %q", s)
	}
	return timeOfDay{h, m}, nil
}
