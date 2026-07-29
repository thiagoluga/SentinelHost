package alert

import (
	"context"
	"fmt"
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
	vs, err := d.store.ListVerdicts(ctx, store.VerdictFilter{IncludeClean: true, Limit: 2000})
	if err != nil {
		return false, err
	}

	counts := map[schema.Level]int{}
	actions := map[schema.ActionTaken]int{}
	var pending []schema.Verdict
	relevant := 0

	for _, v := range vs {
		if v.CreatedAt.Before(start) || v.CreatedAt.After(end) {
			continue
		}
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
