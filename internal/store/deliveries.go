package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DeliveryStatus is the state of an alert delivery.
type DeliveryStatus string

const (
	DeliveryPending   DeliveryStatus = "pending"
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryFailed    DeliveryStatus = "failed"
)

// Delivery is one attempt to notify the user.
//
// Persisted before it goes out: if the process dies halfway (the host kills
// long-running processes), the pending delivery is resumed instead of lost.
type Delivery struct {
	DeliveryID string
	// Channel: "email" or "webhook".
	Channel string
	// Target: the webhook id or the recipient list.
	Target      string
	Event       string
	PayloadJSON string

	Status        DeliveryStatus
	Attempts      int
	HTTPStatus    int
	Error         string
	CreatedAt     time.Time
	LastAttemptAt time.Time
	NextAttemptAt time.Time
	DeliveredAt   time.Time
}

// EnqueueDelivery records a pending delivery.
func (s *Store) EnqueueDelivery(ctx context.Context, d Delivery) error {
	if d.Status == "" {
		d.Status = DeliveryPending
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO deliveries (
			delivery_id, channel, target, event, payload_json, status,
			attempts, created_at, next_attempt_at
		) VALUES (?,?,?,?,?,?,?,?,?)`,
		d.DeliveryID, d.Channel, d.Target, d.Event, d.PayloadJSON, string(d.Status),
		d.Attempts, formatTime(orNow(d.CreatedAt)), nullTime(d.NextAttemptAt))
	if err != nil {
		return fmt.Errorf("enqueueing delivery %s: %w", d.DeliveryID, err)
	}
	return nil
}

// RecordAttempt records the result of one attempt.
//
// The delivery_id is stable across attempts (the webhook contract): the
// destination uses that id for idempotency. That is why an attempt updates the
// row instead of creating another one.
func (s *Store) RecordAttempt(ctx context.Context, id string, ok bool, httpStatus int, errMsg string, nextAttempt time.Time) error {
	status := DeliveryPending
	var deliveredAt any
	switch {
	case ok:
		status = DeliveryDelivered
		deliveredAt = nowUTC()
	case nextAttempt.IsZero():
		// With no next attempt scheduled, the chances are used up.
		status = DeliveryFailed
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE deliveries
		SET status = ?, attempts = attempts + 1, http_status = ?, error = ?,
		    last_attempt_at = ?, next_attempt_at = ?, delivered_at = ?
		WHERE delivery_id = ?`,
		string(status), nullInt(httpStatus), nullString(errMsg), nowUTC(),
		nullTime(nextAttempt), deliveredAt, id)
	if err != nil {
		return fmt.Errorf("recording an attempt for %s: %w", id, err)
	}
	return checkAffected(res, id)
}

// PendingDeliveries returns deliveries ready for another attempt.
func (s *Store) PendingDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	q := deliverySelect + `
		WHERE status = ? AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		ORDER BY created_at`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, string(DeliveryPending), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("looking for pending deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDelivery looks a delivery up.
func (s *Store) GetDelivery(ctx context.Context, id string) (Delivery, error) {
	row := s.db.QueryRowContext(ctx, deliverySelect+` WHERE delivery_id = ?`, id)
	d, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return d, fmt.Errorf("%w: delivery %s", ErrNotFound, id)
	}
	return d, err
}

// ListDeliveries returns the history for a channel/target. It feeds the panel's
// "last delivery" column.
func (s *Store) ListDeliveries(ctx context.Context, channel, target string, limit int) ([]Delivery, error) {
	q := deliverySelect + ` WHERE 1=1`
	var args []any
	if channel != "" {
		q += ` AND channel = ?`
		args = append(args, channel)
	}
	if target != "" {
		q += ` AND target = ?`
		args = append(args, target)
	}
	q += ` ORDER BY created_at DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

const deliverySelect = `
	SELECT delivery_id, channel, target, event, payload_json, status, attempts,
	       http_status, error, created_at, last_attempt_at, next_attempt_at, delivered_at
	FROM deliveries`

func scanDelivery(r rowScanner) (Delivery, error) {
	var (
		d                            Delivery
		status                       string
		httpStatus                   sql.NullInt64
		errMsg                       sql.NullString
		created                      string
		lastAttempt, next, delivered sql.NullString
	)
	err := r.Scan(&d.DeliveryID, &d.Channel, &d.Target, &d.Event, &d.PayloadJSON,
		&status, &d.Attempts, &httpStatus, &errMsg, &created,
		&lastAttempt, &next, &delivered)
	if err != nil {
		return d, err
	}
	d.Status = DeliveryStatus(status)
	if httpStatus.Valid {
		d.HTTPStatus = int(httpStatus.Int64)
	}
	d.Error = strFromNull(errMsg)
	d.CreatedAt = parseTime(created)
	d.LastAttemptAt = timeFromNull(lastAttempt)
	d.NextAttemptAt = timeFromNull(next)
	d.DeliveredAt = timeFromNull(delivered)
	return d, nil
}

func nullInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
