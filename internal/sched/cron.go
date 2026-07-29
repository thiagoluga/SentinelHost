package sched

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a 5-field cron schedule.
//
// A minimal in-house implementation rather than a dependency: the project uses
// exactly one schedule format, for one use case, and "no mandatory external
// dependencies" is a principle, not a preference (Principle VII).
type Schedule struct {
	Minutes  []int
	Hours    []int
	Days     []int
	Months   []int
	Weekdays []int
}

// ParseCron interprets "minute hour day month weekday".
//
// It supports `*`, lists (`1,15`), ranges (`1-5`) and steps (`*/15`). It does not
// support names (`MON`, `JAN`) or `@daily`: what the tool generates and documents
// uses only numbers, and accepting syntax we do not generate would grow the bug
// surface for no benefit.
func ParseCron(expr string) (Schedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return Schedule{}, fmt.Errorf("a cron needs 5 fields, got %d in %q", len(fields), expr)
	}

	var s Schedule
	var err error
	if s.Minutes, err = parseField(fields[0], 0, 59); err != nil {
		return s, fmt.Errorf("minute field: %w", err)
	}
	if s.Hours, err = parseField(fields[1], 0, 23); err != nil {
		return s, fmt.Errorf("hour field: %w", err)
	}
	if s.Days, err = parseField(fields[2], 1, 31); err != nil {
		return s, fmt.Errorf("day field: %w", err)
	}
	if s.Months, err = parseField(fields[3], 1, 12); err != nil {
		return s, fmt.Errorf("month field: %w", err)
	}
	if s.Weekdays, err = parseField(fields[4], 0, 6); err != nil {
		return s, fmt.Errorf("weekday field: %w", err)
	}
	return s, nil
}

// Matches answers whether an instant matches the schedule.
//
// It follows traditional cron's rule: when day-of-month and day-of-week are both
// restricted, only ONE of them has to match. It is counter-intuitive, but it is
// what every administrator expects from a cron line.
func (s Schedule) Matches(t time.Time) bool {
	if !contains(s.Minutes, t.Minute()) ||
		!contains(s.Hours, t.Hour()) ||
		!contains(s.Months, int(t.Month())) {
		return false
	}

	dayRestricted := len(s.Days) < 31
	weekRestricted := len(s.Weekdays) < 7
	dayMatches := contains(s.Days, t.Day())
	weekMatches := contains(s.Weekdays, int(t.Weekday()))

	switch {
	case dayRestricted && weekRestricted:
		return dayMatches || weekMatches
	case dayRestricted:
		return dayMatches
	case weekRestricted:
		return weekMatches
	default:
		return true
	}
}

func parseField(field string, min, max int) ([]int, error) {
	var out []int
	seen := map[int]bool{}

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty value")
		}

		step := 1
		if base, p, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid step in %q", part)
			}
			step = n
			part = base
		}

		start, end := min, max
		switch {
		case part == "*":
			// the whole range
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			var err error
			if start, err = strconv.Atoi(strings.TrimSpace(a)); err != nil {
				return nil, fmt.Errorf("invalid start in %q", part)
			}
			if end, err = strconv.Atoi(strings.TrimSpace(b)); err != nil {
				return nil, fmt.Errorf("invalid end in %q", part)
			}
		default:
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value: %q", part)
			}
			start, end = n, n
		}

		if start < min || end > max || start > end {
			return nil, fmt.Errorf("value out of the %d-%d range: %q", min, max, part)
		}
		for v := start; v <= end; v += step {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("field with no values")
	}
	return out, nil
}

func contains(vs []int, v int) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}
