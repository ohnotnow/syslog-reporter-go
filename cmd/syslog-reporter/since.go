package main

// sinceFlag is the --since value shared by the commands that filter
// known-knowns by when they were created (ait srg-M3Yny.6): a duration
// like 1h or 36h (anything time.ParseDuration takes), a day or week count
// like 3d or 2w, or a plain YYYY-MM-DD date. It resolves against the wall
// clock at parse time; the zero value means "no lower bound".

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const sinceUsage = "only entries created since this long ago (1h, 36h, 3d, 2w) or since this date (YYYY-MM-DD)"

var dayWeekRe = regexp.MustCompile(`^(\d+)([dw])$`)

type sinceFlag struct {
	t   time.Time
	raw string
	now func() time.Time // wall clock; tests pin it
}

func (s *sinceFlag) String() string { return s.raw }

func (s *sinceFlag) Set(v string) error {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if d, err := time.Parse("2006-01-02", v); err == nil {
		s.t, s.raw = d, v
		return nil
	}
	if m := dayWeekRe.FindStringSubmatch(v); m != nil {
		n, _ := strconv.Atoi(m[1])
		if m[2] == "w" {
			n *= 7
		}
		s.t, s.raw = now().AddDate(0, 0, -n), v
		return nil
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		s.t, s.raw = now().Add(-d), v
		return nil
	}
	return fmt.Errorf("--since takes a duration like 1h, 36h, 3d or 2w, or a date YYYY-MM-DD (got %q)", v)
}

// Includes reports whether an entry created at t passes the bound.
func (s *sinceFlag) Includes(t time.Time) bool {
	return s.t.IsZero() || !t.Before(s.t)
}
