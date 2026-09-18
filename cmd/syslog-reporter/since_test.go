package main

import (
	"strings"
	"testing"
	"time"
)

func TestSinceFlagShapes(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2026-09-01", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
		{"1h", now.Add(-time.Hour)},
		{"36h", now.Add(-36 * time.Hour)},
		{"90m", now.Add(-90 * time.Minute)},
		{"3d", now.AddDate(0, 0, -3)},
		{"2w", now.AddDate(0, 0, -14)},
	}
	for _, c := range cases {
		s := sinceFlag{now: func() time.Time { return now }}
		if err := s.Set(c.in); err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if !s.t.Equal(c.want) {
			t.Errorf("%q: got %v, want %v", c.in, s.t, c.want)
		}
		if s.String() != c.in {
			t.Errorf("%q: String() = %q", c.in, s.String())
		}
	}
}

func TestSinceFlagRejectsWithTheDocumentedMessage(t *testing.T) {
	for _, in := range []string{"1x", "yesterday", "", "-2h", "0h"} {
		var s sinceFlag
		err := s.Set(in)
		if err == nil || !strings.Contains(err.Error(), "1h, 36h, 3d or 2w, or a date YYYY-MM-DD") {
			t.Errorf("%q: got %v", in, err)
		}
	}
}

func TestSinceFlagZeroValueIncludesEverything(t *testing.T) {
	var s sinceFlag
	if !s.Includes(time.Time{}) || !s.Includes(time.Now()) {
		t.Error("an unset --since should include every entry")
	}
	now := time.Now()
	bounded := sinceFlag{now: func() time.Time { return now }}
	if err := bounded.Set("1h"); err != nil {
		t.Fatal(err)
	}
	if bounded.Includes(now.Add(-2*time.Hour)) || !bounded.Includes(now.Add(-time.Minute)) {
		t.Error("--since 1h should exclude a two-hour-old entry and include a one-minute-old one")
	}
}
