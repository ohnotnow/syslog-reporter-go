package reporter

import (
	"reflect"
	"testing"
)

// These vectors pin the exact split semantics and number formats the
// report depends on (captured 2026-08-28); the helpers must keep matching
// them, or report output changes shape.

func TestSplitWSSplitsOnWhitespaceRuns(t *testing.T) {
	cases := []struct {
		in       string
		maxsplit int
		want     []string
	}{
		{"  a  b c d  e  f  ", 4, []string{"a", "b", "c", "d", "e  f  "}},
		{"a b c", 4, []string{"a", "b", "c"}},
		{"a\tb\t c d e f", 4, []string{"a", "b", "c", "d", "e f"}},
		{"", 4, nil},
		{"   ", 4, nil},
		{"one", 0, []string{"one"}},
		{"  lead kept  rest  ", 1, []string{"lead", "kept  rest  "}},
		{"a b", -1, []string{"a", "b"}},
	}
	for _, c := range cases {
		got := splitWS(c.in, c.maxsplit)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitWS(%q, %d) = %#v, want %#v", c.in, c.maxsplit, got, c.want)
		}
	}
}

func TestCompactFloatSixSignificantDigits(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{2.5, "2.5"},
		{123456.5, "123456"},
		{1234567.0, "1.23457e+06"},
		{0.5, "0.5"},
		{100.0, "100"},
		{1e-05, "1e-05"},
		{12345678.0, "1.23457e+07"},
		{0.0, "0"},
		{42.0, "42"},
	}
	for _, c := range cases {
		if got := compactFloat(c.in); got != c.want {
			t.Errorf("compactFloat(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestThousandsCommaGroups(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{-1234567, "-1,234,567"},
	}
	for _, c := range cases {
		if got := thousands(c.in); got != c.want {
			t.Errorf("thousands(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestThousandsFloatRoundsThenGroups(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{2.5, "2"}, // %.0f rounds half to even
		{3.5, "4"},
		{1234567.5, "1,234,568"},
		{100.0, "100"},
		{999.4, "999"},
	}
	for _, c := range cases {
		if got := thousandsFloat(c.in); got != c.want {
			t.Errorf("thousandsFloat(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
