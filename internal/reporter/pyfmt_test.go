package reporter

import (
	"reflect"
	"testing"
)

// Expected values in these tests were captured from CPython 3.13 on
// 2026-08-28 (format(x, 'g'), format(x, ','), format(x, ',.0f'),
// str.split(None, 4)); the helpers must keep matching them.

func TestSplitWSMimicsPythonSplit(t *testing.T) {
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

func TestPyGMatchesPythonGFormat(t *testing.T) {
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
		if got := pyG(c.in); got != c.want {
			t.Errorf("pyG(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPyThousandsMatchesPythonCommaFormat(t *testing.T) {
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
		if got := pyThousands(c.in); got != c.want {
			t.Errorf("pyThousands(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPyCommaF0MatchesPythonCommaPointZeroF(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{2.5, "2"}, // Python rounds half to even, and so does Go's %.0f
		{3.5, "4"},
		{1234567.5, "1,234,568"},
		{100.0, "100"},
		{999.4, "999"},
	}
	for _, c := range cases {
		if got := pyCommaF0(c.in); got != c.want {
			t.Errorf("pyCommaF0(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
