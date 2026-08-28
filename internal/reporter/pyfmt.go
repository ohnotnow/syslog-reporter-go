package reporter

// Helpers that reproduce specific Python stdlib semantics the report's
// byte-parity contract depends on. Each mirrors one CPython behaviour;
// change them only against a fresh diff with the Python original.

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// splitWS mimics Python's str.split(None, maxsplit): runs of Unicode
// whitespace separate fields, leading whitespace is skipped, and once
// maxsplit fields have been taken the remainder (internal and trailing
// whitespace intact) becomes the final element. maxsplit < 0 means no limit.
func splitWS(s string, maxsplit int) []string {
	var parts []string
	i, n := 0, len(s)
	for i < n {
		r, w := utf8.DecodeRuneInString(s[i:])
		if unicode.IsSpace(r) {
			i += w
			continue
		}
		if maxsplit >= 0 && len(parts) == maxsplit {
			parts = append(parts, s[i:])
			return parts
		}
		j := i
		for j < n {
			r, w := utf8.DecodeRuneInString(s[j:])
			if unicode.IsSpace(r) {
				break
			}
			j += w
		}
		parts = append(parts, s[i:j])
		i = j
	}
	return parts
}

// pyStrip mimics Python's str.strip(): trims Unicode whitespace from both ends.
func pyStrip(s string) string {
	return strings.TrimFunc(s, unicode.IsSpace)
}

// groupThousands inserts commas into a plain digit string ("1234567" becomes "1,234,567").
func groupThousands(digits string) string {
	n := len(digits)
	if n <= 3 {
		return digits
	}
	var b strings.Builder
	head := n % 3
	if head > 0 {
		b.WriteString(digits[:head])
	}
	for i := head; i < n; i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[i : i+3])
	}
	return b.String()
}

// pyThousands mimics Python's format(n, ','): comma-grouped integer.
func pyThousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	s = groupThousands(s)
	if neg {
		return "-" + s
	}
	return s
}

// pyCommaF0 mimics Python's format(x, ',.0f'): rounded to no decimal places
// (ties to even, which Go's %.0f also does) and comma-grouped.
func pyCommaF0(x float64) string {
	s := fmt.Sprintf("%.0f", x)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	s = groupThousands(s)
	if neg {
		return "-" + s
	}
	return s
}

// pyG mimics Python's format(x, 'g'): 6 significant digits, trailing zeros
// stripped, switching to exponent notation at 1e6 and below 1e-4. These are
// the C %g rules, which Go's 'g' verb with an explicit precision also follows.
func pyG(x float64) string {
	return fmt.Sprintf("%.6g", x)
}
