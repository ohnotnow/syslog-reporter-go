package reporter

// Small parsing and number-formatting helpers shared across the pipeline.
// Their exact behaviour is pinned by tests: splitWS is the input contract
// for rsyslog's column format, and the formatting helpers fix the report's
// number style.

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// splitWS splits on RUNS of Unicode whitespace with a maxsplit: leading
// whitespace is skipped, and once maxsplit fields have been taken the
// remainder (internal and trailing whitespace intact) becomes the final
// element. maxsplit < 0 means no limit. This is the correct parse for
// rsyslog's column format, which pads single-digit days with a double space
// ("Aug  6 ..."); strings.SplitN on a single space would produce an empty
// field there.
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

// thousands formats an integer comma-grouped: 1234567 becomes "1,234,567".
func thousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	s = groupThousands(s)
	if neg {
		return "-" + s
	}
	return s
}

// thousandsFloat rounds to a whole number (ties to even, as Go's %.0f does)
// and comma-groups the result.
func thousandsFloat(x float64) string {
	s := fmt.Sprintf("%.0f", x)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	s = groupThousands(s)
	if neg {
		return "-" + s
	}
	return s
}

// compactFloat renders 6 significant digits with trailing zeros stripped,
// switching to exponent notation at 1e6 and below 1e-4 (the C %g rules,
// which Go's 'g' verb with an explicit precision follows).
func compactFloat(x float64) string {
	return fmt.Sprintf("%.6g", x)
}
