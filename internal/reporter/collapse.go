package reporter

// Collapsing repeats before the issue detector (ait srg-kQYKT): a crash
// loop logging the same message hundreds of thousands of times cost 25M
// prompt tokens on 28 Sep 2026, and the detector had found it in the first
// chunk. Lines sharing host + program + masked message go to the model as
// ONE real example carrying a count and the first and last timestamps, so
// a flood costs about what a quiet day does and is still reported with its
// scale. Only the detector's input changes: --dump-filtered, the context
// index and the anomaly detectors all keep the raw lines.

import (
	"fmt"
	"regexp"
	"strings"
)

// repeatTag prefixes a collapsed line: "[x364112 00:00:03-23:59:58] ".
// The detection prompt explains it; stripRepeatTag removes it from the
// example the model copies back, so the example is a real log line again.
var repeatTag = regexp.MustCompile(`^\[x\d+ [^\]]*\] `)

// CollapseRepeats returns lines with every repeat of a host + program +
// masked message folded into its first occurrence, tagged with the count
// and the first and last timestamps. Order is first-seen, so the output is
// deterministic. Lines ParseLine rejects pass through untouched, as do
// shapes seen only once.
func CollapseRepeats(lines []string) []string {
	type group struct {
		first       int // index into out
		count       int
		start, last string
	}
	groups := map[string]*group{}
	var out []string
	var order []*group // groups in out order, for the tagging pass
	for _, line := range lines {
		program, template, _, ok := Template(line)
		if !ok {
			out = append(out, line)
			continue
		}
		parts := splitWS(line, 4)
		stamp := parts[2]
		key := parts[3] + "\x00" + program + "\x00" + template
		if g, seen := groups[key]; seen {
			g.count++
			g.last = stamp
			continue
		}
		g := &group{first: len(out), count: 1, start: stamp, last: stamp}
		groups[key] = g
		order = append(order, g)
		out = append(out, line)
	}
	for _, g := range order {
		if g.count > 1 {
			out[g.first] = fmt.Sprintf("[x%d %s-%s] %s", g.count, g.start, g.last, out[g.first])
		}
	}
	return out
}

// stripRepeatTag removes a collapse tag the model copied into an example.
func stripRepeatTag(s string) string {
	return repeatTag.ReplaceAllString(strings.TrimSpace(s), "")
}
