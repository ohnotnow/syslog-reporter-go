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
// A line whose message came from several hosts also carries a spread tag,
// "[on 1012 hosts] ", in front of it (tagSpread). The detection prompt
// explains both; stripRepeatTag removes them from the example the model
// copies back, so the example is a real log line again.
var repeatTag = regexp.MustCompile(`^(\[(x\d+ [^\]]*|on \d+ hosts)\] )+`)

// tagSpread prefixes each line whose message spread says came from more
// than one host with "[on N hosts] ". Lines already carry any repeat tag;
// the key is taken from the line after it, as the dedupe took it.
func tagSpread(lines []string, spread map[string]int) []string {
	if len(spread) == 0 {
		return lines
	}
	out := make([]string, len(lines))
	for i, line := range lines {
		key, _ := dedupeKey(repeatTag.ReplaceAllString(line, ""))
		if n := spread[key]; n > 1 {
			line = fmt.Sprintf("[on %d hosts] %s", n, line)
		}
		out[i] = line
	}
	return out
}

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
