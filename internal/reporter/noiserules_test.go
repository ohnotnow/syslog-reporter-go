package reporter

// Tests for the bundled noise rules file and its parser.

import (
	"strings"
	"testing"
)

func TestParseNoiseRulesFormat(t *testing.T) {
	const file = `# a comment line

Hello recv from server
snapd-desktop            # bit brutal, but it spams like hell
named\[\d+\]: client \S+#\d+ denied   # a glued # stays in the pattern
host=*lab* (?i)usb   # lab machines' usb chatter
	tabbed	# tab before the hash
`
	rules, err := ParseNoiseRules(strings.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	want := []NoiseRule{
		{Host: "*", Match: `Hello recv from server`, Reason: DefaultNoiseReason, Line: 3},
		{Host: "*", Match: `snapd-desktop`, Reason: "bit brutal, but it spams like hell", Line: 4},
		{Host: "*", Match: `named\[\d+\]: client \S+#\d+ denied`, Reason: "a glued # stays in the pattern", Line: 5},
		{Host: "*lab*", Match: `(?i)usb`, Reason: "lab machines' usb chatter", Line: 6},
		{Host: "*", Match: `tabbed`, Reason: "tab before the hash", Line: 7},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d:\n got %+v\nwant %+v", i, rules[i], want[i])
		}
	}
}

func TestParseNoiseRulesNamesTheBadLine(t *testing.T) {
	cases := map[string]string{
		"ok\n\n# c\nfine\nalso fine\nstill\nbroken(\n": "line 7",
		"host=*lab*\n":      "line 1",
		"x\n(   # reason\n": "line 2",
	}
	for file, want := range cases {
		_, err := ParseNoiseRules(strings.NewReader(file))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error naming %s", file, err, want)
		}
	}
}

func TestBundledNoiseRulesParse(t *testing.T) {
	rules, err := BundledNoiseRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 100 {
		t.Errorf("only %d bundled rules parsed; the embedded file looks truncated", len(rules))
	}
	for _, r := range rules {
		if r.Host != "*" && !strings.Contains(r.Host, "lab") {
			t.Errorf("line %d: unexpected host glob %q in the bundled file", r.Line, r.Host)
		}
	}
}
