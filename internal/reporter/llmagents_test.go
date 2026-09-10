package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// quoteField is pinned by these vectors (captured 2026-08-28) so the
// explainer payload's quoting of free text never drifts.
func TestQuoteField(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", `'plain text'`},
		{"it's got an apostrophe", `"it's got an apostrophe"`},
		{`double "quotes" here`, `'double "quotes" here'`},
		{`both ' and " quotes`, `'both \' and " quotes'`},
		{"tab\there and newline\nhere", `'tab\there and newline\nhere'`},
		{"backslash \\ and \r carriage", `'backslash \\ and \r carriage'`},
		{"ctrl \x1b[0m chars \x07", `'ctrl \x1b[0m chars \x07'`},
		{"unicode café and   nbsp", `'unicode café and \xa0 nbsp'`},
		{"", `''`},
	}
	for _, c := range cases {
		if got := quoteField(c.in); got != c.want {
			t.Errorf("quoteField(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestChunkLines(t *testing.T) {
	if got := chunkLines(nil, 1000); got != nil {
		t.Errorf("chunking no lines should give no chunks, got %d", len(got))
	}
	lines := make([]string, 1001)
	chunks := chunkLines(lines, 1000)
	if len(chunks) != 2 || len(chunks[0]) != 1000 || len(chunks[1]) != 1 {
		t.Errorf("1001 lines should chunk 1000+1, got %d chunks", len(chunks))
	}
	chunks = chunkLines(lines[:1000], 1000)
	if len(chunks) != 1 {
		t.Errorf("1000 lines should be exactly one chunk, got %d", len(chunks))
	}
}

// The dedupe payload is two-space-indented JSON in declared field order,
// with no HTML escaping.
func TestDedupePayload(t *testing.T) {
	issues := &IssueList{Issues: []*Issue{{
		Issue:              "A <b> & 'thing'",
		Severity:           "high",
		Description:        "desc",
		ExampleLogEntry:    "entry",
		AffectedHost:       []string{"h1", "h2"},
		OS:                 "Rocky Linux 9 x2",
		AffectedService:    "svc",
		TimestampFrequency: "often",
		PotentialImpact:    "impact",
		RecommendedAction:  "act",
	}}}
	got, err := dedupePayload(issues)
	if err != nil {
		t.Fatal(err)
	}
	want := `[
  {
    "issue": "A <b> & 'thing'",
    "severity": "high",
    "description": "desc",
    "example_log_entry": "entry",
    "affected_host": [
      "h1",
      "h2"
    ],
    "os": "Rocky Linux 9 x2",
    "affected_service": "svc",
    "timestamp_frequency": "often",
    "potential_impact": "impact",
    "recommended_action": "act"
  }
]`
	if got != want {
		t.Errorf("payload mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestResolutionPromptWithoutHostOS(t *testing.T) {
	prompt := resolutionPrompt(nil, false)
	if !strings.Contains(prompt, "The primary platform is CentOS / Rocky Linux") {
		t.Error("default prompt should carry the RHEL-family assumption")
	}
	if strings.Contains(prompt, "Known host operating systems") {
		t.Error("default prompt should not mention a host OS inventory")
	}
	if !strings.Contains(prompt, "For EACH issue, provide:") {
		t.Error("prompt body missing")
	}
	if !strings.Contains(prompt, "- look_for:") {
		t.Error("prompt should ask for the look_for field (sysadmin feedback 2026-09-08)")
	}
	if strings.HasSuffix(prompt, "\n") {
		t.Error("rendered prompt should not keep the template's trailing newline")
	}
}

func TestIssueDetectionPromptWithoutHostOS(t *testing.T) {
	prompt := issueDetectionPrompt(nil)
	if strings.Contains(prompt, "Known host operating systems") {
		t.Error("default prompt should not mention a host OS inventory")
	}
	if !strings.Contains(prompt, "- os: ") {
		t.Error("os field description missing")
	}
	if !strings.Contains(prompt, `Write "unknown"`) {
		t.Error("prompt should tell the model to write unknown rather than guess")
	}
	if strings.HasSuffix(prompt, "\n") {
		t.Error("rendered prompt should not keep the template's trailing newline")
	}
}

func TestIssueDetectionPromptWithHostOS(t *testing.T) {
	prompt := issueDetectionPrompt(map[string]string{
		"web1": "Ubuntu 22.04.5",
		"DB2":  "CentOS Linux 7",
	})
	if !strings.Contains(prompt, "Known host operating systems") {
		t.Error("inventory heading missing")
	}
	db2 := strings.Index(prompt, "- DB2: CentOS Linux 7")
	web1 := strings.Index(prompt, "- web1: Ubuntu 22.04.5")
	if db2 == -1 || web1 == -1 || db2 > web1 {
		t.Errorf("inventory wrong or out of order (DB2 at %d, web1 at %d)", db2, web1)
	}
}

func TestResolutionPromptWithHostOS(t *testing.T) {
	prompt := resolutionPrompt(map[string]string{
		"web1": "Ubuntu 22.04.5",
		"DB2":  "CentOS Linux 7",
	}, false)
	if !strings.Contains(prompt, "Known host operating systems") {
		t.Error("inventory heading missing")
	}
	// The inventory sorts case-insensitively by host, so DB2 sorts before web1.
	db2 := strings.Index(prompt, "- DB2: CentOS Linux 7")
	web1 := strings.Index(prompt, "- web1: Ubuntu 22.04.5")
	if db2 == -1 || web1 == -1 || db2 > web1 {
		t.Errorf("inventory wrong or out of order (DB2 at %d, web1 at %d)", db2, web1)
	}
	if !strings.Contains(prompt, "For hosts not listed, assume CentOS / Rocky Linux") {
		t.Error("fallback line missing from inventory branch")
	}
	if strings.Contains(prompt, "The primary platform is CentOS / Rocky Linux") {
		t.Error("default branch should not render alongside the inventory")
	}
}

type stubAnomaly struct {
	host, program, kind, headline, summary, example, osFamily string
}

func (s *stubAnomaly) Host() string        { return s.host }
func (s *stubAnomaly) Program() string     { return s.program }
func (s *stubAnomaly) Kind() string        { return s.kind }
func (s *stubAnomaly) Score() float64      { return 0 }
func (s *stubAnomaly) Headline() string    { return s.headline }
func (s *stubAnomaly) Summary() string     { return s.summary }
func (s *stubAnomaly) ExampleLine() string { return s.example }
func (s *stubAnomaly) OSFamily() string    { return s.osFamily }
func (s *stubAnomaly) SetOSFamily(string)  {}

func TestMergeExplanations(t *testing.T) {
	anomalies := []Anomaly{
		&stubAnomaly{host: "app1", program: "systemd", kind: "peer",
			headline: "Unusually noisy", summary: "1000 vs 10", osFamily: "RHEL-family"},
		&stubAnomaly{host: "app2", program: "cron", kind: "baseline",
			headline: "Gone silent", summary: "0 vs 50", osFamily: "unknown"},
	}
	explanations := []*AnomalyExplanation{{
		Host: "app1", Program: "systemd",
		LikelyCauses:       "a stuck unit",
		InvestigationSteps: []string{"check journal"},
		SuggestedCommands:  []string{"# look\njournalctl -u foo"},
	}}
	got := mergeExplanations(anomalies, explanations)
	if len(got) != 2 {
		t.Fatalf("expected both anomalies back, got %d", len(got))
	}
	if got[0].LikelyCauses != "a stuck unit" || len(got[0].InvestigationSteps) != 1 {
		t.Errorf("explained anomaly lost its explanation: %+v", got[0])
	}
	if got[1].LikelyCauses != "(no explanation generated)" {
		t.Errorf("unexplained anomaly should keep facts only, got %q", got[1].LikelyCauses)
	}
	if got[1].Headline != "Gone silent" || got[1].Kind != "baseline" {
		t.Errorf("deterministic facts lost: %+v", got[1])
	}
}

// Models pad some list entries with leading whitespace (gpt-5.6-luna,
// 2026-08-29); mergeExplanations trims commands and steps at the parse
// boundary so the markdown files and the email agree.
func TestMergeExplanationsTrimsModelPadding(t *testing.T) {
	anomalies := []Anomaly{
		&stubAnomaly{host: "app1", program: "systemd", kind: "peer",
			headline: "Unusually noisy", summary: "1000 vs 10", osFamily: "unknown"},
	}
	explanations := []*AnomalyExplanation{{
		Host: "app1", Program: "systemd",
		LikelyCauses:       "a stuck unit",
		InvestigationSteps: []string{" check journal "},
		SuggestedCommands:  []string{" # padded comment", "journalctl -u foo "},
	}}
	got := mergeExplanations(anomalies, explanations)
	if got[0].InvestigationSteps[0] != "check journal" {
		t.Errorf("step not trimmed: %q", got[0].InvestigationSteps[0])
	}
	if got[0].SuggestedCommands[0] != "# padded comment" ||
		got[0].SuggestedCommands[1] != "journalctl -u foo" {
		t.Errorf("commands not trimmed: %q", got[0].SuggestedCommands)
	}
}

func TestExplainerPayload(t *testing.T) {
	anomalies := []Anomaly{&stubAnomaly{
		host: "app1", program: "systemd", kind: "peer",
		headline: "Unusually noisy", summary: "it's loud: 1000 vs 10",
		example: "Aug 27 03:14:15 app1 systemd[1]: restart", osFamily: "RHEL-family",
	}}
	got := explainerPayload(anomalies)
	want := `1. host=app1 program=systemd os_family=RHEL-family what='Unusually noisy' detail="it's loud: 1000 vs 10" example='Aug 27 03:14:15 app1 systemd[1]: restart'`
	if got != want {
		t.Errorf("payload mismatch:\ngot:  %s\nwant: %s", got, want)
	}
}

// go:embed silently embeds whatever is on disk; make sure the prompts are
// actually there and non-trivial.
func TestPromptsEmbedded(t *testing.T) {
	prompts := map[string]string{
		"issue_detection":     issueDetectionTemplateRaw,
		"issue_dedupe":        issueDedupePromptRaw,
		"anomaly_explanation": anomalyExplanationPromptRaw,
		"resolution":          resolutionTemplateRaw,
	}
	for name, p := range prompts {
		if len(p) < 200 {
			t.Errorf("%s prompt suspiciously short (%d bytes); go:embed broken?", name, len(p))
		}
	}
}

// A whole day's issues go to the resolution writer a dozen at a time, and
// each batch must keep the context windows that belong to its own issues
// (Contexts is index-aligned with Issues, or absent altogether).
func TestResolutionBatchesKeepContextsAligned(t *testing.T) {
	const n = 30
	issues := &IssueList{}
	var contexts []LogContext
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("issue-%02d", i)
		issues.Issues = append(issues.Issues, &Issue{Issue: name})
		contexts = append(contexts, LogContext{Host: name})
	}
	batches := NewResolutionAgent(issues, contexts, "test/model", nil).batches()
	if got := len(batches); got != 3 {
		t.Fatalf("got %d batches for %d issues, want 3", got, n)
	}
	var sizes []int
	for _, b := range batches {
		sizes = append(sizes, len(b.Issues.Issues))
		if len(b.Contexts) != len(b.Issues.Issues) {
			t.Fatalf("batch has %d contexts for %d issues", len(b.Contexts), len(b.Issues.Issues))
		}
		for j, issue := range b.Issues.Issues {
			if b.Contexts[j].Host != issue.Issue {
				t.Errorf("context %q sits beside issue %q", b.Contexts[j].Host, issue.Issue)
			}
		}
	}
	if want := []int{12, 12, 6}; !slices.Equal(sizes, want) {
		t.Errorf("batch sizes %v, want %v", sizes, want)
	}

	plain := NewResolutionAgent(issues, nil, "test/model", nil).batches()
	for _, b := range plain {
		if b.Contexts != nil {
			t.Errorf("batch without contexts got %d", len(b.Contexts))
		}
	}
}

// Run must make one request per batch and hand back every batch's
// resolutions in issue order, so downstream pairing by issue title still
// finds them all.
func TestResolutionRunConcatenatesBatches(t *testing.T) {
	var payloads []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		user := req.Messages[len(req.Messages)-1].Content
		payloads = append(payloads, user)
		var res []map[string]any
		for _, line := range strings.Split(user, "\n") {
			if title, ok := strings.CutPrefix(line, "## "); ok {
				res = append(res, map[string]any{"issue": title, "investigate": " ls "})
			}
		}
		content, _ := json.Marshal(map[string]any{"resolutions": res})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": string(content)}},
		}})
	}))
	defer server.Close()
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	issues := &IssueList{}
	for i := 0; i < 25; i++ {
		issues.Issues = append(issues.Issues, &Issue{Issue: fmt.Sprintf("issue-%02d", i)})
	}
	got, err := NewResolutionAgent(issues, nil, "openai/test-model", nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(payloads) != 3 {
		t.Fatalf("made %d requests for 25 issues, want 3", len(payloads))
	}
	if len(got.Resolutions) != 25 {
		t.Fatalf("got %d resolutions, want 25", len(got.Resolutions))
	}
	for i, r := range got.Resolutions {
		if want := fmt.Sprintf("issue-%02d", i); r.Issue != want {
			t.Errorf("resolution %d is for %q, want %q", i, r.Issue, want)
		}
		if r.Investigate != "ls" {
			t.Errorf("investigate not trimmed: %q", r.Investigate)
		}
	}
}

// The explainer batches like the resolution writer (srg-xiBoC.5): the
// MaxExplain cap applies first, then chunks of explainBatchSize in order.
func TestAnomalyExplainerBatches(t *testing.T) {
	mk := func(n int) []Anomaly {
		var out []Anomaly
		for i := 0; i < n; i++ {
			out = append(out, peerFixture(fmt.Sprintf("host%02d.example.test", i), "sshd", 5))
		}
		return out
	}
	cases := []struct {
		anomalies, max int
		want           []int
	}{
		{0, 15, nil},
		{15, 15, []int{15}},
		{40, 40, []int{15, 15, 10}},
		{20, 15, []int{15}},
	}
	for _, tc := range cases {
		agent := NewAnomalyExplainer(mk(tc.anomalies), "test/model")
		agent.MaxExplain = tc.max
		batches := agent.batches()
		var got []int
		for _, b := range batches {
			got = append(got, len(b))
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%d anomalies at cap %d: batch sizes %v, want %v", tc.anomalies, tc.max, got, tc.want)
		}
		if len(batches) > 1 && batches[1][0].Host() != "host15.example.test" {
			t.Errorf("second batch starts at %s, want host15 (order kept)", batches[1][0].Host())
		}
	}
}
