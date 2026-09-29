package reporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

// The digest names the daily runs that hit the budget, and both layouts
// put the notice straight under the title (owner 2026-09-29).
func TestDigestBudgetNoticeUnderTheTitle(t *testing.T) {
	runs := dailyRuns("2026-09-01", "2026-09-02", "2026-09-03")
	runs[1].BudgetReached = true
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "sshd", "high", []string{"web01.example.test"}, "SSH brute force"),
	}
	d := BuildDigest("2026-09-01", "2026-09-03", runs, findings, nil)
	if !reflect.DeepEqual(d.BudgetDays, []string{"2026-09-02"}) {
		t.Fatalf("BudgetDays = %v, want [2026-09-02]", d.BudgetDays)
	}
	r := &DigestReport{Digest: d, Issues: &IssueList{}, OneOffs: &IssueList{}, Resolutions: &ResolutionList{}, BudgetReached: true}
	for name, out := range map[string]string{"body": r.EmailBody(), "attachment": r.FullReport()} {
		title, rest, _ := strings.Cut(out, "\n\n")
		if !strings.HasPrefix(title, "# Syslog weekly digest") {
			t.Fatalf("%s: no title first: %q", name, title)
		}
		if !strings.HasPrefix(rest, "**LLM budget reached on Wed 2 Sep.**") {
			t.Errorf("%s: budget notice not straight under the title:\n%s", name, rest)
		}
		if !strings.Contains(out, "**LLM budget reached while writing this digest.**") {
			t.Errorf("%s: no notice for the digest's own budget", name)
		}
	}
	quiet := &DigestReport{Digest: BuildDigest("2026-09-01", "2026-09-03", dailyRuns("2026-09-01"), nil, nil),
		Issues: &IssueList{}, OneOffs: &IssueList{}, Resolutions: &ResolutionList{}}
	if strings.Contains(quiet.EmailBody(), "budget") {
		t.Error("a digest with no budget hits mentions the budget")
	}
}

func TestDailyReportBudgetNotice(t *testing.T) {
	rep := &ReportAgent{Issues: &IssueList{}, Resolutions: &ResolutionList{}, BudgetReached: true}
	for name, out := range map[string]string{"body": rep.EmailBody(), "attachment": rep.Run()} {
		_, rest, _ := strings.Cut(out, "\n\n")
		if !strings.HasPrefix(rest, "**LLM budget reached.**") {
			t.Errorf("%s: budget notice not straight under the title:\n%s", name, rest)
		}
	}
	rep.BudgetReached = false
	if strings.Contains(rep.EmailBody(), "budget") {
		t.Error("a run within budget mentions the budget")
	}
}

// Once the budget is spent the agents return what they already have
// alongside llm.ErrBudget, so the run can finish degraded. The stub
// reports 10 prompt tokens per request against a budget of 5, so the
// first request succeeds and every later one is refused.
func TestAgentsReturnPartialResultsOnBudget(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		content := `{"issues":[{"issue":"first chunk","severity":"high","example_log_entry":"x"}],` +
			`"resolutions":[{"issue":"i00","investigate":"ls"}],"explanations":[]}`
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": content}}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 1},
		})
	}))
	defer server.Close()
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")
	llm.SetBudget(5)
	t.Cleanup(func() { llm.SetBudget(0) })

	// Two chunks of distinct lines: the second is refused.
	var lines []string
	for i := 0; i < DetectorChunkSize+1; i++ {
		lines = append(lines, fmt.Sprintf("Sep 28 00:00:00 web01 app%d[1]: message", i))
	}
	issues, err := NewIssueDetector(lines, "openai/test-model", nil).Run(context.Background())
	if !errors.Is(err, llm.ErrBudget) || len(issues.Issues) != 1 {
		t.Fatalf("detector: %d issues, %v; want the first chunk's one issue and ErrBudget", len(issues.Issues), err)
	}
	if !llm.BudgetReached() {
		t.Error("BudgetReached is false after a refusal")
	}
	res, err := NewResolutionAgent(&IssueList{Issues: []*Issue{{Issue: "i00"}}}, nil, "openai/test-model", nil).Run(context.Background())
	if !errors.Is(err, llm.ErrBudget) || res == nil || len(res.Resolutions) != 0 {
		t.Errorf("resolutions: %v, %v; want an empty list and ErrBudget", res, err)
	}
	anomalies := []Anomaly{&stubAnomaly{host: "db01.example.test", program: "postgres", kind: "peer"}}
	explained, err := NewAnomalyExplainer(anomalies, "openai/test-model").Run(context.Background())
	if !errors.Is(err, llm.ErrBudget) || len(explained) != 1 || explained[0].LikelyCauses != "(no explanation generated)" {
		t.Errorf("explainer: %v, %v; want the anomaly facts-only and ErrBudget", explained, err)
	}
	if requests != 1 {
		t.Errorf("%d requests reached the provider, want 1", requests)
	}
}
