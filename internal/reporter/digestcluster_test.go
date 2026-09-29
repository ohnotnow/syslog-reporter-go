package reporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// With clusters, the same fault under drifting labels and host sets is one
// group: days and hosts are unions, the label is the latest day's.
func TestBuildDigestGroupsIssuesByCluster(t *testing.T) {
	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "certbot", "high", []string{"web01.example.test", "web02.example.test"}, "Renewals fail"),
		issueFinding(2, "2026-09-02", "certbot-renew.service", "medium", []string{"web02.example.test"}, "Renewal blocked"),
		issueFinding(3, "2026-09-03", "Certbot/Let's Encrypt", "medium", []string{"web03.example.test"}, "TLS renewal failed"),
		issueFinding(4, "2026-09-03", "certbot", "low", []string{"web01.example.test"}, "Other certbot problem"),
	}
	clusters := map[int64]int{1: 0, 2: 0, 3: 0, 4: 1}
	d := BuildDigest("2026-09-01", "2026-09-03", dailyRuns("2026-09-01", "2026-09-02", "2026-09-03"), findings, clusters)

	if len(d.Issues) != 2 {
		t.Fatalf("issue groups = %d, want 2", len(d.Issues))
	}
	top := d.Issues[0]
	if !reflect.DeepEqual(top.Days, []string{"2026-09-01", "2026-09-02", "2026-09-03"}) {
		t.Errorf("days = %v, want all three", top.Days)
	}
	wantHosts := []string{"web01.example.test", "web02.example.test", "web03.example.test"}
	if !reflect.DeepEqual(top.Hosts, wantHosts) {
		t.Errorf("hosts = %v, want the union %v", top.Hosts, wantHosts)
	}
	if top.Service != "Certbot/Let's Encrypt" || top.Severity != "high" || top.LatestID != 3 {
		t.Errorf("group = %q/%s latest #%d, want the latest label, the worst severity, #3", top.Service, top.Severity, top.LatestID)
	}
	if got := top.DigestIssue(3).AffectedHost; !reflect.DeepEqual(got, wantHosts) {
		t.Errorf("digest issue hosts = %v, want the union", got)
	}
	if d.Issues[1].LatestID != 4 {
		t.Errorf("second group = #%d, want the separate cluster #4", d.Issues[1].LatestID)
	}
}

// The model's answer is repaired, never trusted: an invented id is
// dropped, a repeated id stays in its first cluster, a missing id gets a
// cluster of its own. Anomalies are not sent.
func TestIssueClustererRepairsTheModelsAnswer(t *testing.T) {
	var payload string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		payload = req.Messages[len(req.Messages)-1].Content
		content := `{"clusters":[{"label":"a","ids":[1,2,99]},{"label":"b","ids":[2,3]}]}`
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": content}},
		}})
	}))
	defer server.Close()
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	findings := []*FindingDetail{
		issueFinding(1, "2026-09-01", "sshd", "high", []string{"web01.example.test"}, "One"),
		issueFinding(2, "2026-09-02", "sshd", "high", []string{"web01.example.test"}, "Two"),
		issueFinding(3, "2026-09-02", "cron", "low", []string{"db01.example.test"}, "Three"),
		issueFinding(4, "2026-09-03", "cron", "low", []string{"db01.example.test"}, "Four"),
		anomalyFinding(5, "2026-09-03", "db01.example.test", "postgres", "peer", "Chatty"),
	}
	got, err := NewIssueClusterer(findings, "openai/test-model").Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := map[int64]int{1: 0, 2: 0, 3: 1, 4: 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("clusters = %v, want %v", got, want)
	}
	if strings.Contains(payload, "postgres") || !strings.Contains(payload, `"title":"Four"`) {
		t.Errorf("payload should carry the four issues and no anomaly: %s", payload)
	}
}

// Nothing to group: no model call, each issue its own cluster.
func TestIssueClustererSkipsTheCallForOneIssue(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "http://127.0.0.1:1/v1") // any call would fail
	t.Setenv("OPENAI_API_KEY", "test-key")
	findings := []*FindingDetail{issueFinding(7, "2026-09-01", "sshd", "high", nil, "Only")}
	got, err := NewIssueClusterer(findings, "openai/test-model").Run(context.Background())
	if err != nil || !reflect.DeepEqual(got, map[int64]int{7: 0}) {
		t.Errorf("Run = %v, %v; want {7:0}, nil", got, err)
	}
}
