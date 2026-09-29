package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// flood returns n lines of one crash loop: same host, program and message
// shape, a different pid and timestamp each time.
func flood(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("Sep 28 00:%02d:%02d web01 node_exporter[%d]: listen tcp :9100: bind: address already in use",
			(i/60)%60, i%60, 1000+i)
	}
	return lines
}

func TestCollapseRepeatsFoldsAFlood(t *testing.T) {
	quiet := "Sep 28 00:00:30 db01 sshd[42]: Accepted publickey for backup from 192.0.2.7 port 50122"
	lines := append([]string{quiet}, flood(500)...)

	got := CollapseRepeats(lines)

	want := []string{
		quiet,
		"[x500 00:00:00-00:08:19] Sep 28 00:00:00 web01 node_exporter[1000]: listen tcp :9100: bind: address already in use",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("CollapseRepeats:\n got %q\nwant %q", got, want)
	}
}

func TestCollapseRepeatsPayloadDoesNotGrowWithTheFlood(t *testing.T) {
	small := strings.Join(CollapseRepeats(flood(10)), "\n")
	big := strings.Join(CollapseRepeats(flood(3000)), "\n")
	// Only the count and the last timestamp differ.
	if len(big)-len(small) > 4 {
		t.Errorf("payload grew from %d to %d bytes going from 10 to 3000 repeats", len(small), len(big))
	}
}

func TestCollapseRepeatsKeepsDistinctShapesApart(t *testing.T) {
	lines := []string{
		"Sep 28 01:00:00 web01 certbot[1]: Failed to renew certificate www.example.test",
		"Sep 28 01:00:01 web02 certbot[2]: Failed to renew certificate www.example.test", // other host
		"Sep 28 01:00:02 web01 cron[3]: Failed to renew certificate www.example.test",    // other program
		"Sep 28 01:00:03 web01 certbot[4]: Renewal skipped",                              // other message
		"not a syslog line",
		"not a syslog line", // unparseable: never folded, never dropped
		"Sep 28 01:00:04 web01 certbot[5]: Failed to renew certificate mail.example.test", // same shape as the first
	}

	got := CollapseRepeats(lines)

	want := []string{
		"[x2 01:00:00-01:00:04] " + lines[0],
		lines[1], lines[2], lines[3], lines[4], lines[5],
	}
	if !slices.Equal(got, want) {
		t.Fatalf("CollapseRepeats:\n got %q\nwant %q", got, want)
	}
}

func TestStripRepeatTag(t *testing.T) {
	line := "Sep 28 00:00:00 web01 node_exporter[1000]: bind: address already in use"
	for _, in := range []string{line, "[x500 00:00:00-00:08:19] " + line, "  [x2 01:00:00-01:00:04] " + line + "\n"} {
		if got := stripRepeatTag(in); got != line {
			t.Errorf("stripRepeatTag(%q) = %q, want %q", in, got, line)
		}
	}
	// A log message that merely starts with a bracket is left alone.
	if got := stripRepeatTag("[warn] disk nearly full"); got != "[warn] disk nearly full" {
		t.Errorf("stripRepeatTag touched an untagged line: %q", got)
	}
}

// The detector sends the collapsed lines and hands back a real log line as
// the example even when the model copies the tag, so the context index
// (which matches examples exactly) still finds it.
func TestIssueDetectorSendsCollapsedLinesAndStripsTheTag(t *testing.T) {
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
		first, _, _ := strings.Cut(user, "\n")
		content, _ := json.Marshal(map[string]any{"issues": []map[string]any{
			{"issue": "node_exporter crash loop", "severity": "high", "example_log_entry": first},
		}})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": string(content)}},
		}})
	}))
	defer server.Close()
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	lines := flood(2500)
	detector := NewIssueDetector(lines, "openai/test-model", nil)
	got, err := detector.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("made %d requests for one repeated message, want 1", len(payloads))
	}
	if detector.SentLines != 1 {
		t.Errorf("SentLines = %d, want 1", detector.SentLines)
	}
	if !strings.HasPrefix(payloads[0], "[x2500 ") {
		t.Errorf("payload does not carry the repeat tag: %q", payloads[0])
	}
	if ex := got.Issues[0].ExampleLogEntry; ex != lines[0] {
		t.Errorf("example = %q, want the real first line %q", ex, lines[0])
	}
}
