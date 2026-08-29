package llm

// Redaction tests (srg-so8ja.6, ant ADR srg-Mzvjf). Fictional estate
// strings only.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReplaceFoldCaseInsensitiveAndCounted(t *testing.T) {
	got, n := replaceFold(
		"host1.example.ac.uk said EXAMPLE.AC.UK twice; example.AC.uk thrice",
		"example.ac.uk", redactedMark)
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	want := "host1.[redacted] said [redacted] twice; [redacted] thrice"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSetRedactionsTrimsAndDropsEmpties(t *testing.T) {
	SetRedactions([]string{" example.ac.uk ", "", "  ", "10.20."})
	t.Cleanup(func() { SetRedactions(nil) })
	if got := redactUser("ping 10.20.1.9 at example.ac.uk and Example.AC.UK"); strings.Contains(got, "example.ac.uk") ||
		strings.Contains(got, "Example.AC.UK") || strings.Contains(got, "10.20.1") {
		t.Errorf("values survived redaction: %q", got)
	}
}

// The provider-bound request must carry the redacted user message while the
// system prompt travels untouched - asserted at the wire via the same
// httptest seam TestAzureRoundTrip uses, because that is what actually
// leaves the estate.
func TestCompleteRedactsUserMessageOnly(t *testing.T) {
	SetRedactions([]string{"example.ac.uk"})
	t.Cleanup(func() { SetRedactions(nil) })

	var gotSystem, gotUser string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		for _, m := range body.Messages {
			switch m.Role {
			case "system":
				gotSystem = m.Content
			case "user":
				gotUser = m.Content
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"cmpl-1","object":"chat.completion","choices":[` +
			`{"index":0,"message":{"role":"assistant","content":"{\"answer\":1}"}}]}`))
	}))
	defer server.Close()

	t.Setenv("AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	var out struct {
		Answer int `json:"answer"`
	}
	err := Complete(context.Background(), "azure/test-model",
		"host table: web1.example.ac.uk is Ubuntu",
		"Jun 1 web1.example.ac.uk sshd[9]: Failed password from EXAMPLE.AC.UK",
		"answer", map[string]any{"type": "object"}, &out)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if strings.Contains(strings.ToLower(gotUser), "example.ac.uk") {
		t.Errorf("user message still carries the redacted value: %q", gotUser)
	}
	if got := strings.Count(gotUser, redactedMark); got != 2 {
		t.Errorf("user message has %d redaction marks, want 2: %q", got, gotUser)
	}
	if !strings.Contains(gotSystem, "web1.example.ac.uk") {
		t.Errorf("system prompt must not be redacted, got %q", gotSystem)
	}
}
