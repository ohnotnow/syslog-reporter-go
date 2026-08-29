package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCompleteRejectsUnknownProvider(t *testing.T) {
	err := Complete(context.Background(), "watson/holmes-1", "sys", "usr", "s", nil, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), `unsupported provider prefix "watson"`) {
		t.Fatalf("want unsupported-provider error, got %v", err)
	}
}

func TestCompleteRejectsMissingPrefix(t *testing.T) {
	err := Complete(context.Background(), "gpt-4o-mini", "sys", "usr", "s", nil, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "no provider prefix") {
		t.Fatalf("want missing-prefix error, got %v", err)
	}
}

func TestAzureNeedsBothEnvVars(t *testing.T) {
	t.Setenv("AZURE_OPENAI_ENDPOINT", "https://resource.example/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	err := Complete(context.Background(), "azure/test-model", "sys", "usr", "s", nil, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY") {
		t.Fatalf("want missing-env error, got %v", err)
	}
}

// TestAzureRoundTrip drives the azure/ path against a local fake and checks
// the wiring the live probe verified by hand: the request lands under the
// endpoint's full path (trailing-slash normalisation), carries bearer auth,
// and passes the model id through in the body.
func TestAzureRoundTrip(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		gotModel = body.Model
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"cmpl-1","object":"chat.completion","choices":[` +
			`{"index":0,"message":{"role":"assistant","content":"{\"answer\":42}"}}]}`))
	}))
	defer server.Close()

	// No trailing slash on purpose: completeAzure must add it, or the SDK's
	// relative-URL resolution would drop the /v1 segment.
	t.Setenv("AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	var out struct {
		Answer int `json:"answer"`
	}
	schema := map[string]any{"type": "object"}
	if err := Complete(context.Background(), "azure/test-model", "sys", "usr", "answer", schema, &out); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotPath != "/openai/v1/chat/completions" {
		t.Errorf("request path = %q, want /openai/v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("Authorization = %q, want Bearer test-key", gotAuth)
	}
	if gotModel != "test-model" {
		t.Errorf("model in body = %q, want test-model", gotModel)
	}
	if out.Answer != 42 {
		t.Errorf("decoded answer = %d, want 42", out.Answer)
	}
}
