package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestCheckCredentials(t *testing.T) {
	for _, key := range []string{
		"OPENAI_API_KEY", "OPENAI_BASE_URL",
		"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
		"AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY",
	} {
		t.Setenv(key, "")
	}
	// Missing keys fail fast and name the variable.
	for model, want := range map[string]string{
		"openai/gpt-4o-mini": "OPENAI_API_KEY",
		"anthropic/claude-x": "ANTHROPIC_API_KEY",
		"azure/gpt-4o":       "AZURE_OPENAI_ENDPOINT",
		"no-prefix":          "provider prefix",
		"mystery/model":      "unsupported provider",
	} {
		err := CheckCredentials(model)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected error mentioning %q, got %v", model, want, err)
		}
	}
	// A key satisfies its provider; a base URL waives the key for the
	// SDK-from-env providers.
	t.Setenv("OPENAI_API_KEY", "test-key")
	if err := CheckCredentials("openai/gpt-4o-mini"); err != nil {
		t.Errorf("key set: %v", err)
	}
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
	if err := CheckCredentials("openai/local-model"); err != nil {
		t.Errorf("base URL set: %v", err)
	}
}

// A rate-limited provider must be waited out, not died on: the client is
// configured to retry 429s well past the SDK's 2-retry default, honouring
// Retry-After. Two throttles then success must complete invisibly.
func TestCompleteRetriesThroughRateLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"message":"throttled","type":"too_many_requests"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"cmpl-1","object":"chat.completion","choices":[` +
			`{"index":0,"message":{"role":"assistant","content":"{\"answer\":42}"}}]}`))
	}))
	defer server.Close()

	t.Setenv("AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	var out struct {
		Answer int `json:"answer"`
	}
	schema := map[string]any{"type": "object"}
	if err := Complete(context.Background(), "azure/test-model", "sys", "usr", "answer", schema, &out); err != nil {
		t.Fatalf("Complete should have retried through the 429s: %v", err)
	}
	if requests != 3 {
		t.Errorf("saw %d requests, want 3 (two 429s then success)", requests)
	}
	if out.Answer != 42 {
		t.Errorf("decoded answer = %d, want 42", out.Answer)
	}
}

// Azure 429s carry BOTH "Retry-After: 30" and "Retry-After-Ms: 0"
// (observed live, 2026-09-01); the SDK prefers the -Ms header, so the
// zero makes every retry instant and the budget burns in a second. The
// azure client strips the lying header: with Retry-After: 1 the retry
// must actually wait about a second.
func TestAzureIgnoresZeroRetryAfterMs(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Retry-After-Ms", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"message":"throttled","type":"too_many_requests"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"cmpl-1","object":"chat.completion","choices":[` +
			`{"index":0,"message":{"role":"assistant","content":"{\"answer\":42}"}}]}`))
	}))
	defer server.Close()

	t.Setenv("AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	var out struct {
		Answer int `json:"answer"`
	}
	start := time.Now()
	if err := Complete(context.Background(), "azure/test-model", "sys", "usr", "answer",
		map[string]any{"type": "object"}, &out); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if requests != 2 {
		t.Errorf("saw %d requests, want 2", requests)
	}
	if elapsed := time.Since(start); elapsed < 700*time.Millisecond {
		t.Errorf("retried after only %v; the zero Retry-After-Ms should have been ignored in favour of Retry-After: 1", elapsed)
	}
}
