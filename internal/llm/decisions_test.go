package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decisionsServer fakes the Azure v1 decisions endpoint: it records the
// request and answers with reply.
func decisionsServer(t *testing.T, reply string) (*httptest.Server, *map[string]any, *string) {
	t.Helper()
	var body map[string]any
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(reply))
	}))
	t.Cleanup(server.Close)
	t.Setenv("AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	return server, &body, &path
}

func TestPredicateRoundTrip(t *testing.T) {
	_, body, path := decisionsServer(t, `{"model":"gpt-6-luna","answers":[{"type":"predicate","name":"q","probability":0.07}],`+
		`"usage":{"input_tokens":160,"input_tokens_details":{"cached_tokens":0},"output_tokens":0,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":160}}`)
	ResetUsage()
	t.Cleanup(ResetUsage)

	p, usage, err := Predicate(context.Background(), "azure/luna-deployment", `{"log":{"program":"fwupd"}}`, "Is this routine?")
	if err != nil {
		t.Fatalf("Predicate: %v", err)
	}
	if p != 0.07 || usage.PromptTokens != 160 {
		t.Errorf("got probability %v usage %+v, want 0.07 and 160 prompt tokens", p, usage)
	}
	if *path != "/openai/v1/decisions" {
		t.Errorf("request path = %q, want /openai/v1/decisions", *path)
	}
	if (*body)["model"] != "luna-deployment" || (*body)["input"] != `{"log":{"program":"fwupd"}}` {
		t.Errorf("model or input not passed through: %v", *body)
	}
	qs, _ := (*body)["questions"].([]any)
	if len(qs) != 1 {
		t.Fatalf("want one question, got %v", (*body)["questions"])
	}
	q := qs[0].(map[string]any)
	if q["type"] != "predicate" || q["instructions"] != "Is this routine?" {
		t.Errorf("question = %v", q)
	}
	if got := TotalUsage().PromptTokens; got != 160 {
		t.Errorf("usage totals carry %d prompt tokens, want 160", got)
	}
}

func TestPredicateRefusalIsErrRefused(t *testing.T) {
	decisionsServer(t, `{"model":"gpt-6-luna","answers":[{"type":"refusal","name":"q"}],"usage":{"input_tokens":10,"output_tokens":0,"total_tokens":10}}`)
	_, _, err := Predicate(context.Background(), "azure/luna-deployment", "x", "y")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("want ErrRefused, got %v", err)
	}
}

func TestPredicateScrubsWhatItSends(t *testing.T) {
	withScrub(t, "1", "gla.example=fake.example", "")
	_, body, _ := decisionsServer(t, `{"model":"m","answers":[{"type":"predicate","name":"q","probability":0.5}],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)
	if _, _, err := Predicate(context.Background(), "azure/d", "web1.gla.example to=<ops@gla.example>", "about gla.example"); err != nil {
		t.Fatal(err)
	}
	sent, _ := json.Marshal(*body)
	if strings.Contains(string(sent), "gla.example") || strings.Contains(string(sent), "ops@") {
		t.Errorf("real names left the box: %s", sent)
	}
}

func TestDecisionsModelMustBeAzure(t *testing.T) {
	t.Setenv("AZURE_OPENAI_ENDPOINT", "https://resource.example/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "k")
	for _, model := range []string{"openai/gpt-6-luna", "gpt-6-luna", "azure/"} {
		if err := CheckDecisionsModel(model); err == nil {
			t.Errorf("%q accepted, want refused", model)
		}
	}
	if err := CheckDecisionsModel("azure/luna-deployment"); err != nil {
		t.Errorf("azure/luna-deployment refused: %v", err)
	}
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	if err := CheckDecisionsModel("azure/luna-deployment"); err == nil {
		t.Error("missing key accepted")
	}
}
