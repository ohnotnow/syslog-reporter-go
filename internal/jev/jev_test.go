package jev

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

const reply = `{"model":"jev-1.13.0","answers":{"attention":{"type":"noul","noul":0.88}},"usage":{"input_tokens":764,"output_tokens":33}}`

// serve points the client at a test server for the test's lifetime and
// returns the requests it received.
func serve(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body []byte)) *[][]byte {
	t.Helper()
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		handler(w, r, body)
	}))
	t.Cleanup(srv.Close)
	oldURL, oldBase := BaseURL, retryBase
	BaseURL, retryBase = srv.URL, time.Millisecond
	t.Cleanup(func() { BaseURL, retryBase = oldURL, oldBase })
	t.Setenv("TYPESAFE_API_KEY", "test-key")
	return &bodies
}

func question() map[string]Question {
	return map[string]Question{"attention": {
		Type:         "noul",
		Instructions: map[string]any{"question": "Should an admin see this?", "inspect": "`log.message`"},
		Criteria:     map[string]any{"true": map[string]any{"what": "a fault"}, "false": map[string]any{"what": "chatter"}},
	}}
}

func TestAskSendsTheDocumentedShapeAndDecodesNoul(t *testing.T) {
	var gotAuth string
	bodies := serve(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, reply)
	})
	state := map[string]any{"log": map[string]any{"program": "sshd", "message": "Failed password", "lines_today": 412}}
	resp, err := Ask(context.Background(), state, question())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	var sent struct {
		Model     string                     `json:"model"`
		State     map[string]map[string]any  `json:"state"`
		Questions map[string]json.RawMessage `json:"questions"`
	}
	if err := json.Unmarshal((*bodies)[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Model != DefaultModel || sent.State["log"]["program"] != "sshd" || sent.State["log"]["lines_today"] != float64(412) {
		t.Errorf("request body: %s", (*bodies)[0])
	}
	q := string(sent.Questions["attention"])
	if !strings.Contains(q, `"type":"noul"`) || !strings.Contains(q, `"inspect":"`+"`log.message`"+`"`) ||
		!strings.Contains(q, `"false":{"what":"chatter"}`) {
		t.Errorf("question not sent verbatim: %s", q)
	}
	if resp.Model != "jev-1.13.0" || resp.Usage.InputTokens != 764 {
		t.Errorf("decoded reply: %+v", resp)
	}
	p, err := Noul(resp, "attention")
	if err != nil || p != 0.88 {
		t.Errorf("Noul = %v, %v", p, err)
	}
	if _, err := Noul(resp, "missing"); err == nil {
		t.Error("Noul of an absent answer should error")
	}
}

func TestAskHonoursSYSLOGJEVMODEL(t *testing.T) {
	bodies := serve(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { io.WriteString(w, reply) })
	t.Setenv("SYSLOG_JEV_MODEL", "jev-1.13.0")
	if _, err := Ask(context.Background(), map[string]any{}, question()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string((*bodies)[0]), `"model":"jev-1.13.0"`) {
		t.Errorf("pinned model not sent: %s", (*bodies)[0])
	}
}

func TestAskRetriesRateLimitsThenSucceeds(t *testing.T) {
	calls := 0
	serve(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0.001")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, reply)
	})
	if _, err := Ask(context.Background(), map[string]any{}, question()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestAskGivesUpAfterFiveServerErrors(t *testing.T) {
	calls := 0
	serve(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		calls++
		http.Error(w, "upstream sad", http.StatusServiceUnavailable)
	})
	_, err := Ask(context.Background(), map[string]any{}, question())
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") || !strings.Contains(err.Error(), "upstream sad") {
		t.Errorf("err = %v", err)
	}
	if calls != maxAttempts {
		t.Errorf("calls = %d, want %d", calls, maxAttempts)
	}
}

func TestAskFailsAtOnceOnClientErrors(t *testing.T) {
	calls := 0
	serve(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		calls++
		http.Error(w, `{"error":"bad question"}`, http.StatusBadRequest)
	})
	_, err := Ask(context.Background(), map[string]any{}, question())
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || calls != 1 {
		t.Errorf("err = %v, calls = %d", err, calls)
	}
}

func TestAskScrubsOutboundState(t *testing.T) {
	bodies := serve(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { io.WriteString(w, reply) })
	t.Setenv("SYSLOG_SCRUB", "1")
	t.Setenv("SYSLOG_SCRUB_DOMAINS", "secret-estate.example=fake.example")
	t.Setenv("SYSLOG_SCRUB_IP_PREFIXES", "")
	t.Setenv("SYSLOG_REDACT", "")
	if err := llm.LoadScrub(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		t.Setenv("SYSLOG_SCRUB", "")
		t.Setenv("SYSLOG_SCRUB_DOMAINS", "")
		llm.LoadScrub()
	})
	state := map[string]any{"log": map[string]any{"message": "connect to db.SECRET-estate.example failed for ops@secret-estate.example"}}
	if _, err := Ask(context.Background(), state, question()); err != nil {
		t.Fatal(err)
	}
	sent := string((*bodies)[0])
	if strings.Contains(strings.ToLower(sent), "secret-estate") || !strings.Contains(sent, "db.fake.example") || !strings.Contains(sent, `\u003cemail-1\u003e`) {
		t.Errorf("state left the box unscrubbed: %s", sent)
	}
}

func TestCheckCredentialsNamesTheVariable(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	if err := CheckCredentials(); err == nil || !strings.Contains(err.Error(), "TYPESAFE_API_KEY") {
		t.Errorf("err = %v", err)
	}
	if _, err := Ask(context.Background(), nil, nil); err == nil {
		t.Error("Ask without a key should fail before any request")
	}
}
