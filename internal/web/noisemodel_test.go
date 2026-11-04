package web

// Tests for the noise review model view (ait srg-OymJL.4). Fake providers
// only; fictional hosts and programs.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/jev"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// fakeAzure answers /decisions with decisionsReply and chat completions
// with an explanation, counting each.
type fakeAzure struct {
	decisions, chats atomic.Int32
	decisionsReply   string
	decisionsStatus  int
}

func newFakeAzure(t *testing.T, decisionsReply string) *fakeAzure {
	t.Helper()
	f := &fakeAzure{decisionsReply: decisionsReply, decisionsStatus: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/decisions"):
			f.decisions.Add(1)
			w.WriteHeader(f.decisionsStatus)
			w.Write([]byte(f.decisionsReply))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			f.chats.Add(1)
			w.Write([]byte(`{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant",` +
				`"content":"{\"explanation\":\"Firmware daemon start-up; routine unless it repeats.\"}"}}],` +
				`"usage":{"prompt_tokens":50,"completion_tokens":10}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AZURE_OPENAI_ENDPOINT", srv.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	t.Setenv("TYPESAFE_API_KEY", "")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")
	return f
}

const decisionsOK = `{"model":"m","answers":[{"type":"predicate","name":"q","probability":0.03}],"usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}`

// modelViewServer is a local-auth server with cfg's model settings, a
// logged-in client and one shape in the pool; it returns that shape's id.
func modelViewServer(t *testing.T, cfg Config) (*httptest.Server, *http.Client, int64) {
	t.Helper()
	lib := newAuthTestStore(t)
	createTestUser(t, lib, "opsuser", "correct horse")
	if _, err := lib.ReplaceNoiseShapes(time.Now(), []reporter.NoiseShape{{Program: "fwupd",
		Template: "Daemon ready for requests", Example: "fwupd[9]: Daemon ready for requests",
		ExampleHost: "web1.example.test", Lines: 4, Hosts: 2}}); err != nil {
		t.Fatal(err)
	}
	pool, _ := lib.SampleNoiseShapes(1, time.Now(), nil)
	cfg.AuthMode, cfg.Version = "local", "test"
	auth, err := NewAuthenticator(cfg, lib)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, auth, lib)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	client := sessionClient(t)
	if _, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"opsuser"}, "password": {"correct horse"}, "next": {"/noise"}}); err != nil {
		t.Fatal(err)
	}
	return ts, client, pool[0].ID
}

func getBody(t *testing.T, client *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, bodyOf(t, resp)
}

func TestModelViewScoresExplainsAndCaches(t *testing.T) {
	f := newFakeAzure(t, decisionsOK)
	ts, client, id := modelViewServer(t, Config{DecisionsModel: "azure/dec", ExplainModel: "azure/chat"})
	if _, page := getBody(t, client, ts.URL+"/noise"); !strings.Contains(page, "Model's view") {
		t.Fatal("page lacks the reveal with both models configured")
	}
	for i := 0; i < 2; i++ {
		code, frag := getBody(t, client, fmt.Sprintf("%s/noise/%d/model-view", ts.URL, id))
		if code != http.StatusOK {
			t.Fatalf("model view = %d", code)
		}
		for _, want := range []string{"Rated 3% likely to need attention", "azure/dec",
			"Firmware daemon start-up; routine unless it repeats.", "Explanation by azure/chat",
			"The model's opinion, not a verdict"} {
			if !strings.Contains(frag, want) {
				t.Errorf("open %d: fragment lacks %q", i+1, want)
			}
		}
	}
	if f.decisions.Load() != 1 || f.chats.Load() != 1 {
		t.Errorf("calls: %d decisions, %d chats; want 1 each (second open from cache)", f.decisions.Load(), f.chats.Load())
	}
}

func TestModelViewFallsBackToJev(t *testing.T) {
	var jevCalls atomic.Int32
	jsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jevCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model":"jev-1","answers":{"attention":{"type":"noul","noul":0.42}},"usage":{"input_tokens":3,"output_tokens":0}}`))
	}))
	t.Cleanup(jsrv.Close)
	old := jev.BaseURL
	jev.BaseURL = jsrv.URL
	t.Cleanup(func() { jev.BaseURL = old })
	t.Setenv("TYPESAFE_API_KEY", "test-jev")
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	ts, client, id := modelViewServer(t, Config{ExplainModel: "azure/chat"}) // explain model has no credentials
	_, frag := getBody(t, client, fmt.Sprintf("%s/noise/%d/model-view", ts.URL, id))
	if !strings.Contains(frag, "Rated 42% likely") || !strings.Contains(frag, "jev/") || strings.Contains(frag, "Explanation by") {
		t.Errorf("Jev-only fragment = %s", frag)
	}
	if jevCalls.Load() != 1 {
		t.Errorf("%d Jev calls, want 1", jevCalls.Load())
	}
}

func TestModelViewAbsentWithNothingConfigured(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	ts, client, _ := modelViewServer(t, Config{ExplainModel: "azure/chat"})
	if _, page := getBody(t, client, ts.URL+"/noise"); strings.Contains(page, "Model's view") {
		t.Error("reveal shown with no usable model")
	}
}

func TestModelViewRefusalAndErrors(t *testing.T) {
	f := newFakeAzure(t, `{"model":"m","answers":[{"type":"refusal","name":"q"}],"usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}`)
	ts, client, id := modelViewServer(t, Config{DecisionsModel: "azure/dec", ExplainModel: "azure/chat"})
	if _, frag := getBody(t, client, fmt.Sprintf("%s/noise/%d/model-view", ts.URL, id)); !strings.Contains(frag, "The model declined to score this line.") {
		t.Errorf("refusal fragment = %s", frag)
	}

	// A failing provider: generic message, no upstream text, and nothing
	// cached, so the next open tries again.
	f2 := newFakeAzure(t, `{"error":{"message":"resource secret-resource-name is unhappy"}}`)
	f2.decisionsStatus = http.StatusBadRequest
	ts2, client2, id2 := modelViewServer(t, Config{DecisionsModel: "azure/dec", ExplainModel: "azure/chat"})
	for i := 0; i < 2; i++ {
		_, frag := getBody(t, client2, fmt.Sprintf("%s/noise/%d/model-view", ts2.URL, id2))
		if !strings.Contains(frag, "Could not fetch the model's score.") || strings.Contains(frag, "secret-resource-name") ||
			strings.Contains(frag, "127.0.0.1") {
			t.Errorf("error fragment = %s", frag)
		}
	}
	if f2.decisions.Load() != 2 {
		t.Errorf("%d decisions calls, want 2 (a failed view is not cached)", f2.decisions.Load())
	}
	_ = f
}

func TestModelViewNeedsALogin(t *testing.T) {
	f := newFakeAzure(t, decisionsOK)
	s := newTestServer(t, Config{Version: "test", DecisionsModel: "azure/dec", ExplainModel: "azure/chat"})
	seedNoisePool(t, s.lib, 1)
	pool, _ := s.lib.SampleNoiseShapes(1, time.Now(), nil)
	rec := get(t, s, fmt.Sprintf("/noise/%d/model-view", pool[0].ID))
	if rec.Code != http.StatusForbidden {
		t.Errorf("anonymous model view = %d, want 403", rec.Code)
	}
	if page := get(t, s, "/noise").Body.String(); strings.Contains(page, "Model's view") {
		t.Error("anonymous page shows the reveal")
	}
	if f.decisions.Load()+f.chats.Load() != 0 {
		t.Error("an anonymous request reached a provider")
	}
}
