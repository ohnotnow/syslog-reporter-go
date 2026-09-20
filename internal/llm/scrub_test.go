package llm

// Scrubbing tests (ait srg-5sSQZ, ant ADR srg-Sgdkm). Fictional estate
// strings only.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withScrub configures the package for one test and restores the off
// state afterwards.
func withScrub(t *testing.T, toggle, domains, prefixes string) {
	t.Helper()
	if err := setScrub(toggle, domains, prefixes); err != nil {
		t.Fatalf("setScrub: %v", err)
	}
	t.Cleanup(func() { setScrub("", "", "") })
}

func TestScrubRoundTrip(t *testing.T) {
	withScrub(t, "1", "gla.example=fake.example,student.gla.example=pupil.example", "130.209=192.168")
	line := "Jun 1 web1.gla.example postfix[9]: to=<alice@student.gla.example> from=<bob@other.example>, " +
		"relay=mx.GLA.example[130.209.55.103] retry bob@other.example via 130.2091.1.1"
	out, sess := scrubOut(line)
	for _, real := range []string{"gla.example", "alice", "bob", "other.example", "130.209.55"} {
		if strings.Contains(strings.ToLower(out), real) {
			t.Errorf("outbound still carries %q: %s", real, out)
		}
	}
	for _, want := range []string{"<email-1>", "<email-2>", "web1.fake.example", "mx.fake.example[192.168.55.103]", "130.2091.1.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("outbound lacks %q: %s", want, out)
		}
	}
	if strings.Count(out, "<email-2>") != 2 {
		t.Errorf("repeated address should reuse its token: %s", out)
	}
	back := sess.in(out)
	// The domain swap is case-folded, so the one upper-case mention comes
	// back in the configured case; everything else is byte-identical.
	if want := strings.Replace(line, "GLA.example", "gla.example", 1); back != want {
		t.Errorf("reversal:\n got %s\nwant %s", back, want)
	}
}

func TestScrubSubdomainFallsOutOfParent(t *testing.T) {
	withScrub(t, "1", "gla.example=fake.example", "")
	out, sess := scrubOut(`host.research.gla.example said "ops@gla.example",`)
	if out != `host.research.fake.example said "<email-1>",` {
		t.Errorf("out = %q", out)
	}
	if back := sess.in(out); back != `host.research.gla.example said "ops@gla.example",` {
		t.Errorf("back = %q", back)
	}
}

func TestScrubOffIsIdentity(t *testing.T) {
	withScrub(t, "", "gla.example=fake.example", "")
	line := "ops@gla.example at 130.209.1.1"
	if out, sess := scrubOut(line); out != line || sess.in(line) != line {
		t.Errorf("off should not touch the text, got %q", out)
	}
}

func TestScrubReversesModelProse(t *testing.T) {
	withScrub(t, "1", "gla.example=fake.example", "130.209=192.168")
	_, sess := scrubOut("mail from ops@gla.example")
	got := sess.in(`{"fix":"ssh <email-1> then ping 192.168.9.9 on fake.example; <email-7> is unknown"}`)
	want := `{"fix":"ssh ops@gla.example then ping 130.209.9.9 on gla.example; <email-7> is unknown"}`
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestSetScrubRefusesBadConfig(t *testing.T) {
	cases := []struct{ name, toggle, domains, prefixes, want string }{
		{"empty maps", "1", "", "", "both empty"},
		{"bad toggle", "maybe", "a.example=b.example", "", "SYSLOG_SCRUB="},
		{"not a pair", "1", "gla.example", "", "not real=fake"},
		{"duplicate fake", "1", "a.example=x.example,b.example=x.example", "", "more than once"},
		{"fake is a real", "1", "a.example=b.example,b.example=c.example", "", "both a real and a fake"},
		{"prefix not octets", "1", "", "130.209=example", "dotted octets"},
		{"prefix too long", "1", "", "130.209.1.1=192.168", "dotted octets"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := setScrub(c.toggle, c.domains, c.prefixes)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestLoadScrubRefusesStaleRedact(t *testing.T) {
	t.Setenv("SYSLOG_REDACT", "example.ac.uk")
	if err := LoadScrub(); err == nil || !strings.Contains(err.Error(), "SYSLOG_SCRUB_DOMAINS") {
		t.Errorf("err = %v", err)
	}
}

func TestScrubWarningOnlyOffAndOutsideAzure(t *testing.T) {
	withScrub(t, "", "", "")
	if w := ScrubWarning("azure/gpt", "azure/gpt-mini"); w != "" {
		t.Errorf("azure alone should not warn: %q", w)
	}
	w := ScrubWarning("azure/gpt", "openai/gpt-5.6-luna", "anthropic/claude-sonnet-5")
	if !strings.Contains(w, "openai/gpt-5.6-luna") || !strings.Contains(w, "anthropic/claude-sonnet-5") || strings.Contains(w, "azure/") {
		t.Errorf("warning = %q", w)
	}
	withScrub(t, "1", "gla.example=fake.example", "")
	if w := ScrubWarning("openai/gpt-5.6-luna"); w != "" {
		t.Errorf("on should not warn: %q", w)
	}
}

// What actually leaves the estate: the provider-bound request carries the
// scrubbed user message while the system prompt travels untouched, and the
// decoded reply carries the real names again. Asserted at the wire via the
// same httptest seam TestAzureRoundTrip uses.
func TestCompleteScrubsOutAndReversesIn(t *testing.T) {
	withScrub(t, "1", "gla.example=fake.example", "130.209=192.168")

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
			`{"index":0,"message":{"role":"assistant","content":` +
			`"{\"fix\":\"mail <email-1> about web1.fake.example (192.168.55.103)\"}"}}]}`))
	}))
	defer server.Close()

	t.Setenv("AZURE_OPENAI_ENDPOINT", server.URL+"/openai/v1")
	t.Setenv("AZURE_OPENAI_API_KEY", "test-key")
	t.Setenv("SYSLOG_REASONING_EFFORT", "")

	var out struct {
		Fix string `json:"fix"`
	}
	err := Complete(context.Background(), "azure/test-model",
		"host table: web1.gla.example is Ubuntu",
		"Jun 1 web1.gla.example sshd[9]: Failed password for ops@gla.example from 130.209.55.103",
		"answer", map[string]any{"type": "object"}, &out)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if strings.Contains(gotUser, "gla.example") || strings.Contains(gotUser, "ops@") || strings.Contains(gotUser, "130.209") {
		t.Errorf("user message still carries real values: %q", gotUser)
	}
	if !strings.Contains(gotSystem, "web1.gla.example") {
		t.Errorf("system prompt must not be scrubbed, got %q", gotSystem)
	}
	if want := "mail ops@gla.example about web1.gla.example (130.209.55.103)"; out.Fix != want {
		t.Errorf("decoded reply = %q, want %q", out.Fix, want)
	}
}
