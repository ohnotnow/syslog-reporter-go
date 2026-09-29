package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A one-document cluster; total is what the first search reports.
func fakeCluster(t *testing.T, total int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/_pit") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{"id": "p"})
		case r.URL.Path == "/_search":
			var hits []any
			if _, more := body["search_after"]; !more {
				hits = []any{map[string]any{"sort": []any{1}, "_source": map[string]any{
					"@timestamp": "2026-09-28T10:00:00Z", "host": map[string]any{"name": "web01"},
					"process": map[string]any{"name": "cron"}, "message": "tick"}}}
			}
			json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"total": map[string]any{"value": total}, "hits": hits}})
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFetchWritesTheDay(t *testing.T) {
	t.Setenv("ELK_API_KEY", "id:key")
	out := filepath.Join(t.TempDir(), "syslog-2026-09-28.ndjson")
	var log bytes.Buffer
	code := runFetch([]string{"--url", fakeCluster(t, 1), "--index", "logs", "--day", "2026-09-28", "--out", out}, &log)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, log.String())
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), `"message":"tick"`) {
		t.Errorf("dump: %s", b)
	}
	if !strings.Contains(log.String(), "wrote 1 documents") || strings.Contains(log.String(), "id:key") {
		t.Errorf("log should summarise and never print credentials:\n%s", log.String())
	}
}

func TestFetchExitCodes(t *testing.T) {
	t.Setenv("ELK_API_KEY", "abc")
	t.Setenv("ELK_URL", "")
	t.Setenv("ELK_INDEX", "")
	dir := t.TempDir()
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want int
	}{
		{"no url", []string{"--index", "logs"}, nil, 2},
		{"bad day", []string{"--url", "http://x", "--index", "logs", "--day", "28/09/2026"}, nil, 2},
		{"bad ELK_INSECURE", []string{"--url", "http://x", "--index", "logs"}, map[string]string{"ELK_INSECURE": "maybe"}, 2},
		{"count mismatch", []string{"--url", fakeCluster(t, 5), "--index", "logs", "--out", filepath.Join(dir, "x.ndjson")}, nil, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := runFetch(c.args, io.Discard); got != c.want {
				t.Errorf("exit %d, want %d", got, c.want)
			}
		})
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("count mismatch left %d file(s) behind", len(entries))
	}
}
