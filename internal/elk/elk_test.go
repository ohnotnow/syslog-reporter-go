package elk

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// fakeES serves a PIT, pages docs by search_after (the sort value is the
// doc's index) and records what it was asked.
type fakeES struct {
	t          *testing.T
	docs       []map[string]any
	pageSize   int
	total      int // reported hits.total; -1 = len(docs)
	failAfter  int // fail the search after this many pages; 0 = never
	mu         sync.Mutex
	pages      int
	pitIDs     []string // pit id each search carried
	closed     string   // pit id DELETE /_pit closed
	lastQuery  map[string]any
	pitPath    string
	authHeader string
}

func (f *fakeES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authHeader = r.Header.Get("Authorization")
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_pit"):
		f.pitPath = r.URL.EscapedPath() + "?" + r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]any{"id": "pit-0"})
	case r.Method == http.MethodPost && r.URL.Path == "/_search":
		f.pages++
		if f.failAfter > 0 && f.pages > f.failAfter {
			http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
			return
		}
		pit := body["pit"].(map[string]any)
		f.pitIDs = append(f.pitIDs, pit["id"].(string))
		f.lastQuery = body["query"].(map[string]any)
		start := 0
		if sa, ok := body["search_after"].([]any); ok {
			start = int(sa[0].(float64)) + 1
		}
		end := min(start+f.pageSize, len(f.docs))
		var hits []map[string]any
		for i := start; i < end; i++ {
			hits = append(hits, map[string]any{"_source": f.docs[i], "sort": []any{i}})
		}
		total := f.total
		if total < 0 {
			total = len(f.docs)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"pit_id": fmt.Sprintf("pit-%d", f.pages), // ES may hand back a new id each page
			"hits":   map[string]any{"total": map[string]any{"value": total}, "hits": hits},
		})
	case r.Method == http.MethodDelete && r.URL.Path == "/_pit":
		f.closed, _ = body["id"].(string)
		w.Write([]byte(`{"succeeded":true}`))
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func doc(i int) map[string]any {
	return map[string]any{
		"@timestamp": fmt.Sprintf("2026-09-28T10:00:%02d.000Z", i),
		"host":       map[string]any{"name": "web01", "hostname": "web01.example.test", "os": map[string]any{"name": "Debian", "version": "12", "family": "debian"}, "ip": "192.0.2.1"},
		"process":    map[string]any{"name": "sshd", "pid": 1000 + i},
		"message":    fmt.Sprintf("message %d", i),
		"agent":      map[string]any{"name": "dropped"},
	}
}

func setup(t *testing.T, f *fakeES) (Config, string) {
	t.Helper()
	f.t = t
	if f.pageSize == 0 {
		f.pageSize = 2
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg := Config{URL: srv.URL + "/", Index: "logs-system.syslog-default", Auth: "ApiKey abc",
		Day: "2026-09-28", TZ: "Europe/London", BatchSize: 2, Timeout: 5 * time.Second}
	return cfg, filepath.Join(t.TempDir(), "syslog-2026-09-28.ndjson")
}

func TestDumpPagesThroughEveryDocumentOnce(t *testing.T) {
	f := &fakeES{total: -1}
	for i := 0; i < 5; i++ {
		f.docs = append(f.docs, doc(i))
	}
	cfg, out := setup(t, f)
	res, err := Dump(context.Background(), cfg, out, io.Discard)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if res.Written != 5 || res.Total != 5 || res.Searches != 4 {
		t.Errorf("result %+v, want 5 written of 5 in 4 searches (3 pages + the empty one)", res)
	}
	if res.First != "2026-09-28T10:00:00.000Z" || res.Last != "2026-09-28T10:00:04.000Z" {
		t.Errorf("timestamps %s .. %s", res.First, res.Last)
	}
	lines := readLines(t, out)
	if len(lines) != 5 {
		t.Fatalf("%d lines, want 5", len(lines))
	}
	for i, l := range lines {
		if !strings.Contains(l, fmt.Sprintf(`"message":"message %d"`, i)) {
			t.Errorf("line %d out of order: %s", i, l)
		}
	}
	// Each search carries the pit id the previous reply handed back.
	want := []string{"pit-0", "pit-1", "pit-2", "pit-3"}
	if strings.Join(f.pitIDs, ",") != strings.Join(want, ",") {
		t.Errorf("pit ids carried %v, want %v", f.pitIDs, want)
	}
	if f.closed != "pit-4" {
		t.Errorf("closed pit %q, want the latest id pit-4", f.closed)
	}
}

func TestDumpTrimsToFlatDottedKeysInOrder(t *testing.T) {
	d := doc(0)
	delete(d["host"].(map[string]any), "hostname")
	d["message"] = "a <b> & c"
	f := &fakeES{total: -1, docs: []map[string]any{d}}
	cfg, out := setup(t, f)
	if _, err := Dump(context.Background(), cfg, out, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := `{"@timestamp":"2026-09-28T10:00:00.000Z","host.name":"web01","host.os.name":"Debian",` +
		`"host.os.version":"12","host.os.family":"debian","process.name":"sshd","process.pid":1000,` +
		`"message":"a <b> & c"}`
	if got := readLines(t, out)[0]; got != want {
		t.Errorf("line\n got %s\nwant %s", got, want)
	}
}

func TestDumpSendsTheDayWindowAndEscapedIndex(t *testing.T) {
	f := &fakeES{total: -1}
	cfg, out := setup(t, f)
	cfg.Index = "logs-system.syslog-*,other"
	cfg.TZ = "+01:00"
	if _, err := Dump(context.Background(), cfg, out, io.Discard); err != nil {
		t.Fatal(err)
	}
	r := f.lastQuery["range"].(map[string]any)["@timestamp"].(map[string]any)
	if r["gte"] != "2026-09-28" || r["lt"] != "2026-09-29" || r["time_zone"] != "+01:00" || r["format"] != "yyyy-MM-dd" {
		t.Errorf("range %v", r)
	}
	if f.pitPath != "/logs-system.syslog-*,other/_pit?keep_alive=5m" {
		t.Errorf("pit path %q", f.pitPath)
	}
	if f.authHeader != "ApiKey abc" {
		t.Errorf("auth %q", f.authHeader)
	}
}

func TestDumpFailureLeavesNoFile(t *testing.T) {
	f := &fakeES{total: -1, failAfter: 1}
	for i := 0; i < 5; i++ {
		f.docs = append(f.docs, doc(i))
	}
	cfg, out := setup(t, f)
	if _, err := Dump(context.Background(), cfg, out, io.Discard); err == nil {
		t.Fatal("Dump succeeded with a failing second page")
	}
	assertNoFiles(t, filepath.Dir(out))
	if f.closed == "" {
		t.Error("PIT not closed after a failure")
	}
}

func TestDumpCountMismatchIsIncomplete(t *testing.T) {
	f := &fakeES{total: 7, docs: []map[string]any{doc(0)}}
	cfg, out := setup(t, f)
	_, err := Dump(context.Background(), cfg, out, io.Discard)
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err %v, want ErrIncomplete", err)
	}
	assertNoFiles(t, filepath.Dir(out))
}

// The .gz output must be what the pipeline's own reader accepts.
func TestDumpGzipIsReadByElkSource(t *testing.T) {
	f := &fakeES{total: -1, docs: []map[string]any{doc(0), doc(1), doc(2)}}
	cfg, out := setup(t, f)
	out += ".gz"
	if _, err := Dump(context.Background(), cfg, out, io.Discard); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if _, err := gzip.NewReader(fh); err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	src, err := reporter.NewElkSource(out)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := src.Run()
	if err != nil {
		t.Fatalf("ElkSource: %v", err)
	}
	if len(lines) != 3 || !strings.Contains(lines[0], "web01.example.test sshd[1000]: message 0") {
		t.Errorf("ElkSource read %d lines: %q", len(lines), lines)
	}
}

func TestAuthHeader(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		key, user, pass, want string
		wantErr               bool
	}{
		{key: "id:secret", want: "ApiKey " + enc("id:secret")},
		{key: "QUJD", want: "ApiKey QUJD"},
		{key: "id:secret", user: "u", pass: "p", want: "ApiKey " + enc("id:secret")},
		{user: "u", pass: "p", want: "Basic " + enc("u:p")},
		{user: "u", wantErr: true},
		{wantErr: true},
	}
	for _, c := range cases {
		got, err := AuthHeader(c.key, c.user, c.pass)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("AuthHeader(%q, %q, %q) = %q, %v", c.key, c.user, c.pass, got, err)
		}
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func assertNoFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("left behind: %s", e.Name())
	}
}
