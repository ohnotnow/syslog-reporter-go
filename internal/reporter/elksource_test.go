package reporter

// Port of tests/test_elk_source.py from the Python original.

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func makeDoc(overrides map[string]any) map[string]any {
	doc := map[string]any{
		"@timestamp":    "2026-08-26T13:00:05.000Z",
		"host.name":     "dnsbox.example.ac.uk",
		"host.hostname": "dnsbox",
		"process.name":  "dhcpd",
		"process.pid":   61685,
		"message":       "DHCPDISCOVER from aa:bb:cc:dd:ee:ff via eth0",
	}
	for k, v := range overrides {
		if v == nil {
			delete(doc, k)
		} else {
			doc[k] = v
		}
	}
	return doc
}

func writeNDJSON(t *testing.T, docs []map[string]any, suffix string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dump"+suffix)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var enc *json.Encoder
	if strings.HasSuffix(suffix, ".gz") {
		gz := gzip.NewWriter(f)
		defer gz.Close()
		enc = json.NewEncoder(gz)
	} else {
		enc = json.NewEncoder(f)
	}
	for _, doc := range docs {
		if err := enc.Encode(doc); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func runElk(t *testing.T, path string) (*ElkSource, []string) {
	t.Helper()
	src, err := NewElkSource(path)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := src.Run()
	if err != nil {
		t.Fatal(err)
	}
	return src, lines
}

func TestElkRendersClassicSyslogLine(t *testing.T) {
	path := writeNDJSON(t, []map[string]any{makeDoc(nil)}, ".ndjson")
	_, lines := runElk(t, path)
	// 13:00 UTC on Aug 26 is 14:00 in Europe/London (BST)
	want := []string{"Aug 26 14:00:05 dnsbox dhcpd[61685]: " +
		"DHCPDISCOVER from aa:bb:cc:dd:ee:ff via eth0"}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("got %#v, want %#v", lines, want)
	}
}

func TestElkRenderedLineSatisfiesPipelineParser(t *testing.T) {
	path := writeNDJSON(t, []map[string]any{makeDoc(nil)}, ".ndjson")
	_, lines := runElk(t, path)
	rec := ParseLine(lines[0])
	if rec == nil {
		t.Fatal("expected a parse")
	}
	if rec.Host != "dnsbox" || rec.Program != "dhcpd" || rec.Window != "14:00" {
		t.Errorf("got %+v", rec)
	}
}

func TestElkOffsetTimestampsAndSingleDigitDayPadding(t *testing.T) {
	doc := makeDoc(map[string]any{"@timestamp": "2026-08-06T09:15:00.000+01:00"})
	path := writeNDJSON(t, []map[string]any{doc}, ".ndjson")
	_, lines := runElk(t, path)
	if !strings.HasPrefix(lines[0], "Aug  6 09:15:00 dnsbox") {
		t.Errorf("got %q", lines[0])
	}
}

func TestElkNoPidRendersBareProgramTag(t *testing.T) {
	doc := makeDoc(map[string]any{"process.pid": nil})
	path := writeNDJSON(t, []map[string]any{doc}, ".ndjson")
	_, lines := runElk(t, path)
	if !strings.Contains(lines[0], " dhcpd: DHCPDISCOVER") {
		t.Errorf("got %q", lines[0])
	}
}

func TestElkEmptyProcessNameKeepsEmptyTag(t *testing.T) {
	// Seen in a real dump: process.name present but empty, pid still set.
	// Python's doc.get(key, default) keeps the empty string, so the line
	// renders as 'host [pid]: message' and ParseLine later rejects it; the
	// "unknown" default applies only when the key is absent entirely.
	doc := makeDoc(map[string]any{"process.name": ""})
	path := writeNDJSON(t, []map[string]any{doc}, ".ndjson")
	_, lines := runElk(t, path)
	if !strings.Contains(lines[0], " dnsbox [61685]: DHCPDISCOVER") {
		t.Errorf("got %q", lines[0])
	}
	if ParseLine(lines[0]) != nil {
		t.Error("a line with an empty program must not parse into the aggregates")
	}
}

func TestElkMissingProcessNameRendersUnknown(t *testing.T) {
	doc := makeDoc(map[string]any{"process.name": nil})
	path := writeNDJSON(t, []map[string]any{doc}, ".ndjson")
	_, lines := runElk(t, path)
	if !strings.Contains(lines[0], " dnsbox unknown[61685]: DHCPDISCOVER") {
		t.Errorf("got %q", lines[0])
	}
}

func TestElkReadsGzip(t *testing.T) {
	path := writeNDJSON(t, []map[string]any{makeDoc(nil)}, ".ndjson.gz")
	_, lines := runElk(t, path)
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1", len(lines))
	}
}

func TestElkInfersLogDateFromFirstLineLocalTime(t *testing.T) {
	// 23:30 UTC on the 25th is 00:30 on the 26th in Europe/London
	doc := makeDoc(map[string]any{"@timestamp": "2026-08-25T23:30:00.000Z"})
	src, _ := runElk(t, writeNDJSON(t, []map[string]any{doc}, ".ndjson"))
	if src.LogDate == nil || src.LogDate.Format("2006-01-02") != "2026-08-26" {
		t.Errorf("log date = %v, want 2026-08-26", src.LogDate)
	}
}

func TestElkSkipsAndCountsDocsWithoutMessageOrTimestamp(t *testing.T) {
	noMessage := makeDoc(map[string]any{"message": nil})
	noTimestamp := makeDoc(map[string]any{"@timestamp": nil})
	path := writeNDJSON(t, []map[string]any{noMessage, noTimestamp, makeDoc(nil)}, ".ndjson")
	src, lines := runElk(t, path)
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1", len(lines))
	}
	if src.Skipped != 2 {
		t.Errorf("skipped = %d, want 2", src.Skipped)
	}
}

func TestElkFallsBackToShortFormOfHostName(t *testing.T) {
	doc := makeDoc(map[string]any{"host.hostname": ""})
	path := writeNDJSON(t, []map[string]any{doc}, ".ndjson")
	_, lines := runElk(t, path)
	if !strings.Contains(lines[0], " dnsbox dhcpd") {
		t.Errorf("got %q", lines[0])
	}
}

func TestElkCollectsHostOSMapWhenDumpCarriesOSFields(t *testing.T) {
	withOS := makeDoc(map[string]any{
		"host.os.name":    "Ubuntu",
		"host.os.version": "22.04.1 LTS (Jammy Jellyfish)",
		"host.os.family":  "debian",
	})
	withoutOS := makeDoc(map[string]any{"host.hostname": "oldbox"})
	src, _ := runElk(t, writeNDJSON(t, []map[string]any{withOS, withoutOS}, ".ndjson"))
	if !reflect.DeepEqual(src.HostOS, map[string]string{"dnsbox": "Ubuntu 22.04.1"}) {
		t.Errorf("host os = %#v", src.HostOS)
	}
}

func TestElkHostOSEmptyForPreOSDumps(t *testing.T) {
	src, _ := runElk(t, writeNDJSON(t, []map[string]any{makeDoc(nil)}, ".ndjson"))
	if len(src.HostOS) != 0 {
		t.Errorf("host os = %#v, want empty", src.HostOS)
	}
}

func TestElkNewlinesInMessageAreFlattened(t *testing.T) {
	doc := makeDoc(map[string]any{"message": "line one\nline two"})
	_, lines := runElk(t, writeNDJSON(t, []map[string]any{doc}, ".ndjson"))
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if !strings.HasSuffix(lines[0], "line one line two") {
		t.Errorf("got %q", lines[0])
	}
}

func TestElkNonJSONInputRaisesWithLineNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.ndjson")
	if err := os.WriteFile(path,
		[]byte("Aug 26 14:00:05 dnsbox dhcpd[1]: raw text, not JSON\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := NewElkSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Run(); err == nil || !strings.Contains(err.Error(), ":1:") {
		t.Errorf("expected a :1: line-numbered error, got %v", err)
	}
}
