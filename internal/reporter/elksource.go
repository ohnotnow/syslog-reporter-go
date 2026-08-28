package reporter

// Port of agents/elk_source.py: turn dumped Elasticsearch syslog documents
// back into classic rsyslog text lines. The rest of the pipeline parses raw
// 'Mon DD HH:MM:SS host program[pid]: message' lines by whitespace split, so
// rather than teach every stage a second data model we render each ES
// document back into that shape.
//
// Input is the NDJSON produced by tools/elk_dump.py in the Python repo: one
// JSON object per line, flat dotted keys (@timestamp, host.name,
// host.hostname, process.name, process.pid, message), optionally
// gzip-compressed (.gz suffix).

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	_ "time/tzdata" // embed the tz database so Europe/London resolves on any box
)

type ElkSource struct {
	path string
	tz   *time.Location

	// Set by Run: the local-time date of the first line, so callers can key
	// the aggregate store off the data instead of assuming yesterday.
	LogDate *time.Time
	Skipped int
	// Set by Run when the dump carries host.os.* fields (older dumps don't):
	// short hostname to "Ubuntu 22.04". Callers can use it to replace the
	// program-based OS guess with the real OS.
	HostOS map[string]string
}

func NewElkSource(path string) (*ElkSource, error) {
	tz, err := time.LoadLocation("Europe/London")
	if err != nil {
		return nil, err
	}
	return &ElkSource{path: path, tz: tz, HostOS: map[string]string{}}, nil
}

func (s *ElkSource) Run() ([]string, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(s.path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}

	var lines []string
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	lineno := 0
	for scanner.Scan() {
		lineno++
		raw := scanner.Text()
		if pyStrip(raw) == "" {
			continue
		}
		var doc map[string]any
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf(
				"%s:%d: not valid JSON (%v); is this really an elk_dump.py NDJSON file?",
				s.path, lineno, err)
		}
		rendered, ts, ok, err := s.render(doc)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", s.path, lineno, err)
		}
		if !ok {
			s.Skipped++
			continue
		}
		if s.LogDate == nil {
			day := time.Date(ts.Year(), ts.Month(), ts.Day(), 0, 0, 0, 0, time.UTC)
			s.LogDate = &day
		}
		lines = append(lines, rendered)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (s *ElkSource) localTime(timestamp string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad @timestamp %q: %w", timestamp, err)
	}
	return t.In(s.tz), nil
}

func docString(doc map[string]any, key string) string {
	v, ok := doc[key]
	if !ok || v == nil {
		return ""
	}
	return pyStr(v)
}

// pyStr renders a decoded JSON value the way Python's str() would.
func pyStr(v any) string {
	switch val := v.(type) {
	case nil:
		return "None"
	case string:
		return val
	case json.Number:
		return val.String()
	case bool:
		if val {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(val)
	}
}

// pyGetStr mirrors Python's str(doc.get(key, default)): the default applies
// only when the key is absent, so a present-but-empty value stays empty
// (the 2026-08-26 dump has a pid-only doc that must render as 'host [pid]:',
// exactly as the Python original does).
func pyGetStr(doc map[string]any, key, def string) string {
	v, exists := doc[key]
	if !exists {
		return def
	}
	return pyStr(v)
}

func (s *ElkSource) noteHostOS(doc map[string]any, host string) {
	if _, seen := s.HostOS[host]; seen {
		return
	}
	name := docString(doc, "host.os.name")
	if name == "" {
		return
	}
	version := strings.SplitN(pyGetStr(doc, "host.os.version", ""), " ", 2)[0]
	s.HostOS[host] = strings.TrimSpace(name + " " + version)
}

// render turns one ES document into an rsyslog-style line. ok is false when
// the document has no timestamp or message (the caller counts it as skipped).
func (s *ElkSource) render(doc map[string]any) (line string, ts time.Time, ok bool, err error) {
	timestamp := docString(doc, "@timestamp")
	message := docString(doc, "message")
	if timestamp == "" || message == "" {
		return "", time.Time{}, false, nil
	}
	ts, err = s.localTime(timestamp)
	if err != nil {
		return "", time.Time{}, false, err
	}
	// Syslog pads a single-digit day with a space: 'Aug  6', not 'Aug 6'.
	stamp := fmt.Sprintf("%s %2d %s", ts.Format("Jan"), ts.Day(), ts.Format("15:04:05"))
	host := docString(doc, "host.hostname")
	if host == "" {
		host = strings.SplitN(pyGetStr(doc, "host.name", "unknown"), ".", 2)[0]
	}
	s.noteHostOS(doc, host)
	// Default only when the key is absent: a present-but-empty process.name
	// renders an empty program, exactly like the Python original.
	program := pyGetStr(doc, "process.name", "unknown")
	var tag string
	if pid, exists := doc["process.pid"]; exists && pid != nil {
		tag = fmt.Sprintf("%s[%s]:", program, docString(doc, "process.pid"))
	} else {
		tag = program + ":"
	}
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	return fmt.Sprintf("%s %s %s %s", stamp, host, tag, message), ts, true, nil
}
