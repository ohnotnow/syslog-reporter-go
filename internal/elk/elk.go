// Package elk dumps one day of syslog documents from Elasticsearch as
// NDJSON: one trimmed JSON object per line, flat dotted keys, the input
// reporter.ElkSource reads (ait srg-Sm1Is.1). Paging is a point-in-time
// plus search_after, so the dump is a consistent snapshot with no skipped
// or duplicated documents. The account needs only the 'read' index
// privilege (which includes PIT).
//
// The day is bounded on both sides (gte day, lt day+1, in the given time
// zone), which also keeps out the future-dated documents that bad RFC3164
// year parsing creates around new year.
//
// Proxies follow the standard http(s)_proxy / no_proxy variables; a site
// whose cluster must not go through its proxy lists it in no_proxy.
package elk

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pitKeepAlive = "5m"

// keepFields are the source fields the pipeline needs, written in this
// order as flat dotted keys; a missing or null field is left out.
var keepFields = [][]string{
	{"@timestamp"},
	{"host", "name"},
	{"host", "hostname"},
	{"host", "os", "name"},
	{"host", "os", "version"},
	{"host", "os", "family"},
	{"process", "name"},
	{"process", "pid"},
	{"message"},
}

// Config is one dump. URL, Index, Auth and Day are required.
type Config struct {
	URL       string
	Index     string
	Auth      string // Authorization header value, from AuthHeader
	Day       string // YYYY-MM-DD
	TZ        string // IANA name or +hh:mm, passed to Elasticsearch verbatim
	BatchSize int    // documents per search, 1..10000
	Timeout   time.Duration
	Insecure  bool   // skip TLS verification
	CACert    string // PEM file of a CA to trust instead of the system pool
}

// Result describes a finished dump.
type Result struct {
	Written, Total int
	First, Last    string // @timestamp of the first and last document
	Searches       int
}

// ErrIncomplete means the dump finished but wrote a different number of
// documents than the search reported; no file is left under the final name.
var ErrIncomplete = errors.New("document count does not match the search total")

// AuthHeader builds the Authorization value. An API key wins; an "id:key"
// key is base64-encoded, anything else is assumed already encoded, as
// Kibana hands it out. Otherwise username and password make Basic auth.
func AuthHeader(apiKey, username, password string) (string, error) {
	if apiKey != "" {
		if strings.Contains(apiKey, ":") {
			apiKey = base64.StdEncoding.EncodeToString([]byte(apiKey))
		}
		return "ApiKey " + apiKey, nil
	}
	if username == "" {
		return "", errors.New("no credentials: set ELK_API_KEY or ELK_USERNAME/ELK_PASSWORD (env or .env), or pass --key-file / --username")
	}
	if password == "" {
		return "", fmt.Errorf("no password for %s: set ELK_PASSWORD (env or .env)", username)
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)), nil
}

type client struct {
	base     string
	auth     string
	http     *http.Client
	searches int
}

func newClient(cfg Config) (*client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch {
	case cfg.Insecure:
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case cfg.CACert != "":
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CACert)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &client{
		base: strings.TrimRight(cfg.URL, "/"),
		auth: cfg.Auth,
		http: &http.Client{Transport: transport, Timeout: cfg.Timeout},
	}, nil
}

// do sends one request and decodes the JSON reply into out (nil = discard).
// Numbers decode as json.Number so a pid or a sort value survives exactly.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
		return fmt.Errorf("%s %s: HTTP %d\n%s", method, path, resp.StatusCode, detail)
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	return dec.Decode(out)
}

// shardStatus is the _shards block of a PIT or search reply. An HTTP 200
// is not proof of a whole answer: a failed shard or a timed-out search
// returns a subset, and its total can match what it returned.
type shardStatus struct {
	Total  int `json:"total"`
	Failed int `json:"failed"`
}

func (s shardStatus) check(what string) error {
	if s.Failed > 0 {
		return fmt.Errorf("%s: %d of %d shards failed", what, s.Failed, s.Total)
	}
	return nil
}

type searchResponse struct {
	PitID    string      `json:"pit_id"`
	TimedOut bool        `json:"timed_out"`
	Shards   shardStatus `json:"_shards"`
	Hits     struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source map[string]any    `json:"_source"`
			Sort   []json.RawMessage `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

// Dump writes cfg.Day's documents to out (gzip when out ends in .gz) and
// logs progress to logw. It writes to a temporary file beside out and
// renames it only when the whole day arrived, so a file under the final
// name is always a complete day.
func Dump(ctx context.Context, cfg Config, out string, logw io.Writer) (res Result, err error) {
	day, err := time.Parse("2006-01-02", cfg.Day)
	if err != nil {
		return res, fmt.Errorf("day must be YYYY-MM-DD, got %q", cfg.Day)
	}
	c, err := newClient(cfg)
	if err != nil {
		return res, err
	}
	query := map[string]any{"range": map[string]any{"@timestamp": map[string]any{
		"gte":       cfg.Day,
		"lt":        day.AddDate(0, 0, 1).Format("2006-01-02"),
		"format":    "yyyy-MM-dd",
		"time_zone": cfg.TZ,
	}}}

	var pit struct {
		ID     string      `json:"id"`
		Shards shardStatus `json:"_shards"`
	}
	if err := c.do(ctx, http.MethodPost, "/"+escapeIndex(cfg.Index)+"/_pit?keep_alive="+pitKeepAlive, nil, &pit); err != nil || pit.ID == "" {
		if err == nil {
			err = errors.New("no id in the reply")
		}
		return res, fmt.Errorf("could not open a point-in-time on %s: %w\n"+
			"The account needs the 'read' index privilege on the pattern (check with GET /_security/user/_privileges)", cfg.Index, err)
	}
	pitID := pit.ID
	defer func() {
		// A background context: a cancelled dump should still close its PIT.
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.do(closeCtx, http.MethodDelete, "/_pit", map[string]any{"id": pitID}, nil); err != nil {
			fmt.Fprintf(logw, "warning: could not close the point-in-time (it expires on its own after %s)\n", pitKeepAlive)
		}
		res.Searches = c.searches
	}()
	if err := pit.Shards.check("opening the point-in-time"); err != nil {
		return res, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".tmp-*")
	if err != nil {
		return res, err
	}
	defer func() {
		if tmp != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	var w io.Writer = tmp
	var gz *gzip.Writer
	if strings.HasSuffix(out, ".gz") {
		gz = gzip.NewWriter(tmp)
		w = gz
	}
	bw := newDocWriter(w)

	var searchAfter []json.RawMessage
	first := true
	for {
		body := map[string]any{
			"size":             cfg.BatchSize,
			"query":            query,
			"pit":              map[string]any{"id": pitID, "keep_alive": pitKeepAlive},
			"sort":             []any{map[string]any{"@timestamp": "asc"}},
			"track_total_hits": first,
			// Refuse a subset rather than detect it afterwards; the checks
			// below cover clusters that ignore this.
			"allow_partial_search_results": false,
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		var sr searchResponse
		c.searches++
		if err := c.do(ctx, http.MethodPost, "/_search", body, &sr); err != nil {
			return res, fmt.Errorf("after %d documents: %w", res.Written, err)
		}
		if sr.PitID != "" {
			pitID = sr.PitID
		}
		if sr.TimedOut {
			return res, fmt.Errorf("after %d documents: search timed out (partial results)", res.Written)
		}
		if err := sr.Shards.check(fmt.Sprintf("after %d documents", res.Written)); err != nil {
			return res, err
		}
		if first {
			res.Total = sr.Hits.Total.Value
			fmt.Fprintf(logw, "documents in window: %d\n", res.Total)
			first = false
		}
		if len(sr.Hits.Hits) == 0 {
			break
		}
		for _, hit := range sr.Hits.Hits {
			ts, err := bw.write(hit.Source)
			if err != nil {
				return res, err
			}
			if ts != "" {
				if res.First == "" {
					res.First = ts
				}
				res.Last = ts
			}
		}
		res.Written += len(sr.Hits.Hits)
		searchAfter = sr.Hits.Hits[len(sr.Hits.Hits)-1].Sort
		fmt.Fprintf(logw, "  fetched %d / %d\n", res.Written, res.Total)
	}

	if gz != nil {
		if err := gz.Close(); err != nil {
			return res, err
		}
	}
	if err := tmp.Close(); err != nil {
		return res, err
	}
	if res.Written != res.Total {
		return res, fmt.Errorf("%w: expected %d, wrote %d", ErrIncomplete, res.Total, res.Written)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return res, err
	}
	tmp = nil
	return res, nil
}

// docWriter writes trimmed documents one per line with keys in keepFields
// order and without HTML escaping, so '<', '>' and '&' in a message stay
// literal.
type docWriter struct {
	w   io.Writer
	buf bytes.Buffer
	enc *json.Encoder
}

func newDocWriter(w io.Writer) *docWriter {
	d := &docWriter{w: w}
	d.enc = json.NewEncoder(&d.buf)
	d.enc.SetEscapeHTML(false)
	return d
}

// write emits one document and returns its @timestamp when it is a string.
func (d *docWriter) write(source map[string]any) (string, error) {
	var line bytes.Buffer
	line.WriteByte('{')
	var ts string
	n := 0
	for _, path := range keepFields {
		v := lookup(source, path)
		if v == nil {
			continue
		}
		if path[0] == "@timestamp" {
			ts, _ = v.(string)
		}
		if n > 0 {
			line.WriteByte(',')
		}
		n++
		if err := d.encode(&line, strings.Join(path, ".")); err != nil {
			return "", err
		}
		line.WriteByte(':')
		if err := d.encode(&line, v); err != nil {
			return "", err
		}
	}
	line.WriteString("}\n")
	_, err := d.w.Write(line.Bytes())
	return ts, err
}

// encode appends v's JSON to line, without the encoder's trailing newline.
func (d *docWriter) encode(line *bytes.Buffer, v any) error {
	d.buf.Reset()
	if err := d.enc.Encode(v); err != nil {
		return err
	}
	line.Write(bytes.TrimSuffix(d.buf.Bytes(), []byte("\n")))
	return nil
}

func lookup(source map[string]any, path []string) any {
	var v any = source
	for _, part := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		if v, ok = m[part]; !ok {
			return nil
		}
	}
	return v
}

// escapeIndex percent-encodes an index pattern for the URL path, keeping
// the characters a pattern is made of (letters, digits, * , - _ . ~).
func escapeIndex(index string) string {
	var b strings.Builder
	for _, c := range []byte(index) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("*,-_.~", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
