package reporter

// The four LLM stages: issue detection, issue dedupe, resolutions, and
// anomaly explanation. Prompts are embedded so the binary ships
// self-contained; the hand-written JSON schemas mirror the data models in
// models.go. All calls go through the internal/llm seam, which routes on
// the litellm-style model prefix.

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"unicode"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

// go:embed keeps each prompt file's trailing newline; the agents trim it
// so a system prompt never ends in a blank line.

//go:embed prompts/issue_detection.tmpl
var issueDetectionTemplateRaw string

//go:embed prompts/issue_dedupe.txt
var issueDedupePromptRaw string

//go:embed prompts/issue_cluster.txt
var issueClusterPromptRaw string

//go:embed prompts/anomaly_explanation.txt
var anomalyExplanationPromptRaw string

//go:embed prompts/resolution.tmpl
var resolutionTemplateRaw string

var (
	issueDetectionTmpl = template.Must(template.New("issue_detection").Parse(issueDetectionTemplateRaw))
	resolutionTmpl     = template.Must(template.New("resolution").Parse(resolutionTemplateRaw))
)

// issueItemSchema mirrors the Issue model; used by both the detector and
// the deduplicator (they share the IssueList response model).
func issueItemSchema() map[string]any {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"issue":               str(),
			"severity":            map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low"}},
			"description":         str(),
			"example_log_entry":   str(),
			"affected_host":       map[string]any{"type": "array", "items": str()},
			"os":                  str(),
			"affected_service":    str(),
			"timestamp_frequency": str(),
			"potential_impact":    str(),
			"recommended_action":  str(),
		},
		"required": []string{"issue", "severity", "description", "example_log_entry",
			"affected_host", "os", "affected_service", "timestamp_frequency",
			"potential_impact", "recommended_action"},
		"additionalProperties": false,
	}
}

func issueListSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"issues": map[string]any{"type": "array", "items": issueItemSchema()},
		},
		"required":             []string{"issues"},
		"additionalProperties": false,
	}
}

func resolutionListSchema() map[string]any {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"resolutions": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"issue":        str(),
						"root_cause":   str(),
						"investigate":  str(),
						"look_for":     str(),
						"fix_commands": map[string]any{"type": "array", "items": str()},
						"notes":        str(),
					},
					"required":             []string{"issue", "root_cause", "investigate", "look_for", "fix_commands", "notes"},
					"additionalProperties": false,
				},
			},
		},
		"required":             []string{"resolutions"},
		"additionalProperties": false,
	}
}

func anomalyExplanationListSchema() map[string]any {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"explanations": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"host":                str(),
						"program":             str(),
						"likely_causes":       str(),
						"investigation_steps": map[string]any{"type": "array", "items": str()},
						"suggested_commands":  map[string]any{"type": "array", "items": str()},
					},
					"required": []string{"host", "program", "likely_causes",
						"investigation_steps", "suggested_commands"},
					"additionalProperties": false,
				},
			},
		},
		"required":             []string{"explanations"},
		"additionalProperties": false,
	}
}

// chunkLines splits lines into consecutive chunks of at most size lines.
func chunkLines(lines []string, size int) [][]string {
	var chunks [][]string
	for i := 0; i < len(lines); i += size {
		end := i + size
		if end > len(lines) {
			end = len(lines)
		}
		chunks = append(chunks, lines[i:end])
	}
	return chunks
}

// DetectorChunkSize is the lines per issue-detector request. The model
// reports roughly 7-10 issues per request whatever it is sent, and after
// CollapseRepeats every line is a distinct message, so 1000 collapsed lines
// hid real problems on 28 Sep 2026 (ait srg-kQYKT). Cost follows total
// lines, not requests, so smaller chunks only add a system prompt each.
const DetectorChunkSize = 250

// IssueDetectorAgent finds issues in the filtered log, DetectorChunkSize
// lines at a time, after CollapseRepeats has folded each repeated message into one tagged
// example. HostOS is the per-host OS inventory when the log source knows it
// (nil otherwise); the model copies each issue's OS from it. Spread is
// LogFilter.Spread, when the caller has it: lines whose message came from
// several hosts are tagged with the count. SentLines is how many lines Run
// sent after collapsing.
type IssueDetectorAgent struct {
	Lines     []string
	Model     string
	HostOS    map[string]string
	Spread    map[string]int
	SentLines int
}

func NewIssueDetector(lines []string, model string, hostOS map[string]string) *IssueDetectorAgent {
	return &IssueDetectorAgent{Lines: lines, Model: model, HostOS: hostOS}
}

func (a *IssueDetectorAgent) Run(ctx context.Context) (*IssueList, error) {
	system := issueDetectionPrompt(a.HostOS)
	lines := tagSpread(CollapseRepeats(a.Lines), a.Spread)
	a.SentLines = len(lines)
	var all []*Issue
	for _, chunk := range chunkLines(lines, DetectorChunkSize) {
		var got IssueList
		err := llm.Complete(ctx, a.Model, system, strings.Join(chunk, "\n"),
			"IssueList", issueListSchema(), &got)
		if err != nil {
			// What the earlier chunks found, for a run that finishes
			// degraded (llm.ErrBudget); every other caller treats err as fatal.
			return &IssueList{Issues: all}, err
		}
		for _, issue := range got.Issues {
			issue.ExampleLogEntry = stripRepeatTag(issue.ExampleLogEntry)
		}
		all = append(all, got.Issues...)
	}
	return &IssueList{Issues: all}, nil
}

// IssueDeduplicatorAgent merges near-duplicate issues reported across
// separate log chunks, so the top-N digest shows N distinct concerns.
type IssueDeduplicatorAgent struct {
	Issues *IssueList
	Model  string
}

func NewIssueDeduplicator(issues *IssueList, model string) *IssueDeduplicatorAgent {
	return &IssueDeduplicatorAgent{Issues: issues, Model: model}
}

// dedupePayload renders the issues as two-space-indented JSON: full
// fidelity (complete affected_host lists) so the model can merge host
// lists properly.
func dedupePayload(issues *IssueList) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(issues.Issues); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func (a *IssueDeduplicatorAgent) Run(ctx context.Context) (*IssueList, error) {
	// Nothing to merge with 0 or 1 issue: skip the call.
	if len(a.Issues.Issues) <= 1 {
		return a.Issues, nil
	}
	payload, err := dedupePayload(a.Issues)
	if err != nil {
		return nil, err
	}
	system := strings.TrimSuffix(issueDedupePromptRaw, "\n")
	var got IssueList
	err = llm.Complete(ctx, a.Model, system, payload, "IssueList", issueListSchema(), &got)
	if err != nil {
		return nil, err
	}
	return &got, nil
}

// IssueClusterer groups a digest window's daily issues by underlying
// problem (ait srg-tCbyJ). Service labels, titles and host sets are LLM
// prose that drift from day to day, so no deterministic key matches the
// same fault across days; the model assigns clusters and BuildDigest
// still does all the counting.
type IssueClusterer struct {
	Findings []*FindingDetail
	Model    string
}

func NewIssueClusterer(findings []*FindingDetail, model string) *IssueClusterer {
	return &IssueClusterer{Findings: findings, Model: model}
}

func issueClusterSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"clusters": map[string]any{"type": "array", "items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"label": map[string]any{"type": "string"},
					"ids":   map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
				},
				"required":             []string{"label", "ids"},
				"additionalProperties": false,
			}},
		},
		"required":             []string{"clusters"},
		"additionalProperties": false,
	}
}

type issueClusters struct {
	Clusters []struct {
		Label string  `json:"label"`
		IDs   []int64 `json:"ids"`
	} `json:"clusters"`
}

// Run returns a cluster number for every issue finding's id. The model's
// answer is checked, not trusted (it has invented ids, listed one twice and
// left one out in testing): unknown ids are dropped, an id listed twice
// stays in its first cluster, and an id left out becomes a cluster of its
// own. Anomaly findings are ignored.
func (a *IssueClusterer) Run(ctx context.Context) (map[int64]int, error) {
	type item struct {
		ID       int64    `json:"id"`
		Date     string   `json:"date"`
		Severity string   `json:"severity"`
		Service  string   `json:"service"`
		Title    string   `json:"title"`
		Hosts    []string `json:"hosts"`
	}
	var items []item
	for _, f := range a.Findings {
		if f.Kind == "issue" && f.Issue != nil {
			items = append(items, item{f.ID, f.LogDate, f.Severity, f.Service, f.Title, f.Hosts})
		}
	}
	out := make(map[int64]int, len(items))
	next := 0 // the first cluster number the model did not use
	if len(items) > 1 {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(items); err != nil {
			return nil, err
		}
		var got issueClusters
		system := strings.TrimSuffix(issueClusterPromptRaw, "\n")
		if err := llm.Complete(ctx, a.Model, system, strings.TrimSuffix(buf.String(), "\n"),
			"IssueClusters", issueClusterSchema(), &got); err != nil {
			return nil, err
		}
		known := make(map[int64]bool, len(items))
		for _, it := range items {
			known[it.ID] = true
		}
		next = len(got.Clusters)
		for n, c := range got.Clusters {
			for _, id := range c.IDs {
				if _, taken := out[id]; known[id] && !taken {
					out[id] = n
				}
			}
		}
	}
	for _, it := range items {
		if _, ok := out[it.ID]; !ok {
			out[it.ID] = next
			next++
		}
	}
	return out, nil
}

// ResolutionAgent turns each issue into paste-ready investigate/fix commands.
// Contexts, when given, is one LogContext per issue (see LogIndex) and is
// appended to that issue's markdown so the model reasons from the
// surrounding lines rather than a single example.
type ResolutionAgent struct {
	Issues   *IssueList
	Contexts []LogContext
	Model    string
	HostOS   map[string]string
}

func NewResolutionAgent(issues *IssueList, contexts []LogContext, model string, hostOS map[string]string) *ResolutionAgent {
	return &ResolutionAgent{Issues: issues, Contexts: contexts, Model: model, HostOS: hostOS}
}

// resolutionBatchSize caps the issues per resolution request. One request
// for a whole day's issues sends nothing back until every resolution is
// written, and on a slow provider day that outlived the connection: 48
// issues produced no response headers in ten minutes (openai-go's cap,
// seen 2026-09-09), and the SDK then re-sent the identical request eight
// more times. A dozen per call keeps each request to a few minutes, so a
// retry redoes one batch rather than the day.
const resolutionBatchSize = 12

// explainBatchSize caps the anomalies per explainer request, for the same
// reason. It equals DefaultMaxExplain so a daily run at the default cap
// still makes exactly one request; the weekly digest, or a raised cap,
// gets the protection (ait srg-xiBoC.5).
const explainBatchSize = 15

// DefaultMaxResolveIssues is the default SYSLOG_MAX_RESOLVE_ISSUES: the
// most issues one run hands to the resolution writer. The writer runs on
// the expensive model and its output tokens are most of a day's bill, so
// a storm day that detects a thousand issues must not turn into a
// thousand resolutions (owner decision 2026-09-09). The digest's severity
// ranking picks which ones are written; the rest still reach the
// attachment and the library as detected.
const DefaultMaxResolveIssues = 60

// batches splits the agent into per-request agents of at most
// resolutionBatchSize issues, each carrying the context windows for its
// own issues (Contexts is index-aligned with Issues, or nil).
func (a *ResolutionAgent) batches() []*ResolutionAgent {
	var out []*ResolutionAgent
	for i := 0; i < len(a.Issues.Issues); i += resolutionBatchSize {
		end := min(i+resolutionBatchSize, len(a.Issues.Issues))
		b := &ResolutionAgent{Issues: &IssueList{Issues: a.Issues.Issues[i:end]}, Model: a.Model, HostOS: a.HostOS}
		if i < len(a.Contexts) {
			b.Contexts = a.Contexts[i:min(end, len(a.Contexts))]
		}
		out = append(out, b)
	}
	return out
}

// payload is the issues as markdown, each followed by its context window
// when one was found.
func (a *ResolutionAgent) payload() string {
	var b strings.Builder
	for i, issue := range a.Issues.Issues {
		b.WriteString(issue.ToMarkdown())
		if i < len(a.Contexts) {
			b.WriteString(a.Contexts[i].ToMarkdown())
		}
		b.WriteString("\n")
	}
	return b.String()
}

type hostOSEntry struct{ Host, OS string }

func issueDetectionPrompt(hostOS map[string]string) string {
	return hostOSPrompt(issueDetectionTmpl, hostOS, false)
}

// resolutionPrompt renders the resolution system prompt; withContext adds
// the paragraph explaining the "Surrounding log lines" blocks, so a run
// with context disabled never tells the model to expect them.
func resolutionPrompt(hostOS map[string]string, withContext bool) string {
	return hostOSPrompt(resolutionTmpl, hostOS, withContext)
}

// hostOSPrompt renders a system prompt template, embedding the per-host OS
// inventory when the log source knows it, sorted case-insensitively by
// host (exact host as the tie-break, so the order never depends on map
// iteration).
func hostOSPrompt(tmpl *template.Template, hostOS map[string]string, withContext bool) string {
	entries := make([]hostOSEntry, 0, len(hostOS))
	for host, osName := range hostOS {
		entries = append(entries, hostOSEntry{Host: host, OS: osName})
	}
	sort.Slice(entries, func(i, j int) bool {
		li, lj := strings.ToLower(entries[i].Host), strings.ToLower(entries[j].Host)
		if li != lj {
			return li < lj
		}
		return entries[i].Host < entries[j].Host
	})
	var buf strings.Builder
	_ = tmpl.Execute(&buf, struct {
		HostOS      []hostOSEntry
		WithContext bool
	}{entries, withContext})
	return strings.TrimSuffix(buf.String(), "\n")
}

func (a *ResolutionAgent) Run(ctx context.Context) (*ResolutionList, error) {
	if len(a.Issues.Issues) == 0 {
		return &ResolutionList{}, nil
	}
	system := resolutionPrompt(a.HostOS, len(a.Contexts) > 0)
	var all ResolutionList
	var err error
	for _, batch := range a.batches() {
		var got ResolutionList
		err = llm.Complete(ctx, a.Model, system, batch.payload(),
			"ResolutionList", resolutionListSchema(), &got)
		if err != nil {
			break // return the batches already written alongside err
		}
		all.Resolutions = append(all.Resolutions, got.Resolutions...)
	}
	// Models pad some list entries with stray leading whitespace (seen from
	// gpt-5.6-luna, 2026-08-29: '# comment' lines with one leading space).
	// Trim at the parse boundary so every downstream view - markdown files,
	// email, findings library - agrees.
	for _, r := range all.Resolutions {
		r.Investigate = strings.TrimSpace(r.Investigate)
		r.LookFor = strings.TrimSpace(r.LookFor)
		trimEach(r.FixCommands)
	}
	return &all, err
}

// trimEach TrimSpaces a list of LLM-supplied lines in place.
func trimEach(ss []string) {
	for i := range ss {
		ss[i] = strings.TrimSpace(ss[i])
	}
}

// AnomalyExplanation is the LLM-generated half of an explained anomaly.
type AnomalyExplanation struct {
	Host               string   `json:"host"`
	Program            string   `json:"program"`
	LikelyCauses       string   `json:"likely_causes"`
	InvestigationSteps []string `json:"investigation_steps"`
	SuggestedCommands  []string `json:"suggested_commands"`
}

type AnomalyExplanationList struct {
	Explanations []*AnomalyExplanation `json:"explanations"`
}

// AnomalyExplainerAgent asks the LLM to explain the top detected anomalies:
// likely causes, investigation steps, and OS-aware commands. Detection stays
// deterministic; the LLM never decides what counts as an anomaly.
type AnomalyExplainerAgent struct {
	Anomalies  []Anomaly
	Model      string
	MaxExplain int
}

func NewAnomalyExplainer(anomalies []Anomaly, model string) *AnomalyExplainerAgent {
	return &AnomalyExplainerAgent{Anomalies: anomalies, Model: model, MaxExplain: DefaultMaxExplain}
}

// explainerPayload lists the anomalies one per line, quoting the free-text
// fields so multi-line log text stays on one payload line.
func explainerPayload(anomalies []Anomaly) string {
	lines := make([]string, len(anomalies))
	for i, a := range anomalies {
		lines[i] = fmt.Sprintf("%d. host=%s program=%s os_family=%s what=%s detail=%s example=%s",
			i+1, a.Host(), a.Program(), a.OSFamily(),
			quoteField(a.Headline()), quoteField(a.Summary()), quoteField(a.ExampleLine()))
	}
	return strings.Join(lines, "\n")
}

// batches splits the MaxExplain-capped anomalies into per-request chunks
// of at most explainBatchSize, in order.
func (a *AnomalyExplainerAgent) batches() [][]Anomaly {
	top := a.Anomalies
	if len(top) > a.MaxExplain {
		top = top[:a.MaxExplain]
	}
	var out [][]Anomaly
	for i := 0; i < len(top); i += explainBatchSize {
		out = append(out, top[i:min(i+explainBatchSize, len(top))])
	}
	return out
}

func (a *AnomalyExplainerAgent) Run(ctx context.Context) ([]*ExplainedAnomaly, error) {
	batches := a.batches()
	if len(batches) == 0 {
		return nil, nil
	}
	system := strings.TrimSuffix(anomalyExplanationPromptRaw, "\n")
	var top []Anomaly
	var explanations []*AnomalyExplanation
	var err error
	for _, batch := range batches {
		top = append(top, batch...)
		if err != nil {
			continue // keep the rest as facts only, alongside err
		}
		var got AnomalyExplanationList
		err = llm.Complete(ctx, a.Model, system, explainerPayload(batch),
			"AnomalyExplanationList", anomalyExplanationListSchema(), &got)
		explanations = append(explanations, got.Explanations...)
	}
	return mergeExplanations(top, explanations), err
}

// mergeExplanations pairs each anomaly with its explanation by
// (host, program). Anomalies the LLM didn't return are still rendered, with
// the facts only, so nothing silently disappears from the report.
func mergeExplanations(anomalies []Anomaly, explanations []*AnomalyExplanation) []*ExplainedAnomaly {
	byKey := make(map[[2]string]*AnomalyExplanation, len(explanations))
	for _, e := range explanations {
		byKey[[2]string{e.Host, e.Program}] = e
	}
	explained := make([]*ExplainedAnomaly, len(anomalies))
	for i, a := range anomalies {
		ea := &ExplainedAnomaly{
			Host:         a.Host(),
			Program:      a.Program(),
			Kind:         a.Kind(),
			Headline:     a.Headline(),
			Detail:       a.Summary(),
			OSFamily:     a.OSFamily(),
			ExampleLine:  a.ExampleLine(),
			LikelyCauses: "(no explanation generated)",
		}
		if e, ok := byKey[[2]string{a.Host(), a.Program()}]; ok {
			trimEach(e.InvestigationSteps)
			trimEach(e.SuggestedCommands)
			ea.LikelyCauses = e.LikelyCauses
			ea.InvestigationSteps = e.InvestigationSteps
			ea.SuggestedCommands = e.SuggestedCommands
		}
		explained[i] = ea
	}
	return explained
}

// quoteField quotes a string for the explainer payload: single quotes
// unless the string contains a single quote and no double quote; backslash
// escapes for the quote, backslash, \n \r \t; \xhh (or \u/\U) for other
// non-printables. The exact output is pinned by test vectors.
func quoteField(s string) string {
	quote := rune('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, r := range s {
		switch {
		case r == quote || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteRune(quote)
	return b.String()
}
