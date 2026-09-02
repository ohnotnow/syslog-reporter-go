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
						"fix_commands": map[string]any{"type": "array", "items": str()},
						"notes":        str(),
					},
					"required":             []string{"issue", "root_cause", "investigate", "fix_commands", "notes"},
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

// IssueDetectorAgent finds issues in the filtered log, 1000 lines at a time.
// HostOS is the per-host OS inventory when the log source knows it (nil
// otherwise); the model copies each issue's OS from it.
type IssueDetectorAgent struct {
	Lines  []string
	Model  string
	HostOS map[string]string
}

func NewIssueDetector(lines []string, model string, hostOS map[string]string) *IssueDetectorAgent {
	return &IssueDetectorAgent{Lines: lines, Model: model, HostOS: hostOS}
}

func (a *IssueDetectorAgent) Run(ctx context.Context) (*IssueList, error) {
	system := issueDetectionPrompt(a.HostOS)
	var all []*Issue
	for _, chunk := range chunkLines(a.Lines, 1000) {
		var got IssueList
		err := llm.Complete(ctx, a.Model, system, strings.Join(chunk, "\n"),
			"IssueList", issueListSchema(), &got)
		if err != nil {
			return nil, err
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

// ResolutionAgent turns each issue into paste-ready investigate/fix commands.
type ResolutionAgent struct {
	Issues *IssueList
	Model  string
	HostOS map[string]string
}

func NewResolutionAgent(issues *IssueList, model string, hostOS map[string]string) *ResolutionAgent {
	return &ResolutionAgent{Issues: issues, Model: model, HostOS: hostOS}
}

type hostOSEntry struct{ Host, OS string }

func issueDetectionPrompt(hostOS map[string]string) string {
	return hostOSPrompt(issueDetectionTmpl, hostOS)
}

func resolutionPrompt(hostOS map[string]string) string {
	return hostOSPrompt(resolutionTmpl, hostOS)
}

// hostOSPrompt renders a system prompt template, embedding the per-host OS
// inventory when the log source knows it, sorted case-insensitively by
// host (exact host as the tie-break, so the order never depends on map
// iteration).
func hostOSPrompt(tmpl *template.Template, hostOS map[string]string) string {
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
	_ = tmpl.Execute(&buf, struct{ HostOS []hostOSEntry }{entries})
	return strings.TrimSuffix(buf.String(), "\n")
}

func (a *ResolutionAgent) Run(ctx context.Context) (*ResolutionList, error) {
	if len(a.Issues.Issues) == 0 {
		return &ResolutionList{}, nil
	}
	var got ResolutionList
	err := llm.Complete(ctx, a.Model, resolutionPrompt(a.HostOS), a.Issues.ToMarkdown(),
		"ResolutionList", resolutionListSchema(), &got)
	if err != nil {
		return nil, err
	}
	// Models pad some list entries with stray leading whitespace (seen from
	// gpt-5.6-luna, 2026-08-29: '# comment' lines with one leading space).
	// Trim at the parse boundary so every downstream view - markdown files,
	// email, findings library - agrees.
	for _, r := range got.Resolutions {
		r.Investigate = strings.TrimSpace(r.Investigate)
		trimEach(r.FixCommands)
	}
	return &got, nil
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

func (a *AnomalyExplainerAgent) Run(ctx context.Context) ([]*ExplainedAnomaly, error) {
	top := a.Anomalies
	if len(top) > a.MaxExplain {
		top = top[:a.MaxExplain]
	}
	if len(top) == 0 {
		return nil, nil
	}
	system := strings.TrimSuffix(anomalyExplanationPromptRaw, "\n")
	var got AnomalyExplanationList
	err := llm.Complete(ctx, a.Model, system, explainerPayload(top),
		"AnomalyExplanationList", anomalyExplanationListSchema(), &got)
	if err != nil {
		return nil, err
	}
	return mergeExplanations(top, got.Explanations), nil
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
