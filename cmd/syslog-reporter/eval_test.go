package main

// Eval tests cover configuration and accounting; the local endpoint tests
// request routing, not model quality.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

func TestEvalOutputNameSanitisesTheModelString(t *testing.T) {
	when := time.Date(2026, 8, 29, 15, 12, 3, 0, time.UTC)
	got := evalOutputName("azure/gpt-5.6-luna:live", when)
	want := "eval_azure_gpt-5.6-luna_live_2026-08-29_151203.md"
	if got != want {
		t.Errorf("evalOutputName = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "/:") {
		t.Errorf("output name still contains / or : - %q", got)
	}
}

func TestEvalFrontMatterRendersEveryField(t *testing.T) {
	meta := evalMeta{
		Model:         "openai/gpt-5.6-luna",
		Generated:     time.Date(2026, 8, 29, 15, 12, 3, 0, time.UTC),
		InputLines:    5000,
		FilteredLines: 480,
		Detect:        1500 * time.Millisecond,
		Dedupe:        250 * time.Millisecond,
		Resolve:       2 * time.Second,
		Total:         3750 * time.Millisecond,
		Usage:         llm.Usage{PromptTokens: 1234, CompletionTokens: 567},
	}
	got := evalFrontMatter(meta)
	if !strings.HasPrefix(got, "---\n") || !strings.HasSuffix(got, "---\n") {
		t.Errorf("front-matter not fenced with ---: %q", got)
	}
	for _, want := range []string{
		`model: "openai/gpt-5.6-luna"`,
		"generated: 2026-08-29T15:12:03Z",
		"input_lines: 5000",
		"filtered_lines: 480",
		"duration_detection: 1.5s",
		"duration_dedupe: 250ms",
		"duration_resolution: 2s",
		"duration_total: 3.75s",
		"prompt_tokens: 1234",
		"completion_tokens: 567",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("front-matter missing line %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "cost") {
		t.Error("front-matter must not compute a cost")
	}
}

// The bundled fixture ships in the public repo: every line must use a
// fictional hostname (repo rule - no real estate names ever).
func TestEvalFixtureUsesFictionalHostnamesOnly(t *testing.T) {
	for i, line := range strings.Split(strings.TrimRight(evalFixture, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			t.Fatalf("fixture line %d is not syslog-shaped: %q", i+1, line)
		}
		if !strings.HasSuffix(fields[3], ".example.test") {
			t.Errorf("fixture line %d hostname %q is not *.example.test", i+1, fields[3])
		}
	}
}

func TestEvalModelPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, base, scan, issue string
		args                    []string
		wantScan, wantIssue     string
	}{
		{name: "built-in", wantScan: "openai/gpt-5.6-luna", wantIssue: "openai/gpt-5.6-luna"},
		{name: "default env", base: "openai/default", wantScan: "openai/default", wantIssue: "openai/default"},
		{name: "model flag", base: "openai/default", args: []string{"--model", "openai/flag"}, wantScan: "openai/flag", wantIssue: "openai/flag"},
		{name: "stage env beats model", scan: "openai/scan", issue: "openai/issue", args: []string{"--model", "openai/flag"}, wantScan: "openai/scan", wantIssue: "openai/issue"},
		{name: "partial split", scan: "openai/scan", args: []string{"--model", "openai/flag"}, wantScan: "openai/scan", wantIssue: "openai/flag"},
		{name: "override issue only", scan: "openai/scan", issue: "openai/issue", args: []string{"--issue-model", "openai/other"}, wantScan: "openai/scan", wantIssue: "openai/other"},
		{name: "force single", scan: "openai/scan", issue: "openai/issue", args: []string{"--scan-model", "openai/single", "--issue-model", "openai/single"}, wantScan: "openai/single", wantIssue: "openai/single"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SYSLOG_DEFAULT_MODEL", tc.base)
			t.Setenv("SYSLOG_LOGSCAN_MODEL", tc.scan)
			t.Setenv("SYSLOG_ISSUE_MODEL", tc.issue)
			cfg, err := parseEvalFlags(tc.args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.scanModel != tc.wantScan || cfg.issueModel != tc.wantIssue {
				t.Fatalf("models = %q, %q; want %q, %q", cfg.scanModel, cfg.issueModel, tc.wantScan, tc.wantIssue)
			}
		})
	}
}

func TestEvalRoutesModelsAndAccountsForStages(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			var models []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Model  string `json:"model"`
					Effort string `json:"reasoning_effort"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				models = append(models, body.Model)
				if body.Effort != "high" {
					t.Errorf("effort = %q", body.Effort)
				}
				content := `{"issues":[{"issue":"Disk full","severity":"high"},{"issue":"Disk full again","severity":"high"}]}`
				if len(models) == 2 {
					content = `{"issues":[{"issue":"Disk full","severity":"high"}]}`
				}
				if len(models) == 3 {
					content = `{"resolutions":[{"issue":"Disk full","root_cause":"No space"}]}`
				}
				if empty {
					content = `{"issues":[]}`
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"id":"eval-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q}}],"usage":{"prompt_tokens":%d,"completion_tokens":%d}}`, content, len(models)*100, len(models)*10)
			}))
			t.Cleanup(server.Close)
			t.Cleanup(llm.ResetUsage)
			t.Cleanup(func() { llm.SetLogger(nil) })
			t.Setenv("OPENAI_BASE_URL", server.URL+"/v1/")
			t.Setenv("OPENAI_API_KEY", "test-key")
			t.Setenv("SYSLOG_REASONING_EFFORT", "high")
			t.Setenv("SYSLOG_BLANKET_IGNORE", "")
			t.Setenv("SYSLOG_KNOWN_KNOWNS", filepath.Join(t.TempDir(), "absent.toml"))
			out := filepath.Join(t.TempDir(), "eval.md")
			runEval([]string{"--scan-model", "openai/scan-test", "--issue-model", "openai/issue-test", "--out", out})
			wantModels := []string{"scan-test", "scan-test", "issue-test"}
			totals := []string{"dedupe_prompt_tokens: 200", "dedupe_completion_tokens: 20", "resolution_prompt_tokens: 300", "resolution_completion_tokens: 30", "prompt_tokens: 600", "completion_tokens: 60"}
			if empty {
				wantModels = []string{"scan-test"}
				totals = []string{"dedupe_prompt_tokens: 0", "dedupe_completion_tokens: 0", "resolution_prompt_tokens: 0", "resolution_completion_tokens: 0", "prompt_tokens: 100", "completion_tokens: 10"}
			}
			if !slices.Equal(models, wantModels) {
				t.Fatalf("requests = %v; want %v", models, wantModels)
			}
			report, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			wants := append(totals, `model: "openai/issue-test (scan: openai/scan-test)"`, `scan_model: "openai/scan-test"`, `issue_model: "openai/issue-test"`, `reasoning_effort: "high"`, "detection_prompt_tokens: 100", "detection_completion_tokens: 10", "_Analysis by openai/issue-test (scan: openai/scan-test)_")
			for _, want := range wants {
				if !strings.Contains("\n"+string(report), "\n"+want+"\n") {
					t.Errorf("report missing %q: %s", want, report)
				}
			}
		})
	}
}
