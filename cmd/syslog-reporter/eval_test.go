package main

// Eval command tests (ait srg-5CQZn): filename sanitising and front-matter
// rendering are unit-tested; the LLM round-trip is validated live, not
// mocked (repo convention).

import (
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

func TestEvalOutputNameSanitisesTheModelString(t *testing.T) {
	when := time.Date(2026, 8, 29, 15, 12, 3, 0, time.UTC)
	got := evalOutputName("azure/gpt-4o:live", when)
	want := "eval_azure_gpt-4o_live_2026-08-29_151203.md"
	if got != want {
		t.Errorf("evalOutputName = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "/:") {
		t.Errorf("output name still contains / or : - %q", got)
	}
}

func TestEvalFrontMatterRendersEveryField(t *testing.T) {
	meta := evalMeta{
		Model:     "openai/gpt-4o-mini",
		Generated: time.Date(2026, 8, 29, 15, 12, 3, 0, time.UTC),
		Detect:    1500 * time.Millisecond,
		Dedupe:    250 * time.Millisecond,
		Resolve:   2 * time.Second,
		Total:     3750 * time.Millisecond,
		Usage:     llm.Usage{PromptTokens: 1234, CompletionTokens: 567},
	}
	got := evalFrontMatter(meta)
	if !strings.HasPrefix(got, "---\n") || !strings.HasSuffix(got, "---\n") {
		t.Errorf("front-matter not fenced with ---: %q", got)
	}
	for _, want := range []string{
		"model: openai/gpt-4o-mini",
		"generated: 2026-08-29T15:12:03Z",
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
