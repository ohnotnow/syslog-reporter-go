package reporter

// The trust-boundary framing in the embedded prompts is a security control
// (srg-so8ja.4): log-derived text is attacker-influenceable, so every LLM
// stage must be told it is quoted evidence, never instructions. These pins
// stop the framing silently vanishing in a later prompt edit.

import (
	"strings"
	"testing"
)

func TestPromptsCarryTrustBoundary(t *testing.T) {
	prompts := map[string]string{
		"issue_detection.tmpl":    issueDetectionTemplateRaw,
		"issue_dedupe.txt":        issueDedupePromptRaw,
		"anomaly_explanation.txt": anomalyExplanationPromptRaw,
		"resolution.tmpl":         resolutionTemplateRaw,
	}
	for name, text := range prompts {
		if !strings.Contains(text, "Trust boundary") {
			t.Errorf("%s: missing its Trust boundary block", name)
		}
		if !strings.Contains(text, "untrusted") {
			t.Errorf("%s: no longer describes its input as untrusted", name)
		}
	}
	// The paste-safety convention rides with the two command-writing stages.
	for _, name := range []string{"anomaly_explanation.txt", "resolution.tmpl"} {
		if !strings.Contains(prompts[name], "CHANGES STATE") {
			t.Errorf("%s: missing the CHANGES STATE rule", name)
		}
	}
}
