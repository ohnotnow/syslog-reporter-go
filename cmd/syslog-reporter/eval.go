package main

// The eval command (ait srg-5CQZn): compare provider/model combinations by
// running the real noise filter and LLM stages (detection -> dedupe ->
// resolution) through the production seam over a small file of log lines,
// and writing the resulting report fragment with timing and token metadata.
// Comparing several models is a shell loop over --model invocations; there
// is deliberately no multi-model orchestration and no computed cost (a
// price table goes stale the week it is written).

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// evalfixture.txt is a canned set of filtered-style log lines (fictional
// hostnames only) so a bare `eval --model X` is zero-setup. It is .txt
// rather than .log because the repo gitignores *.log (real dumps), and an
// ignored embed file would vanish from fresh clones and break the build.
//
//go:embed evalfixture.txt
var evalFixture string

const evalHelpIntro = `Compare provider/model combinations: run the noise filter then the LLM
stages (detection, dedupe, resolution) over a small log sample and write a
report fragment with per-stage timings and token counts in its front-matter.
usage: syslog-reporter eval --model <provider/model> [--input <file>] [--out <file>]
flags:
`

const evalHelpEnv = `The default --input is a bundled sample of fictional log lines, so a bare
'eval --model X' needs no setup. Compare models with a shell loop over
--model invocations. No cost is computed: multiply the token counts by your
own price sheet. Environment: the provider keys, SYSLOG_REASONING_EFFORT and
SYSLOG_REDACT apply exactly as in 'run' (OPENAI_API_KEY, ANTHROPIC_API_KEY,
AZURE_OPENAI_ENDPOINT + _API_KEY), as do the filter's SYSLOG_BLANKET_IGNORE
and SYSLOG_KNOWN_KNOWNS.
`

func runEval(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	setUsage(fs, evalHelpIntro, evalHelpEnv)
	model := fs.String("model", "", "Model to evaluate (litellm format, e.g. openai/gpt-5.6-luna). Required.")
	input := fs.String("input", "", "File of log lines to analyse, raw or filtered (default: the bundled sample).")
	outPath := fs.String("out", "", "Output path (default eval_<model>_<timestamp>.md).")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fatal("unrecognised extra arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *model == "" {
		fatal("eval needs --model (litellm format, e.g. openai/gpt-5.6-luna)")
	}
	if err := llm.CheckCredentials(*model); err != nil {
		fatal("%v", err)
	}
	log := &logger{}
	llm.SetLogger(log.Warn)

	lines := strings.Split(strings.TrimRight(evalFixture, "\n"), "\n")
	source := "bundled fixture"
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fatal("%v", err)
		}
		lines, err = readLines(f)
		f.Close()
		if err != nil {
			fatal("reading %s: %v", *input, err)
		}
		source = *input
	}

	path := *outPath
	started := time.Now()
	if path == "" {
		path = evalOutputName(*model, started)
	}

	// The noise filter runs first, exactly as in a real run: an unfiltered
	// day fed to the model by accident is an eye-watering bill, and a fair
	// model comparison wants the input production would actually send
	// (owner decision 2026-08-29). Known-knowns expiry is judged against
	// the wall clock; eval input has no slice date.
	knowns, err := reporter.LoadKnownKnowns(
		getenvDefault("SYSLOG_KNOWN_KNOWNS", "known_knowns.toml"), time.Now())
	if err != nil {
		fatal("%v", err)
	}
	rawCount := len(lines)
	lines = reporter.NewLogFilter(lines, knowns).Run()

	log.Info("Evaluating %s over %d filtered lines (%s, %d before filtering)",
		*model, len(lines), source, rawCount)
	llm.ResetUsage()
	ctx := context.Background()

	t := time.Now()
	// eval reads plain text, so there is no per-host OS inventory to pass.
	issues, err := reporter.NewIssueDetector(lines, *model, nil).Run(ctx)
	if err != nil {
		fatal("detecting issues: %v", err)
	}
	detectDur := time.Since(t)
	log.Info("Detection: %d issues in %s", len(issues.Issues), detectDur.Round(time.Millisecond))

	t = time.Now()
	issues, err = reporter.NewIssueDeduplicator(issues, *model).Run(ctx)
	if err != nil {
		fatal("consolidating issues: %v", err)
	}
	dedupeDur := time.Since(t)
	log.Info("Dedupe: %d issues in %s", len(issues.Issues), dedupeDur.Round(time.Millisecond))

	t = time.Now()
	resolutions, err := reporter.NewResolutionAgent(issues, *model, nil).Run(ctx)
	if err != nil {
		fatal("resolving issues: %v", err)
	}
	resolveDur := time.Since(t)
	log.Info("Resolutions: %d in %s", len(resolutions.Resolutions), resolveDur.Round(time.Millisecond))

	meta := evalMeta{
		Model:         *model,
		Generated:     started,
		InputLines:    rawCount,
		FilteredLines: len(lines),
		Detect:        detectDur,
		Dedupe:        dedupeDur,
		Resolve:       resolveDur,
		Total:         time.Since(started),
		Usage:         llm.TotalUsage(),
	}
	content := evalFrontMatter(meta) + "\n" + reporter.EvalFragment(issues, resolutions, *model)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		fatal("writing %s: %v", path, err)
	}
	log.Info("Wrote %s (total %s, %d prompt + %d completion tokens)",
		path, meta.Total.Round(time.Millisecond),
		meta.Usage.PromptTokens, meta.Usage.CompletionTokens)
}

// evalOutputName builds the default output filename: the model string with
// / and : flattened to _, plus a sortable timestamp.
func evalOutputName(model string, now time.Time) string {
	sanitised := strings.NewReplacer("/", "_", ":", "_").Replace(model)
	return fmt.Sprintf("eval_%s_%s.md", sanitised, now.Format("2006-01-02_150405"))
}

type evalMeta struct {
	Model         string
	Generated     time.Time
	InputLines    int
	FilteredLines int
	Detect        time.Duration
	Dedupe        time.Duration
	Resolve       time.Duration
	Total         time.Duration
	Usage         llm.Usage
}

// evalFrontMatter renders the metadata block: what ran, how long each stage
// took, and what it cost in tokens (never in money).
func evalFrontMatter(m evalMeta) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "model: %s\n", m.Model)
	fmt.Fprintf(&b, "generated: %s\n", m.Generated.Format(time.RFC3339))
	fmt.Fprintf(&b, "input_lines: %d\n", m.InputLines)
	fmt.Fprintf(&b, "filtered_lines: %d\n", m.FilteredLines)
	fmt.Fprintf(&b, "duration_detection: %s\n", m.Detect.Round(time.Millisecond))
	fmt.Fprintf(&b, "duration_dedupe: %s\n", m.Dedupe.Round(time.Millisecond))
	fmt.Fprintf(&b, "duration_resolution: %s\n", m.Resolve.Round(time.Millisecond))
	fmt.Fprintf(&b, "duration_total: %s\n", m.Total.Round(time.Millisecond))
	fmt.Fprintf(&b, "prompt_tokens: %d\n", m.Usage.PromptTokens)
	fmt.Fprintf(&b, "completion_tokens: %d\n", m.Usage.CompletionTokens)
	b.WriteString("---\n")
	return b.String()
}
