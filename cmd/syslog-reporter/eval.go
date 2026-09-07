package main

// The eval command (ait srg-5CQZn): compare provider/model combinations by
// running the real noise filter and LLM stages (detection -> dedupe ->
// resolution) through the production seam over a small file of log lines,
// and writing the resulting report fragment with timing and token metadata.
// Comparing configurations uses separate invocations; there
// is deliberately no multi-model orchestration and no computed cost (a
// price table goes stale the week it is written).

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"io"
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
usage: syslog-reporter eval [--model <provider/model>] [--scan-model <provider/model>]
       [--issue-model <provider/model>] [--input <file>] [--out <file>]
flags:
`

const evalHelpEnv = `The default --input is a bundled sample of fictional log lines, so a bare
'eval' needs no input setup. Compare configurations with separate invocations.
Model precedence: --scan-model / --issue-model > SYSLOG_LOGSCAN_MODEL /
SYSLOG_ISSUE_MODEL > --model > SYSLOG_DEFAULT_MODEL > built-in default.
Stage environment variables override --model; set both stage flags to the
same model to force a single-model comparison. Anomaly explanations are
not evaluated. No cost is computed: multiply the token counts by your
own price sheet. Environment: the provider keys, SYSLOG_REASONING_EFFORT and
SYSLOG_REDACT apply exactly as in 'run' (OPENAI_API_KEY, ANTHROPIC_API_KEY,
AZURE_OPENAI_ENDPOINT + _API_KEY), as do the filter's SYSLOG_BLANKET_IGNORE
and SYSLOG_KNOWN_KNOWNS.
`

type evalConfig struct {
	scanModel, issueModel string
	input, outPath        string
}

func parseEvalFlags(args []string, output io.Writer) (evalConfig, error) {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(output)
	setUsage(fs, evalHelpIntro, evalHelpEnv)
	model := fs.String("model", getenvDefault("SYSLOG_DEFAULT_MODEL", "openai/gpt-5.6-luna"), "Fallback model; stage environment variables override it.")
	scan := fs.String("scan-model", os.Getenv("SYSLOG_LOGSCAN_MODEL"), "Detection and deduplication model (default: SYSLOG_LOGSCAN_MODEL, then --model).")
	issue := fs.String("issue-model", os.Getenv("SYSLOG_ISSUE_MODEL"), "Resolution model (default: SYSLOG_ISSUE_MODEL, then --model).")
	input := fs.String("input", "", "File of log lines to analyse, raw or filtered (default: the bundled sample).")
	out := fs.String("out", "", "Output path (default: eval_<models>_<timestamp>.md).")
	if err := fs.Parse(args); err != nil {
		return evalConfig{}, err
	}
	if fs.NArg() > 0 {
		return evalConfig{}, fmt.Errorf("unrecognised extra arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *scan == "" {
		*scan = *model
	}
	if *issue == "" {
		*issue = *model
	}
	return evalConfig{scanModel: *scan, issueModel: *issue, input: *input, outPath: *out}, nil
}

func runEval(args []string) {
	cfg, err := parseEvalFlags(args, os.Stderr)
	if err == flag.ErrHelp {
		return
	}
	if err != nil {
		fatal("%v", err)
	}
	for _, model := range []string{cfg.scanModel, cfg.issueModel} {
		if err := llm.CheckCredentials(model); err != nil {
			fatal("%v", err)
		}
	}
	modelLabel := reporter.ModelLabel(cfg.scanModel, cfg.issueModel)
	if err := llm.CheckReasoningEffort(); err != nil {
		fatal("%v", err)
	}
	log := &logger{}
	llm.SetLogger(log.Warn)

	lines := strings.Split(strings.TrimRight(evalFixture, "\n"), "\n")
	source := "bundled fixture"
	if cfg.input != "" {
		f, err := os.Open(cfg.input)
		if err != nil {
			fatal("%v", err)
		}
		lines, err = readLines(f)
		f.Close()
		if err != nil {
			fatal("reading %s: %v", cfg.input, err)
		}
		source = cfg.input
	}

	path := cfg.outPath
	started := time.Now()
	if path == "" {
		name := cfg.issueModel
		if cfg.scanModel != cfg.issueModel {
			name += "_scan_" + cfg.scanModel
		}
		path = evalOutputName(name, started)
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
	logIndex := reporter.NewLogIndex(lines) // raw lines, for context windows
	lines = reporter.NewLogFilter(lines, knowns).Run()

	log.Info("Evaluating %s over %d filtered lines (%s, %d before filtering)",
		modelLabel, len(lines), source, rawCount)
	log.Info("Reasoning effort: %s", llm.ReasoningEffort())
	llm.ResetUsage()
	ctx := context.Background()

	t := time.Now()
	// eval reads plain text, so there is no per-host OS inventory to pass.
	issues, err := reporter.NewIssueDetector(lines, cfg.scanModel, nil).Run(ctx)
	if err != nil {
		fatal("detecting issues: %v", err)
	}
	detectDur := time.Since(t)
	detectUsage := llm.TotalUsage()
	log.Info("Detection: %d issues in %s", len(issues.Issues), detectDur.Round(time.Millisecond))

	t = time.Now()
	issues, err = reporter.NewIssueDeduplicator(issues, cfg.scanModel).Run(ctx)
	if err != nil {
		fatal("consolidating issues: %v", err)
	}
	dedupeDur := time.Since(t)
	afterDedupe := llm.TotalUsage()
	log.Info("Dedupe: %d issues in %s", len(issues.Issues), dedupeDur.Round(time.Millisecond))

	t = time.Now()
	contexts := logIndex.ContextsFor(issues)
	resolutions, err := reporter.NewResolutionAgent(issues, contexts, cfg.issueModel, nil).Run(ctx)
	if err != nil {
		fatal("resolving issues: %v", err)
	}
	resolveDur := time.Since(t)
	log.Info("Resolutions: %d in %s", len(resolutions.Resolutions), resolveDur.Round(time.Millisecond))

	meta := evalMeta{
		Model:           modelLabel,
		ScanModel:       cfg.scanModel,
		IssueModel:      cfg.issueModel,
		ReasoningEffort: llm.ReasoningEffort(),
		DetectUsage:     detectUsage,
		DedupeUsage:     usageDifference(afterDedupe, detectUsage),
		ResolveUsage:    usageDifference(llm.TotalUsage(), afterDedupe),
		Generated:       started,
		InputLines:      rawCount,
		FilteredLines:   len(lines),
		Detect:          detectDur,
		Dedupe:          dedupeDur,
		Resolve:         resolveDur,
		Total:           time.Since(started),
		Usage:           llm.TotalUsage(),
	}
	content := evalFrontMatter(meta) + "\n" + reporter.EvalFragment(issues, resolutions, modelLabel)
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

func usageDifference(after, before llm.Usage) llm.Usage {
	return llm.Usage{PromptTokens: after.PromptTokens - before.PromptTokens, CompletionTokens: after.CompletionTokens - before.CompletionTokens}
}

type evalMeta struct {
	ScanModel, IssueModel, ReasoningEffort string
	DetectUsage, DedupeUsage, ResolveUsage llm.Usage
	Model                                  string
	Generated                              time.Time
	InputLines                             int
	FilteredLines                          int
	Detect                                 time.Duration
	Dedupe                                 time.Duration
	Resolve                                time.Duration
	Total                                  time.Duration
	Usage                                  llm.Usage
}

// evalFrontMatter renders the metadata block: what ran, how long each stage
// took, and what it cost in tokens (never in money).
func evalFrontMatter(m evalMeta) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "model: %q\n", m.Model)
	fmt.Fprintf(&b, "scan_model: %q\nissue_model: %q\nreasoning_effort: %q\n", m.ScanModel, m.IssueModel, m.ReasoningEffort)
	for _, stage := range []struct {
		name  string
		usage llm.Usage
	}{
		{"detection", m.DetectUsage}, {"dedupe", m.DedupeUsage}, {"resolution", m.ResolveUsage},
	} {
		fmt.Fprintf(&b, "%s_prompt_tokens: %d\n%s_completion_tokens: %d\n", stage.name, stage.usage.PromptTokens, stage.name, stage.usage.CompletionTokens)
	}
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
