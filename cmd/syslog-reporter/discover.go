package main

// knowns discover: the scored noise finder (ait srg-M3Yny.9, ant ADR
// srg-uHwCr, evaluation in srg-FGSKN). Templates a window of the dumps
// daily keeps, asks a scorer once per message shape whether an admin
// would want to see it, and adds the confidently routine, recurring
// shapes to known_knowns. The scorer is Jev (source jev) by default, or
// the Azure OpenAI Decisions API with --decisions-model (source
// decisions, ait srg-uh92Y). Auto-add is the default;
// --preview shows the candidates first and asks y/n on a terminal, and on
// anything that is not a terminal (cron, an agent) prints and adds
// nothing. The admin reviews the result with 'knowns hits'.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/jev"
	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
	"golang.org/x/term"
)

// The attention question's parts, shared by both scorers. Jev takes them
// in its object form (attentionQuestion); the Decisions API takes one
// instructions string (attentionInstructions). The not_for sits on the
// yes side: a message is not worth attention merely for containing the
// word error. The evaluation (srg-FGSKN) had it on the no side, which
// says the opposite, so the 0.1 threshold measured there predates the
// fix; re-measure with --preview.
const (
	attentionAsk       = "Should this system log message be brought to a system administrator's attention?"
	attentionFocus     = "Judge whether an admin would want to know or act, given how many lines, hosts and days produced it."
	attentionYesWhat   = "Indicates a failure, error, security event, resource problem, hardware fault or misconfiguration an administrator should act on or know about"
	attentionNoWhat    = "Routine operational chatter: successful or expected events, informational start/stop messages, scheduled jobs running normally, debug output"
	attentionYesNotFor = "A message that merely contains the word error or warning but describes normal behaviour"
)

var (
	attentionYesExamples = []string{
		"kernel: EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0",
		"sshd: Failed password for invalid user <user> from <ip> port <n> ssh2",
		"systemd: <fqdn>.service: Main process exited, code=exited, status=1/FAILURE",
	}
	attentionNoExamples = []string{
		"systemd: Started Daily apt download activities.",
		"sshd: Accepted publickey for <user> from <ip> port <n> ssh2",
		"CRON: (<user>) CMD (/usr/lib/<fqdn> --cron)",
	}
)

var attentionQuestion = map[string]jev.Question{"attention": {
	Type: "noul",
	Instructions: map[string]any{
		"question": attentionAsk,
		"inspect":  "`log.message`",
		"focus":    attentionFocus,
	},
	Criteria: map[string]any{
		"true":  map[string]any{"what": attentionYesWhat, "not_for": attentionYesNotFor, "examples": attentionYesExamples},
		"false": map[string]any{"what": attentionNoWhat, "examples": attentionNoExamples},
	},
}}

// attentionInstructions is the same question as prose.
var attentionInstructions = attentionAsk + " Inspect log.message in the input; the input also gives how many lines, hosts and days produced it. " +
	attentionFocus + "\n\nAnswer yes when it: " + attentionYesWhat + ". This does not cover: " + attentionYesNotFor + ". For example:\n- " + strings.Join(attentionYesExamples, "\n- ") +
	"\n\nAnswer no when it is: " + attentionNoWhat + ". For example:\n- " + strings.Join(attentionNoExamples, "\n- ")

// Defaults that differ by scorer. Jev's come from the evaluation
// (srg-FGSKN). Decisions scores are far more extreme (1,356 shapes under
// 0.05 against Jev's 226 on the 2026-09-08 dump), so 0.2 mutes about what
// Jev mutes at 0.2, the owner's choice to lean towards filtering
// (2026-11-04); 8 parallel calls were throttled on the shared Azure
// deployment, 2 were not. The 10M cap is there for runaways, not as a
// budget (owner, 2026-11-04): three days of local dumps already came to
// 3,846 distinct shapes, about 1.85M tokens, so a 30-day window would
// stall under 2M every month.
const (
	decisionsMaxPromptTokens = 10_000_000
	jevThreshold             = 0.1
	jevWorkers               = 8
	decisionsThreshold       = 0.2
	decisionsWorkers         = 2
)

// shape is one message template's tally across the window.
type shape struct {
	Program, Template string
	Example           string // one 'program[pid]: message' this shape came from
	ExampleHost       string // the host Example came from
	Lines             int
	Hosts             map[string]bool
	Days              map[string]bool
	Score             float64
}

func (s *shape) key() string { return s.Program + "\x00" + s.Template }

// scorer asks for the attention score of one shape and reports the tokens
// it cost; a type so tests can stand in for Jev and the Decisions API.
type scorer func(ctx context.Context, s *shape) (float64, llm.Usage, error)

func runKnownsDiscover(args []string) {
	fs, dbPath := knownsFlagSet("knowns discover")
	days := fs.Int("days", 30, "Days of dumps to read, ending yesterday")
	dumpDir := fs.String("dump-dir", defaultDumpDir(), "Where daily keeps syslog-YYYY-MM-DD.ndjson.gz (default: $WORK_DIR/dumps)")
	threshold := fs.Float64("threshold", jevThreshold, "Add a shape only when its attention score is below this (default 0.1 on Jev, 0.2 with --decisions-model)")
	minDays := fs.Int("min-days", 3, "Add a shape only when it appeared on at least this many days")
	minLines := fs.Int("min-lines", 1, "Add a shape only when it produced at least this many lines in the window")
	workers := fs.Int("workers", jevWorkers, "Parallel scoring calls (default 8 on Jev, 2 with --decisions-model)")
	maxPromptTokens := fs.Int64("max-prompt-tokens", decisionsMaxPromptTokens,
		"With --decisions-model: most prompt tokens this run may send; past it the run stops and adds nothing (0 = no cap). Separate from the daily run's budget")
	decisionsModel := fs.String("decisions-model", os.Getenv("SYSLOG_DECISIONS_MODEL"),
		"Score with the Azure OpenAI Decisions API on this azure/<deployment> (a gpt-6-luna deployment) instead of Jev")
	preview := fs.Bool("preview", false, "Print the candidates and ask before adding (prints only when stdin is not a terminal)")
	debug := fs.Bool("debug", false, "Log each shape's score")
	if extra := cli.ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		fatal("knowns discover takes flags only (got %s)", strings.Join(extra, " "))
	}
	log := &logger{debugEnabled: *debug}
	backend, source, score := "Jev", reporter.KnownSourceJev, jevScorer(log)
	if *decisionsModel != "" {
		if err := llm.CheckDecisionsModel(*decisionsModel); err != nil {
			fatal("%v", err)
		}
		if !flagSet(fs, "threshold") {
			*threshold = decisionsThreshold
		}
		if !flagSet(fs, "workers") {
			*workers = decisionsWorkers
		}
		// Its own cap, not the daily run's: llm_spend is one row a day that
		// run reads at startup, so spend recorded there would leave that
		// day's report degraded. Nothing is recorded; the cap is per run.
		llm.SetBudget(*maxPromptTokens, 0, nil)
		llm.SetLogger(log.Warn)
		llm.SetDebugLogger(log.Debug)
		backend, source, score = *decisionsModel, reporter.KnownSourceDecisions, decisionsScorer(log, *decisionsModel)
	} else if err := jev.CheckCredentials(); err != nil {
		fatal("%v", err)
	}
	if *days < 1 || *workers < 1 || *threshold <= 0 || *threshold > 1 {
		fatal("--days and --workers must be at least 1; --threshold must be in (0, 1]")
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()

	yesterday := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	found, missing := selectDumps(*dumpDir, yesterday, *days)
	for _, day := range missing {
		log.Info("No dump for %s in %s; skipping", day, *dumpDir)
	}
	if len(found) == 0 {
		fatal("no syslog-YYYY-MM-DD.ndjson.gz dumps for the last %d days in %s", *days, *dumpDir)
	}

	shapes := map[string]*shape{}
	for _, d := range found {
		knowns, err := lib.LoadKnownKnowns(d.day)
		if err != nil {
			fatal("%v", err)
		}
		lines, _, _, err := readLogSource(d.path, true)
		if err != nil {
			fatal("%v", err)
		}
		survivors := reporter.NewLogFilter(lines, knowns).Run()
		n := accumulate(shapes, survivors, d.day.Format("2006-01-02"))
		log.Info("%s: %d lines after the filter, %d shapes so far", filepath.Base(d.path), n, len(shapes))
	}

	ctx := context.Background()
	usage, elapsed, err := scoreShapes(ctx, shapes, *workers, score)
	if errors.Is(err, llm.ErrBudget) {
		// Unscored shapes sit at 0, which reads as "routine", so a partial
		// run must never add anything.
		fatal("stopped at --max-prompt-tokens %d after %d prompt tokens; nothing added. Raise it or use a smaller --days", *maxPromptTokens, usage.PromptTokens)
	}
	if err != nil {
		fatal("%v", err)
	}
	log.Info("%s: %d shapes scored in %s, %d input tokens, %d output tokens",
		backend, len(shapes), elapsed.Round(time.Second), usage.PromptTokens, usage.CompletionTokens)

	candidates := selectCandidates(shapes, *threshold, *minDays, *minLines)
	inputs, err := candidateInputs(candidates, source)
	if err != nil {
		fatal("%v", err)
	}
	if len(inputs) == 0 {
		fmt.Println("no shapes met the thresholds; nothing to add")
		return
	}
	if *preview {
		printCandidates(os.Stdout, candidates, inputs)
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stderr, "%d candidates printed; stdin is not a terminal, nothing added\n", len(inputs))
			return
		}
		if !confirm(os.Stdin, os.Stdout, fmt.Sprintf("Add %d entries to known_knowns (y/n)? ", len(inputs))) {
			fmt.Println("nothing added")
			return
		}
	}
	added, err := lib.AddKnownEntries(inputs)
	if err != nil {
		fatal("%v", err)
	}
	for _, e := range added {
		fmt.Printf("known-known %d added: %s\n", e.ID, describeKnown(e))
	}
	fmt.Fprintf(os.Stderr, "%d added; review with 'syslog-reporter knowns hits <dump> --source %s'\n", len(added), source)
}

func defaultDumpDir() string {
	return filepath.Join(getenvDefault("WORK_DIR", "/var/lib/syslog-reporter"), "dumps")
}

type dumpFile struct {
	day  time.Time
	path string
}

// selectDumps returns the dated dump files present for the days days
// ending on end, oldest first, and the dates with no file.
func selectDumps(dir string, end time.Time, days int) (found []dumpFile, missing []string) {
	for i := days - 1; i >= 0; i-- {
		day := end.AddDate(0, 0, -i)
		path := filepath.Join(dir, "syslog-"+day.Format("2006-01-02")+".ndjson.gz")
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			missing = append(missing, day.Format("2006-01-02"))
			continue
		}
		found = append(found, dumpFile{day: day, path: path})
	}
	return found, missing
}

// accumulate folds one day's surviving lines into shapes and returns how
// many lines templated.
func accumulate(shapes map[string]*shape, lines []string, day string) int {
	n := 0
	for _, line := range lines {
		program, template, rest, ok := reporter.Template(line)
		if !ok {
			continue
		}
		n++
		s := &shape{Program: program, Template: template}
		if have, ok := shapes[s.key()]; ok {
			s = have
		} else {
			s.Hosts, s.Days = map[string]bool{}, map[string]bool{}
			s.Example, s.ExampleHost = rest, strings.Fields(line)[3]
			shapes[s.key()] = s
		}
		s.Lines++
		s.Hosts[strings.Fields(line)[3]] = true
		s.Days[day] = true
	}
	return n
}

// shapeState is what a scorer is shown about one shape: the counts ride
// along so the model judges "this shape, this often, this widely", as in
// the evaluation.
func shapeState(s *shape) map[string]any {
	return map[string]any{"log": map[string]any{
		"program": s.Program, "message": s.Template,
		"lines_seen": s.Lines, "hosts_seen": len(s.Hosts), "days_seen": len(s.Days),
	}}
}

func logScore(log *logger, score float64, s *shape) {
	log.Debug("%.2f %5d lines %3d hosts %2d days  %s: %s", score, s.Lines, len(s.Hosts), len(s.Days), s.Program, s.Template)
}

// jevScorer asks TypeSafe's Jev.
func jevScorer(log *logger) scorer {
	return func(ctx context.Context, s *shape) (float64, llm.Usage, error) {
		resp, err := jev.Ask(ctx, shapeState(s), attentionQuestion)
		if err != nil {
			return 0, llm.Usage{}, err
		}
		score, err := jev.Noul(resp, "attention")
		if err != nil {
			return 0, llm.Usage{}, err
		}
		logScore(log, score, s)
		return score, llm.Usage{PromptTokens: int64(resp.Usage.InputTokens), CompletionTokens: int64(resp.Usage.OutputTokens)}, nil
	}
}

// decisionsScorer asks the Azure OpenAI Decisions API, with the same
// state (as JSON text) and the question as prose. A refused shape scores
// 1, so it can never become a candidate: a refusal is not a "routine".
func decisionsScorer(log *logger, model string) scorer {
	return func(ctx context.Context, s *shape) (float64, llm.Usage, error) {
		input, err := json.Marshal(shapeState(s))
		if err != nil {
			return 0, llm.Usage{}, err
		}
		score, usage, err := llm.Predicate(ctx, model, string(input), attentionInstructions)
		if errors.Is(err, llm.ErrRefused) {
			log.Info("%s refused to score %s: %s; kept visible", model, s.Program, s.Template)
			return 1, usage, nil
		}
		if err != nil {
			return 0, llm.Usage{}, err
		}
		logScore(log, score, s)
		return score, usage, nil
	}
}

// scoreShapes scores every shape with workers in parallel; the first
// error stops the rest.
func scoreShapes(ctx context.Context, shapes map[string]*shape, workers int, score scorer) (llm.Usage, time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan *shape)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		usage    llm.Usage
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range work {
				v, u, err := score(ctx, s)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
						cancel()
					}
				} else {
					s.Score = v
					usage.PromptTokens += u.PromptTokens
					usage.CompletionTokens += u.CompletionTokens
				}
				mu.Unlock()
			}
		}()
	}
	for _, s := range shapes {
		select {
		case work <- s:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	return usage, time.Since(start), firstErr
}

// selectCandidates applies the thresholds and orders the result by lines
// descending, then program, then template, so output is deterministic.
func selectCandidates(shapes map[string]*shape, threshold float64, minDays, minLines int) []*shape {
	var out []*shape
	for _, s := range shapes {
		if s.Score < threshold && len(s.Days) >= minDays && s.Lines >= minLines {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Lines != out[j].Lines {
			return out[i].Lines > out[j].Lines
		}
		if out[i].Program != out[j].Program {
			return out[i].Program < out[j].Program
		}
		return out[i].Template < out[j].Template
	})
	return out
}

// candidateInputs turns candidates into store inputs with the scorer's
// source, checking that each generated regex matches the line it came
// from: one that does not is a templating bug, not something to write
// into the table.
func candidateInputs(candidates []*shape, source string) ([]reporter.KnownEntryInput, error) {
	inputs := make([]reporter.KnownEntryInput, 0, len(candidates))
	for _, s := range candidates {
		match := reporter.TemplateRegex(s.Program, s.Template)
		re, err := reporter.CompileLinePattern(match)
		if err != nil {
			return nil, fmt.Errorf("generated regex for %s shape does not compile: %v", s.Program, err)
		}
		if !re.MatchString(s.Example) {
			return nil, fmt.Errorf("generated regex %q does not match its own example line for program %s", match, s.Program)
		}
		inputs = append(inputs, reporter.KnownEntryInput{
			Host: "*", Match: match,
			Reason: fmt.Sprintf("%s: score %.2f, %d lines on %d hosts over %d days", source, s.Score, s.Lines, len(s.Hosts), len(s.Days)),
			Added:  time.Now(), Source: source,
		})
	}
	return inputs, nil
}

func printCandidates(w io.Writer, candidates []*shape, inputs []reporter.KnownEntryInput) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCORE\tLINES\tHOSTS\tDAYS\tPROGRAM\tTEMPLATE")
	for _, s := range candidates {
		fmt.Fprintf(tw, "%.2f\t%d\t%d\t%d\t%s\t%s\n", s.Score, s.Lines, len(s.Hosts), len(s.Days), s.Program, s.Template)
	}
	tw.Flush()
	fmt.Fprintln(w)
	for i, in := range inputs {
		fmt.Fprintf(w, "%d. %s\n", i+1, in.Match)
	}
}

// flagSet reports whether name was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// confirm asks a y/n question on a terminal; anything but y or yes is no.
func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	answer, _ := bufio.NewReader(in).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}
