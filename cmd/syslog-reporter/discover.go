package main

// knowns discover: the Jev-scored noise finder (ait srg-M3Yny.9, ant ADR
// srg-uHwCr, evaluation in srg-FGSKN). Templates a window of the dumps
// daily-run.sh keeps, asks Jev once per message shape whether an admin
// would want to see it, and adds the confidently routine, recurring
// shapes to known_knowns with source jev. Auto-add is the default;
// --preview shows the candidates first and asks y/n on a terminal, and on
// anything that is not a terminal (cron, an agent) prints and adds
// nothing. The admin reviews the result with 'knowns hits'.

import (
	"bufio"
	"context"
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
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
	"golang.org/x/term"
)

// attentionQuestion is the one question, unchanged from the evaluation
// (srg-FGSKN) so the thresholds measured there still apply.
var attentionQuestion = map[string]jev.Question{"attention": {
	Type: "noul",
	Instructions: map[string]any{
		"question": "Should this system log message be brought to a system administrator's attention?",
		"inspect":  "`log.message`",
		"focus":    "Judge whether an admin would want to know or act, given how many lines, hosts and days produced it.",
	},
	Criteria: map[string]any{
		"true": map[string]any{
			"what": "Indicates a failure, error, security event, resource problem, hardware fault or misconfiguration an administrator should act on or know about",
			"examples": []string{
				"kernel: EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0",
				"sshd: Failed password for invalid user <user> from <ip> port <n> ssh2",
				"systemd: <fqdn>.service: Main process exited, code=exited, status=1/FAILURE",
			},
		},
		"false": map[string]any{
			"what":    "Routine operational chatter: successful or expected events, informational start/stop messages, scheduled jobs running normally, debug output",
			"not_for": "A message that merely contains the word error or warning but describes normal behaviour",
			"examples": []string{
				"systemd: Started Daily apt download activities.",
				"sshd: Accepted publickey for <user> from <ip> port <n> ssh2",
				"CRON: (<user>) CMD (/usr/lib/<fqdn> --cron)",
			},
		},
	},
}}

// shape is one message template's tally across the window.
type shape struct {
	Program, Template string
	Example           string // one 'program[pid]: message' this shape came from
	Lines             int
	Hosts             map[string]bool
	Days              map[string]bool
	Score             float64
}

func (s *shape) key() string { return s.Program + "\x00" + s.Template }

// scorer asks for the attention score of one shape and reports the tokens
// it cost; a type so tests can stand in for Jev.
type scorer func(ctx context.Context, s *shape) (float64, jev.Usage, error)

func runKnownsDiscover(args []string) {
	fs, dbPath := knownsFlagSet("knowns discover")
	days := fs.Int("days", 30, "Days of dumps to read, ending yesterday")
	dumpDir := fs.String("dump-dir", defaultDumpDir(), "Where daily-run.sh keeps syslog-YYYY-MM-DD.ndjson.gz (default: $WORK_DIR/dumps)")
	threshold := fs.Float64("threshold", 0.1, "Add a shape only when its attention score is below this")
	minDays := fs.Int("min-days", 3, "Add a shape only when it appeared on at least this many days")
	minLines := fs.Int("min-lines", 1, "Add a shape only when it produced at least this many lines in the window")
	workers := fs.Int("workers", 8, "Parallel Jev calls")
	preview := fs.Bool("preview", false, "Print the candidates and ask before adding (prints only when stdin is not a terminal)")
	debug := fs.Bool("debug", false, "Log each shape's score")
	if extra := cli.ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		fatal("knowns discover takes flags only (got %s)", strings.Join(extra, " "))
	}
	if *days < 1 || *workers < 1 || *threshold <= 0 || *threshold > 1 {
		fatal("--days and --workers must be at least 1; --threshold must be in (0, 1]")
	}
	if err := jev.CheckCredentials(); err != nil {
		fatal("%v", err)
	}
	log := &logger{debugEnabled: *debug}
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
	usage, elapsed, err := scoreShapes(ctx, shapes, *workers, jevScorer(log))
	if err != nil {
		fatal("%v", err)
	}
	log.Info("Jev: %d shapes scored in %s, %d input tokens, %d output tokens",
		len(shapes), elapsed.Round(time.Second), usage.InputTokens, usage.OutputTokens)

	candidates := selectCandidates(shapes, *threshold, *minDays, *minLines)
	inputs, err := candidateInputs(candidates)
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
	fmt.Fprintf(os.Stderr, "%d added; review with 'syslog-reporter knowns hits <dump> --source jev'\n", len(added))
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
			s.Example = rest
			shapes[s.key()] = s
		}
		s.Lines++
		s.Hosts[strings.Fields(line)[3]] = true
		s.Days[day] = true
	}
	return n
}

// jevScorer asks the real API. The state carries the counts so the model
// judges "this shape, this often, this widely", as in the evaluation.
func jevScorer(log *logger) scorer {
	return func(ctx context.Context, s *shape) (float64, jev.Usage, error) {
		state := map[string]any{"log": map[string]any{
			"program": s.Program, "message": s.Template,
			"lines_seen": s.Lines, "hosts_seen": len(s.Hosts), "days_seen": len(s.Days),
		}}
		resp, err := jev.Ask(ctx, state, attentionQuestion)
		if err != nil {
			return 0, jev.Usage{}, err
		}
		score, err := jev.Noul(resp, "attention")
		if err != nil {
			return 0, jev.Usage{}, err
		}
		log.Debug("%.2f %5d lines %3d hosts %2d days  %s: %s", score, s.Lines, len(s.Hosts), len(s.Days), s.Program, s.Template)
		return score, resp.Usage, nil
	}
}

// scoreShapes scores every shape with workers in parallel; the first
// error stops the rest.
func scoreShapes(ctx context.Context, shapes map[string]*shape, workers int, score scorer) (jev.Usage, time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan *shape)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		usage    jev.Usage
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
					usage.InputTokens += u.InputTokens
					usage.OutputTokens += u.OutputTokens
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

// candidateInputs turns candidates into store inputs, checking that each
// generated regex matches the line it came from: one that does not is a
// templating bug, not something to write into the table.
func candidateInputs(candidates []*shape) ([]reporter.KnownEntryInput, error) {
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
			Reason: fmt.Sprintf("jev: score %.2f, %d lines on %d hosts over %d days", s.Score, s.Lines, len(s.Hosts), len(s.Days)),
			Added:  time.Now(), Source: reporter.KnownSourceJev,
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

// confirm asks a y/n question on a terminal; anything but y or yes is no.
func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	answer, _ := bufio.NewReader(in).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}
