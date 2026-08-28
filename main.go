// syslog-reporter: a batch tool that turns a noisy org-wide rsyslog stream
// into a short, prioritised report for a sysadmin team. Go port of the
// Python syslog_reporter; this entry point mirrors main.py.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

// version is stamped by the release build via -ldflags "-X main.version=...".
var version = "dev"

type logger struct {
	debugEnabled bool
}

func (l *logger) log(level, format string, args ...any) {
	now := time.Now()
	fmt.Fprintf(os.Stderr, "%s,%03d - syslog-reporter - %s - %s\n",
		now.Format("2006-01-02 15:04:05"), now.Nanosecond()/1e6, level,
		fmt.Sprintf(format, args...))
}

func (l *logger) Info(format string, args ...any) { l.log("INFO", format, args...) }

func (l *logger) Debug(format string, args ...any) {
	if l.debugEnabled {
		l.log("DEBUG", format, args...)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "syslog-reporter: %s\n", fmt.Sprintf(format, args...))
	os.Exit(1)
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// readLines mimics Python's readlines(): every line keeps its trailing
// newline; a final line without one is kept as-is.
func readLines(r io.Reader) ([]string, error) {
	br := bufio.NewReaderSize(r, 1024*1024)
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			lines = append(lines, line)
		}
		if err == io.EOF {
			return lines, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func main() {
	// Like python-dotenv: pick up a .env beside the binary's working
	// directory without overriding variables already in the environment.
	_ = godotenv.Load()

	defaultModel := getenvDefault("SYSLOG_DEFAULT_MODEL", "openai/gpt-4o-mini")
	defaultDBPath := getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db")
	defaultKnownsPath := getenvDefault("SYSLOG_KNOWN_KNOWNS", "known_knowns.toml")
	keepDays, err := strconv.Atoi(getenvDefault("SYSLOG_DB_KEEP_DAYS", "90"))
	if err != nil {
		fatal("SYSLOG_DB_KEEP_DAYS must be an integer: %v", err)
	}

	fs := flag.NewFlagSet("syslog-reporter", flag.ExitOnError)
	model := fs.String("model", defaultModel, "Model to use (litellm format)")
	filePath := fs.String("file", "--", "Alternative way to pass the file; or -- for stdin")
	format := fs.String("format", "auto",
		"Input format: 'raw' is rsyslog text, 'ndjson' is an elk_dump.py dump "+
			"(.gz handled). 'auto' picks ndjson for *.ndjson / *.ndjson.gz paths, "+
			"raw otherwise (stdin is always raw).")
	debug := fs.Bool("debug", false, "Print extra debug information")
	sendEmail := fs.Bool("send-email", false, "Email the report to the recipients")
	recipients := fs.String("recipients", "", "Comma-separated list of email addresses to send the report to.")
	dateStr := fs.String("date", "",
		"ISO date (YYYY-MM-DD) the log slice covers, for the aggregate store. Defaults to yesterday.")
	dbPath := fs.String("db", defaultDBPath,
		fmt.Sprintf("SQLite aggregate store path (default %s)", defaultDBPath))
	knownsPath := fs.String("known-knowns", defaultKnownsPath,
		fmt.Sprintf("TOML file of operator-acknowledged oddities to suppress "+
			"(default %s; missing file just means none).", defaultKnownsPath))
	noStore := fs.Bool("no-store", false,
		"Don't persist aggregates or run the history-based detectors (peer comparison still runs).")
	noLLM := fs.Bool("no-llm", false,
		"Skip every LLM stage (issue detection, dedupe, resolutions, anomaly "+
			"explanations) so the run costs nothing.")
	dumpFiltered := fs.Bool("dump-filtered", false,
		"Print the filtered log lines and exit (parity/debug tool).")
	showVersion := fs.Bool("version", false, "Print the version and exit.")

	// Python's argparse accepts flags after the positional logfile; Go's flag
	// package stops at the first non-flag argument, so re-parse until every
	// argument is consumed.
	args := os.Args[1:]
	var positionals []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		positionals = append(positionals, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(positionals) > 1 {
		fatal("unrecognised extra arguments: %s", strings.Join(positionals[1:], " "))
	}
	if *showVersion {
		fmt.Printf("syslog-reporter %s\n", version)
		return
	}

	// The positional path wins; fall back to --file; "--" (or nothing) means stdin.
	path := *filePath
	if len(positionals) == 1 {
		path = positionals[0]
	}
	if *format != "auto" && *format != "raw" && *format != "ndjson" {
		fatal("--format must be one of auto, raw, ndjson (got %q)", *format)
	}
	isNDJSON := *format == "ndjson" ||
		(*format == "auto" && (strings.HasSuffix(path, ".ndjson") || strings.HasSuffix(path, ".ndjson.gz")))

	var logDate time.Time
	if *dateStr != "" {
		parsed, err := time.Parse("2006-01-02", *dateStr)
		if err != nil {
			fatal("--date must be YYYY-MM-DD: %v", err)
		}
		logDate = parsed
	}

	var lines []string
	var hostOS map[string]string
	switch {
	case isNDJSON:
		if path == "--" {
			fatal("--format ndjson needs a file path, not stdin")
		}
		source, err := reporter.NewElkSource(path)
		if err != nil {
			fatal("%v", err)
		}
		lines, err = source.Run()
		if err != nil {
			fatal("%v", err)
		}
		if source.Skipped > 0 {
			fmt.Fprintf(os.Stderr, "warning: skipped %d NDJSON records with no timestamp or message\n", source.Skipped)
		}
		// Key the aggregates off the data itself rather than assuming the
		// dump is yesterday's; an explicit --date still wins.
		if logDate.IsZero() && source.LogDate != nil {
			logDate = *source.LogDate
		}
		hostOS = source.HostOS
	case path == "--":
		var err error
		lines, err = readLines(os.Stdin)
		if err != nil {
			fatal("reading stdin: %v", err)
		}
	default:
		f, err := os.Open(path)
		if err != nil {
			fatal("%v", err)
		}
		lines, err = readLines(f)
		f.Close()
		if err != nil {
			fatal("reading %s: %v", path, err)
		}
	}

	run(runConfig{
		lines:      lines,
		model:      *model,
		debug:      *debug,
		recipients: *recipients,
		sendEmail:  *sendEmail,
		logDate:    logDate,
		dbPath:     *dbPath,
		storeOn:    !*noStore,
		keepDays:   keepDays,
		llmOn:      !*noLLM,
		hostOS:     hostOS,
		knownsPath: *knownsPath,
		dumpOnly:   *dumpFiltered,
	})
}

type runConfig struct {
	lines      []string
	model      string
	debug      bool
	recipients string
	sendEmail  bool
	logDate    time.Time
	dbPath     string
	storeOn    bool
	keepDays   int
	llmOn      bool
	hostOS     map[string]string
	knownsPath string
	dumpOnly   bool
}

func run(cfg runConfig) {
	log := &logger{debugEnabled: cfg.debug}

	// The slice we're processing is yesterday's by default; the date keys
	// the persisted aggregates (NDJSON input overrides this from the data).
	logDate := cfg.logDate
	if logDate.IsZero() {
		now := time.Now()
		logDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	}
	log.Debug("Using model: %s", cfg.model)
	log.Debug("Original log file length: %d", len(cfg.lines))

	// Operator-acknowledged estate oddities ("that host always does that,
	// it's the microscope"): dropped from the issue path and muted on the
	// anomaly path, with a footer line in the report so suppression stays
	// visible. Expiry is judged against the slice date, so backfills of
	// historical days behave historically.
	knowns, err := reporter.LoadKnownKnowns(cfg.knownsPath, logDate)
	if err != nil {
		fatal("%v", err)
	}
	log.Info("Known knowns: %d active, %d expired (%s)",
		len(knowns.Active), len(knowns.Expired), cfg.knownsPath)

	log.Info("Filtering log file")
	logFilter := reporter.NewLogFilter(cfg.lines, knowns)
	log.Info("Blanket ignore: %d entries from SYSLOG_BLANKET_IGNORE", len(logFilter.BlanketIgnores))
	filteredLines := logFilter.Run()
	log.Debug("Filtered log file length: %d", len(filteredLines))

	if cfg.dumpOnly {
		out := bufio.NewWriter(os.Stdout)
		for _, line := range filteredLines {
			out.WriteString(line)
			if !strings.HasSuffix(line, "\n") {
				out.WriteByte('\n')
			}
		}
		out.Flush()
		return
	}

	ctx := context.Background()
	issues := &reporter.IssueList{}
	resolutions := &reporter.ResolutionList{}
	if cfg.llmOn {
		log.Info("Detecting issues")
		var err error
		issues, err = reporter.NewIssueDetector(filteredLines, cfg.model).Run(ctx)
		if err != nil {
			fatal("detecting issues: %v", err)
		}
		log.Debug("Detected %d issues", len(issues.Issues))

		log.Info("Consolidating duplicate issues")
		issues, err = reporter.NewIssueDeduplicator(issues, cfg.model).Run(ctx)
		if err != nil {
			fatal("consolidating issues: %v", err)
		}
		log.Debug("Consolidated to %d issues", len(issues.Issues))

		log.Info("Resolving %d issues", len(issues.Issues))
		resolutions, err = reporter.NewResolutionAgent(issues, cfg.model, cfg.hostOS).Run(ctx)
		if err != nil {
			fatal("resolving issues: %v", err)
		}
		log.Debug("Generated %d resolutions", len(resolutions.Resolutions))
	} else {
		chunks := (len(filteredLines) + 999) / 1000
		log.Info("--no-llm: skipping issue detection (%d filtered lines would have gone to the LLM in %d chunk(s))",
			len(filteredLines), chunks)
	}

	// Detect anomalies on the RAW lines (upstream of the filter, so we still
	// see the high-volume programs the denylist removes).
	// Three detectors feed one combined, de-duplicated list:
	//   - peer:     a host unlike its fleet peers (no history needed)
	//   - baseline: a host unlike its OWN trailing-N-day normal (needs history)
	//   - temporal: a same-time-of-day burst vs prior days (needs history)
	// The history-based two are no-ops until the SQLite store has accumulated
	// a week or two; the peer detector works from day one.
	log.Info("Detecting anomalies")
	detector := reporter.NewPeerDetector(cfg.lines)
	agg := detector.Aggregate()
	peerAnomalies := detector.Run()
	log.Debug("Detected %d peer anomalies", len(peerAnomalies))

	var baselineAnomalies, temporalAnomalies []reporter.Anomaly
	if cfg.storeOn {
		store, err := reporter.OpenAggregateStore(cfg.dbPath)
		if err != nil {
			fatal("opening aggregate store %s: %v", cfg.dbPath, err)
		}
		written, err := store.WriteAggregates(logDate, agg.Counts)
		if err != nil {
			fatal("writing aggregates: %v", err)
		}
		if _, err := store.Prune(cfg.keepDays); err != nil {
			fatal("pruning aggregate store: %v", err)
		}
		log.Debug("Persisted %d aggregate rows for %s to %s",
			written, logDate.Format("2006-01-02"), cfg.dbPath)
		baselineAnomalies, err = reporter.NewBaselineDetector(agg, store, logDate).Run()
		if err != nil {
			fatal("baseline detector: %v", err)
		}
		temporalAnomalies, err = reporter.NewTemporalDetector(agg, store, logDate).Run()
		if err != nil {
			fatal("temporal detector: %v", err)
		}
		store.Close()
		log.Debug("Detected %d baseline and %d temporal anomalies",
			len(baselineAnomalies), len(temporalAnomalies))
	} else {
		log.Debug("Aggregate store disabled (--no-store); peer detector only")
	}

	anomalies := reporter.CombineAnomalies(peerAnomalies, baselineAnomalies, temporalAnomalies)
	log.Debug("Combined to %d anomalies after de-duplication", len(anomalies))

	// Mute known-known (host, program) pairs before the explainer, so we
	// never pay the LLM to explain something we're about to bin.
	var kept []reporter.Anomaly
	for _, a := range anomalies {
		if !knowns.AnomalyMuted(a.Host(), a.Program()) {
			kept = append(kept, a)
		}
	}
	if len(kept) != len(anomalies) {
		log.Debug("Muted %d known-known anomalies", len(anomalies)-len(kept))
	}
	anomalies = kept
	if len(cfg.hostOS) > 0 {
		// Replace the program-based OS guess with the real OS where the
		// source knows it (ELK dumps carry host.os.*; raw text does not).
		for _, a := range anomalies {
			if osName, ok := cfg.hostOS[a.Host()]; ok {
				a.SetOSFamily(osName)
			}
		}
	}
	var explained []*reporter.ExplainedAnomaly
	if cfg.llmOn {
		log.Info("Explaining anomalies")
		var err error
		explained, err = reporter.NewAnomalyExplainer(anomalies, cfg.model).Run(ctx)
		if err != nil {
			fatal("explaining anomalies: %v", err)
		}
		log.Debug("Explained %d anomalies", len(explained))
	} else {
		log.Info("--no-llm: rendering anomalies without explanations")
		explained = reporter.FactsOnly(anomalies)
	}

	// Generate the report: a short digest for the email body, and the full
	// findings as an attachment.
	log.Info("Generating report")
	rep := &reporter.ReportAgent{
		Issues:      issues,
		Resolutions: resolutions,
		Anomalies:   explained,
		LLMSkipped:  !cfg.llmOn,
		Model:       cfg.model,
		Knowns:      knowns,
	}
	fullReport := rep.Run()
	emailBody := rep.EmailBody()
	log.Debug("Generated report")

	// While we refine things, always drop the two files to the working directory.
	if err := os.WriteFile("email_body.md", []byte(emailBody), 0o644); err != nil {
		fatal("%v", err)
	}
	if err := os.WriteFile("email_attachment.md", []byte(fullReport), 0o644); err != nil {
		fatal("%v", err)
	}
	log.Info("Wrote email_body.md and email_attachment.md")

	// Print the short digest (not the full report) for cron logs.
	fmt.Print(emailBody)

	if cfg.sendEmail {
		log.Info("Sending email to %s", cfg.recipients)
		agent, err := reporter.NewEmailAgent(emailBody, fullReport, cfg.recipients)
		if err != nil {
			fatal("%v", err)
		}
		agent.Run()
	} else {
		log.Info("Skipping email")
	}
}
