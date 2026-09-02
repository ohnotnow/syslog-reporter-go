// syslog-reporter: a batch tool that turns a noisy org-wide rsyslog stream
// into a short, prioritised report for a sysadmin team.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
	"github.com/ohnotnow/syslog-reporter-go/internal/selfupdate"
	"github.com/ohnotnow/syslog-reporter-go/internal/web"
)

// version is stamped by the release build via -ldflags onto
// internal/selfupdate.Version; this alias keeps the call sites short.
var version = selfupdate.Version

type logger struct {
	debugEnabled bool
}

func (l *logger) log(level, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		time.Now().Format("2006-01-02 15:04:05"), level,
		fmt.Sprintf(format, args...))
}

func (l *logger) Info(format string, args ...any) { l.log("INFO", format, args...) }

func (l *logger) Warn(format string, args ...any) { l.log("WARN", format, args...) }

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

// readLines reads all lines, each keeping its trailing newline; a final
// line without one is kept as-is.
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
	// Pick up a .env in the working directory without overriding variables
	// already in the environment.
	_ = godotenv.Load()

	// SYSLOG_REDACT: comma-separated literal strings stripped from every
	// provider-bound message (ant ADR srg-Mzvjf). Parsed once here; the llm
	// package never reads the environment itself.
	if v := os.Getenv("SYSLOG_REDACT"); v != "" {
		llm.SetRedactions(strings.Split(v, ","))
	}

	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// runMgmtReport renders the periodic management summary (ait srg-YHETx): a
// pure reader of the runs/findings/feedback tables, with per-day volume
// borrowed from the aggregates baseline for days predating the run stats
// columns. Always writes mgmt_report.html to the working directory, like
// the daily report's file drops; --send-email posts it to the separate
// SYSLOG_MGMT_RECIPIENTS list (management is a different audience from the
// team digest, so there is deliberately no fallback to
// SYSLOG_SMTP_RECIPIENTS).
func runMgmtReport(args []string) {
	fs := flag.NewFlagSet("mgmt-report", flag.ExitOnError)
	setUsage(fs, mgmtHelpIntro, mgmtHelpEnv)
	days := fs.Int("days", 30, "Number of days the report covers, ending yesterday")
	sendEmail := fs.Bool("send-email", false, "Email the report to the recipients")
	recipientsFlag := fs.String("recipients", "",
		"Comma-separated recipient addresses (default: SYSLOG_MGMT_RECIPIENTS)")
	dbPath := fs.String("db", getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		"Path to the SQLite database")
	outPath := fs.String("out", "mgmt_report.html", "Where to write the HTML report")
	debug := fs.Bool("debug", false, "Print extra debug information")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fatal("unrecognised extra arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *days < 1 {
		fatal("--days must be at least 1")
	}
	log := &logger{debugEnabled: *debug}

	// Management is a different audience from the team digest, so the
	// recipients list is separate and there is deliberately no fallback to
	// SYSLOG_SMTP_RECIPIENTS.
	recipients := *recipientsFlag
	if recipients == "" {
		recipients = os.Getenv("SYSLOG_MGMT_RECIPIENTS")
	}
	if *sendEmail {
		if recipients == "" {
			fatal("--send-email needs --recipients or SYSLOG_MGMT_RECIPIENTS to be set")
		}
		if os.Getenv("SYSLOG_SMTP_SERVER") == "" {
			fatal("--send-email needs SYSLOG_SMTP_SERVER to be set")
		}
		if os.Getenv("SYSLOG_SMTP_SENDER") == "" {
			fatal("--send-email needs SYSLOG_SMTP_SENDER to be set")
		}
	} else if *recipientsFlag != "" {
		log.Warn("--recipients given but --send-email not set; no email will be sent")
	}
	// mgmt-report is a pure reader; a missing db is a typo'd path.
	if err := reporter.RequireDatabase(*dbPath); err != nil {
		fatal("%v", err)
	}

	// The period ends yesterday: log dates cover completed days, and
	// anchoring to the calendar (not the newest run) keeps a stalled cron
	// visible as "no data" days rather than silently reporting stale weeks.
	to := time.Now().AddDate(0, 0, -1)
	from := to.AddDate(0, 0, -(*days - 1))

	lib, err := reporter.OpenLibraryStore(*dbPath)
	if err != nil {
		fatal("opening findings library %s: %v", *dbPath, err)
	}
	defer lib.Close()
	agg, err := reporter.OpenAggregateStore(*dbPath)
	if err != nil {
		fatal("opening aggregate store %s: %v", *dbPath, err)
	}
	defer agg.Close()

	stats, err := reporter.GatherMgmtStats(lib, agg, from, to)
	if err != nil {
		fatal("gathering management stats: %v", err)
	}
	log.Debug("Gathered stats: %d/%d days with data, %d findings",
		stats.DaysWithData, len(stats.Days), stats.TotalFindings)

	html, err := reporter.RenderMgmtHTML(stats, version)
	if err != nil {
		fatal("rendering management report: %v", err)
	}
	if err := os.WriteFile(*outPath, []byte(html), 0o600); err != nil {
		fatal("writing %s: %v", *outPath, err)
	}
	log.Info("Wrote %s", *outPath)

	text := reporter.RenderMgmtText(stats)
	fmt.Print(text)

	if *sendEmail {
		agent := &reporter.EmailAgent{
			BodyText:   text,
			HTMLBody:   html,
			Recipients: recipients,
			Subject: fmt.Sprintf("Syslog management summary - %s",
				reporter.MgmtPeriodLabel(stats.From, stats.To)),
			SMTPServer: os.Getenv("SYSLOG_SMTP_SERVER"),
			Sender:     os.Getenv("SYSLOG_SMTP_SENDER"),
		}
		// The report file is already on disk; a failed send must still
		// fail the process so cron notices.
		if err := agent.Run(); err != nil {
			fatal("%v", err)
		}
	} else {
		log.Info("Skipping email")
	}
}

// runServe starts the findings library web app (serve mode). Every setting
// is a flag whose default comes from the matching SYSLOG_WEB_* variable
// (flag wins), so systemd units can stay env-shaped while a sysadmin at a
// shell just types flags.
func runServe(args []string) {
	cfg, err := web.ConfigFromEnv()
	if err != nil {
		fatal("%v", err)
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	setUsage(fs, serveHelpIntro, serveHelpEnv)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "host:port to bind")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite file to serve")
	fs.StringVar(&cfg.AuthMode, "auth", cfg.AuthMode, "Auth mode: none, local, or oidc (not built yet)")
	fs.StringVar(&cfg.CertFile, "tls-cert", cfg.CertFile, "TLS certificate; with --tls-key, serve HTTPS")
	fs.StringVar(&cfg.KeyFile, "tls-key", cfg.KeyFile, "TLS private key")
	fs.BoolVar(&cfg.SecureCookies, "secure-cookies", cfg.SecureCookies,
		"Force the Secure cookie flag on, for TLS terminated at a reverse proxy")
	debug := fs.Bool("debug", false, "Log every request (method, path, status, duration)")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fatal("unrecognised extra arguments: %s", strings.Join(fs.Args(), " "))
	}
	log := &logger{debugEnabled: *debug}
	if err := cfg.Validate(); err != nil {
		fatal("%v", err)
	}
	// serve only reads the store; a missing file is a typo'd path, not an
	// invitation to create an empty library and serve "no findings yet".
	if err := reporter.RequireDatabase(cfg.DBPath); err != nil {
		fatal("%v", err)
	}
	cfg.Version = version
	cfg.Debug = *debug
	cfg.Logger = log
	// Risky-but-supported combinations announce themselves; the operator's
	// call stands (warn, never refuse - srg-so8ja.9).
	for _, warning := range cfg.StartupWarnings() {
		log.Warn("%s", warning)
	}
	// The findings pages read the library on every request, so serve mode
	// always opens the store; the local auth driver shares the same handle.
	lib, err := reporter.OpenLibraryStore(cfg.DBPath)
	if err != nil {
		fatal("opening %s: %v", cfg.DBPath, err)
	}
	defer lib.Close()
	var users web.UserStore
	if cfg.AuthMode == "local" {
		users = lib
	}
	auth, err := web.NewAuthenticator(cfg, users)
	if err != nil {
		fatal("%v", err)
	}
	srv, err := web.New(cfg, auth, lib)
	if err != nil {
		fatal("%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Bind before announcing, so a taken port fails without first printing
	// a URL that never existed.
	ln, err := srv.Listen()
	if err != nil {
		fatal("%v", err)
	}
	scheme := "http"
	if cfg.CertFile != "" {
		scheme = "https"
	}
	log.Info("Serving on %s://%s (db %s)", scheme, ln.Addr(), cfg.DBPath)
	if err := srv.Serve(ctx, ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("%v", err)
	}
	log.Info("Server stopped")
}

// runUser handles the local-auth account lifecycle: add, list, passwd,
// remove. Passwords are prompted for without echo when stdin is a
// terminal, or read from stdin with --password-stdin for scripted/agent
// use; never accepted as a CLI argument, never echoed or logged.
func runUser(args []string) {
	const usage = "usage: syslog-reporter user <add|list|passwd|remove> [args] (see 'user --help')"
	if len(args) == 0 {
		fatal(usage)
	}
	switch args[0] {
	case "--help", "-h", "help":
		fmt.Print(userHelp)
	case "add":
		runUserAdd(args[1:])
	case "list":
		runUserList(args[1:])
	case "passwd":
		runUserPasswd(args[1:])
	case "remove":
		runUserRemove(args[1:])
	default:
		fatal("unknown user command %q\n%s", args[0], usage)
	}
}

// userFlagSet builds the shared flag set for the user subcommands: the
// help wiring and the store path.
func userFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), userHelp) }
	dbPath := fs.String("db", getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		"SQLite store path, resolved exactly as in batch mode")
	return fs, dbPath
}

// passwordStdinFlag adds --password-stdin to a user subcommand's flags.
func passwordStdinFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("password-stdin", false,
		"Read the password from stdin instead of prompting (for scripted use)")
}

// readNewPassword collects a password: from stdin with --password-stdin,
// otherwise prompted for twice without echo.
func readNewPassword(passwordStdin bool) string {
	var password string
	if passwordStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal("reading password from stdin: %v", err)
		}
		password = strings.TrimRight(string(data), "\r\n")
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fatal("stdin is not a terminal; pipe the password in with --password-stdin")
		}
		fmt.Fprint(os.Stderr, "Password: ")
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("reading password: %v", err)
		}
		fmt.Fprint(os.Stderr, "Again: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("reading password: %v", err)
		}
		if !bytes.Equal(first, second) {
			fatal("passwords do not match")
		}
		password = string(first)
	}
	if password == "" {
		fatal("password must not be empty")
	}
	return password
}

// openUserStore opens the library for the user subcommands. The store must
// already exist: account admin on a typo'd path must not conjure a new db
// that serve will never read.
func openUserStore(dbPath string) *reporter.LibraryStore {
	if err := reporter.RequireDatabase(dbPath); err != nil {
		fatal("%v", err)
	}
	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		fatal("opening %s: %v", dbPath, err)
	}
	return lib
}

func runUserAdd(args []string) {
	fs, dbPath := userFlagSet("user add")
	passwordStdin := passwordStdinFlag(fs)
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 2 {
		fatal("usage: syslog-reporter user add <username> <email> [--password-stdin] [--db <path>]")
	}
	username, email := positionals[0], positionals[1]
	// The path check comes before the password prompt: a typo'd --db must
	// not cost the operator two blind password entries first.
	if err := reporter.RequireDatabase(*dbPath); err != nil {
		fatal("%v", err)
	}
	password := readNewPassword(*passwordStdin)
	if err := userAdd(*dbPath, username, email, password); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("user %s added\n", username)
}

func runUserList(args []string) {
	fs, dbPath := userFlagSet("user list")
	if extra := cli.ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		fatal("user list takes no arguments (got %s)", strings.Join(extra, " "))
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	users, err := lib.ListUsers()
	if err != nil {
		fatal("%v", err)
	}
	if len(users) == 0 {
		fmt.Println("no users (add one with 'user add')")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tEMAIL\tLOCAL LOGIN\tCREATED")
	for _, u := range users {
		login := "yes"
		if !u.PasswordHash.Valid {
			login = "no (SSO only)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", u.Username, u.Email, login, u.CreatedAt)
	}
	tw.Flush()
}

func runUserPasswd(args []string) {
	fs, dbPath := userFlagSet("user passwd")
	passwordStdin := passwordStdinFlag(fs)
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter user passwd <username> [--password-stdin] [--db <path>]")
	}
	username := positionals[0]
	lib := openUserStore(*dbPath)
	defer lib.Close()
	password := readNewPassword(*passwordStdin)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fatal("%v", err)
	}
	if err := lib.SetUserPassword(username, string(hash)); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("password updated for %s\n", username)
}

func runUserRemove(args []string) {
	fs, dbPath := userFlagSet("user remove")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter user remove <username> [--db <path>]")
	}
	username := positionals[0]
	lib := openUserStore(*dbPath)
	defer lib.Close()
	if err := lib.RemoveUser(username); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("user %s removed (their feedback votes are now anonymous)\n", username)
}

// userAdd is the testable core of `user add`: hash and insert.
func userAdd(dbPath, username, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dbPath, err)
	}
	defer lib.Close()
	if _, err := lib.CreateUser(username, email, string(hash)); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
			return fmt.Errorf("username %q already exists", username)
		}
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
			return fmt.Errorf("email %q already exists", email)
		}
		return err
	}
	return nil
}

func runBatch(cliArgs []string) {
	defaultModel := getenvDefault("SYSLOG_DEFAULT_MODEL", "openai/gpt-5.6-luna")
	defaultDBPath := getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db")
	defaultKnownsPath := getenvDefault("SYSLOG_KNOWN_KNOWNS", "known_knowns.toml")
	keepDays, err := strconv.Atoi(getenvDefault("SYSLOG_DB_KEEP_DAYS", "90"))
	if err != nil {
		fatal("SYSLOG_DB_KEEP_DAYS must be an integer: %v", err)
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	setUsage(fs, runHelpIntro, runHelpEnv)
	model := fs.String("model", defaultModel, "Model to use (litellm format)")
	format := fs.String("format", "auto",
		"Input format: 'raw' is rsyslog text, 'ndjson' is an elk_dump.py dump "+
			"(.gz handled). 'auto' picks ndjson for *.ndjson / *.ndjson.gz paths, "+
			"raw otherwise (stdin is always raw).")
	debug := fs.Bool("debug", false, "Print extra debug information")
	sendEmail := fs.Bool("send-email", false, "Email the report to the recipients")
	recipients := fs.String("recipients", "",
		"Comma-separated recipient addresses (default: SYSLOG_SMTP_RECIPIENTS)")
	outDir := fs.String("out-dir", ".",
		"Directory the report files are written to (must exist)")
	dateStr := fs.String("date", "",
		"ISO date (YYYY-MM-DD) the log slice covers, for the aggregate store. Defaults to yesterday.")
	dbPath := fs.String("db", defaultDBPath, "SQLite aggregate store path")
	knownsPath := fs.String("known-knowns", defaultKnownsPath,
		"TOML file of operator-acknowledged oddities to suppress (missing file just means none)")
	noStore := fs.Bool("no-store", false,
		"Don't persist aggregates or run the history-based detectors (peer comparison still runs)")
	noLLM := fs.Bool("no-llm", false,
		"Skip every LLM stage (issue detection, dedupe, resolutions, anomaly "+
			"explanations) so the run costs nothing")
	dumpFiltered := fs.Bool("dump-filtered", false,
		"Print the filtered log lines and exit (the filter-tuning aid)")

	// Flags are accepted before or after the positional logfile.
	positionals := cli.ParseFlagsAnywhere(fs, cliArgs)
	if len(positionals) > 1 {
		fatal("unrecognised extra arguments: %s", strings.Join(positionals[1:], " "))
	}

	// The positional path names the logfile; "--" (or nothing) means stdin.
	path := "--"
	if len(positionals) == 1 {
		path = positionals[0]
	}
	if *format != "auto" && *format != "raw" && *format != "ndjson" {
		fatal("--format must be one of auto, raw, ndjson (got %q)", *format)
	}

	// Everything that can be checked before the pipeline spends time or
	// money fails here, with the missing setting named.
	if info, err := os.Stat(*outDir); err != nil || !info.IsDir() {
		fatal("--out-dir %s is not an existing directory", *outDir)
	}
	if *sendEmail {
		if *recipients == "" && os.Getenv("SYSLOG_SMTP_RECIPIENTS") == "" {
			fatal("--send-email needs --recipients or SYSLOG_SMTP_RECIPIENTS to be set")
		}
		if os.Getenv("SYSLOG_SMTP_SERVER") == "" {
			fatal("--send-email needs SYSLOG_SMTP_SERVER to be set")
		}
		if os.Getenv("SYSLOG_SMTP_SENDER") == "" {
			fatal("--send-email needs SYSLOG_SMTP_SENDER to be set")
		}
	}
	if !*noLLM && !*dumpFiltered {
		if err := llm.CheckCredentials(*model); err != nil {
			fatal("%v", err)
		}
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
		outDir:     *outDir,
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
	outDir     string
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
	llm.SetLogger(log.Warn)

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
		issues, err = reporter.NewIssueDetector(filteredLines, cfg.model, cfg.hostOS).Run(ctx)
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

	if cfg.llmOn {
		usage := llm.TotalUsage()
		log.Info("LLM usage: %d prompt tokens, %d completion tokens", usage.PromptTokens, usage.CompletionTokens)
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
		LogDate:     logDate,
	}
	fullReport := rep.Run()
	emailBody := rep.EmailBody()
	log.Debug("Generated report")

	// Persist this run's findings into the library (same SQLite file as the
	// aggregates) so history accumulates before any UI exists. A capture
	// failure costs the library one day, not the report or the email.
	if cfg.storeOn {
		captureModel := cfg.model
		if !cfg.llmOn {
			captureModel = ""
		}
		if lib, err := reporter.OpenLibraryStore(cfg.dbPath); err != nil {
			log.Warn("opening findings library %s: %v", cfg.dbPath, err)
		} else {
			if err := reporter.CaptureRun(lib, logDate, captureModel,
				len(cfg.lines), len(filteredLines), issues, resolutions, explained); err != nil {
				log.Warn("capturing findings: %v", err)
			} else {
				log.Info("Captured %d findings for %s",
					len(issues.Issues)+len(explained), logDate.Format("2006-01-02"))
			}
			lib.Close()
		}
	} else {
		log.Info("--no-store: skipping findings capture")
	}

	// The report files are the artefact cron archives and what survives a
	// failed send; --out-dir places them, defaulting to the working
	// directory.
	bodyPath := filepath.Join(cfg.outDir, "email_body.md")
	attachmentPath := filepath.Join(cfg.outDir, "email_attachment.md")
	if err := os.WriteFile(bodyPath, []byte(emailBody), 0o600); err != nil {
		fatal("%v", err)
	}
	if err := os.WriteFile(attachmentPath, []byte(fullReport), 0o600); err != nil {
		fatal("%v", err)
	}
	log.Info("Wrote %s and %s", bodyPath, attachmentPath)

	// Print the short digest (not the full report) for cron logs.
	fmt.Print(emailBody)

	if cfg.sendEmail {
		// The HTML alternative is a nicety: if rendering ever fails, send
		// the markdown-only email rather than losing the morning report.
		htmlBody, err := reporter.RenderDigestHTML(emailBody, version)
		if err != nil {
			log.Warn("rendering HTML digest, falling back to plain text: %v", err)
			htmlBody = ""
		}
		agent, err := reporter.NewEmailAgent(emailBody, htmlBody, fullReport, cfg.recipients)
		if err != nil {
			fatal("%v", err)
		}
		// The agent resolves the SYSLOG_SMTP_RECIPIENTS fallback, so log
		// its list rather than the (often empty) --recipients flag.
		log.Info("Sending email to %s", agent.Recipients)
		// email_body.md and email_attachment.md are already on disk; a
		// failed send must still fail the process so cron notices.
		if err := agent.Run(); err != nil {
			fatal("%v", err)
		}
	} else {
		if cfg.recipients != "" {
			log.Warn("--recipients given but --send-email not set; no email will be sent")
		}
		log.Info("Skipping email")
	}
}
