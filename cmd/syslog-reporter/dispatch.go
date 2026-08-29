package main

// First-level command dispatch (ait srg-M2nyl, ant ADR srg-Lp8cB): every
// invocation names an explicit command; nothing falls through to a guessed
// batch run. The registry below is the single source both dispatch and the
// usage text build from, so help cannot drift from what actually runs.

import (
	"fmt"
	"io"
	"os"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/selfupdate"
)

type command struct {
	name    string
	summary string
	run     func(args []string) int
}

var commands = []command{
	{"run", "Run the daily batch pipeline over a log dump and write the report", cmdRun},
	{"eval", "Compare provider/model combinations over a small log sample", cmdEval},
	{"serve", "Serve the findings library web UI (default 127.0.0.1:7373)", cmdServe},
	{"user", "Manage local-auth accounts (add, list, passwd, remove)", cmdUser},
	{"findings", "List, show and record feedback on findings from the terminal", cmdFindings},
	{"mgmt-report", "Render the management summary (HTML file plus plain text)", cmdMgmtReport},
	{"self-update", "Replace this binary with the latest GitHub release", cmdSelfUpdate},
}

func cmdRun(args []string) int {
	runBatch(args)
	return 0
}

func cmdEval(args []string) int {
	runEval(args)
	return 0
}

func cmdServe(args []string) int {
	runServe(args)
	return 0
}

func cmdUser(args []string) int {
	runUser(args)
	return 0
}

func cmdFindings(args []string) int {
	defaultDB := getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db")
	if err := cli.RunFindings(defaultDB, args, os.Stdout); err != nil {
		fatal("%v", err)
	}
	return 0
}

func cmdMgmtReport(args []string) int {
	runMgmtReport(args)
	return 0
}

func cmdSelfUpdate(args []string) int {
	// Explicit invocation only: nothing in the batch pipeline may trigger
	// this. --check uses 0/1/2 codes.
	return selfupdate.Run(args)
}

// dispatch resolves the first argument to a command and runs it. A bare
// invocation or an unknown command prints usage and fails: guessing a batch
// run from a stray argument is exactly the trap this exists to close.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "--help", "-h", "-help", "help":
		// 'help <command>' forwards to that command's own --help.
		if args[0] == "help" && len(args) > 1 {
			for _, c := range commands {
				if c.name == args[1] {
					return c.run([]string{"--help"})
				}
			}
			fmt.Fprintf(stderr, "syslog-reporter: unknown command %q\nRun 'syslog-reporter --help' for the list of commands.\n", args[1])
			return 2
		}
		usage(stdout)
		return 0
	case "--version", "-version", "version":
		fmt.Fprintf(stdout, "syslog-reporter %s\n", version)
		// Release builds also mention a newer release when one exists;
		// dev builds and lookup failures stay a single line.
		selfupdate.VersionCheck(stdout)
		return 0
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(args[1:])
		}
	}
	fmt.Fprintf(stderr, "syslog-reporter: unknown command %q\nRun 'syslog-reporter --help' for the list of commands.\n", args[0])
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `syslog-reporter turns a noisy syslog stream into a short, prioritised report.

usage:
  syslog-reporter <command> [flags]

The everyday invocation is the batch run over a log dump:
  syslog-reporter run dump.ndjson.gz

commands:
`)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, `
Run 'syslog-reporter <command> --help' for a command's flags.
'syslog-reporter --version' prints the version; release builds also check
for a newer GitHub release (see self-update).
`)
}
