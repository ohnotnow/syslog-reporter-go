package main

// The budget command (ait srg-ZqQMU): the prompt-token budget is per day
// and lives in the store, so someone deliberately spending more (other
// servers, other dumps) needs a way past it that is not a hand-written
// UPDATE against the live database.

import (
	"flag"
	"fmt"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func runBudget(args []string) {
	fs := flag.NewFlagSet("budget", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), budgetHelp) }
	dbPath := fs.String("db", getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		"SQLite store path, resolved exactly as in batch mode")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	reset := false
	switch {
	case len(positionals) == 0:
	case len(positionals) == 1 && positionals[0] == "reset":
		reset = true
	default:
		fatal("usage: syslog-reporter budget [reset] [--db <path>]")
	}
	limit, err := maxPromptTokensFromEnv()
	if err != nil {
		fatal("%v", err)
	}
	if err := reporter.RequireDatabase(*dbPath); err != nil {
		fatal("%v", err)
	}
	lib, err := reporter.OpenLibraryStore(*dbPath)
	if err != nil {
		fatal("opening %s: %v", *dbPath, err)
	}
	defer lib.Close()

	today := time.Now()
	day := today.Format("2006-01-02")
	spent, err := lib.PromptTokensSpent(today)
	if err != nil {
		fatal("%v", err)
	}
	if reset {
		if err := lib.ResetPromptTokens(today); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("%s: spend reset from %d to 0 prompt tokens\n", day, spent)
		return
	}
	if limit == 0 {
		fmt.Printf("%s: %d prompt tokens spent; no daily budget (SYSLOG_MAX_PROMPT_TOKENS=0)\n", day, spent)
		return
	}
	fmt.Printf("%s: %d of %d prompt tokens spent\n", day, spent, limit)
}
