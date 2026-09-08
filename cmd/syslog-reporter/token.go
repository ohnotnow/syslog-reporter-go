package main

// The token command (ait srg-Kj5Q8.3): bearer tokens for the sysadmin API,
// minted and revoked on the box by whoever administers the store. The raw
// token is printed once, alone on stdout, so 'token create' pipes cleanly
// into a password manager or a paste.

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func runToken(args []string) {
	const usage = "usage: syslog-reporter token <create|list|revoke> [args] (see 'token --help')"
	if len(args) == 0 {
		fatal(usage)
	}
	switch args[0] {
	case "--help", "-h", "help":
		fmt.Print(tokenHelp)
	case "create":
		runTokenCreate(args[1:])
	case "list":
		runTokenList(args[1:])
	case "revoke":
		runTokenRevoke(args[1:])
	default:
		fatal("unknown token command %q\n%s", args[0], usage)
	}
}

func tokenFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), tokenHelp) }
	dbPath := fs.String("db", getenvDefault("SYSLOG_DB_PATH", "syslog_aggregates.db"),
		"SQLite store path, resolved exactly as in batch mode")
	return fs, dbPath
}

func runTokenCreate(args []string) {
	fs, dbPath := tokenFlagSet("token create")
	expiresFlag := fs.String("expires", "", "Date (YYYY-MM-DD) after which the token stops working")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter token create <username> [--expires YYYY-MM-DD] [--db <path>]")
	}
	expires, err := parseExpiry(*expiresFlag)
	if err != nil {
		fatal("%v", err)
	}
	raw, tok, err := tokenCreate(*dbPath, positionals[0], expires)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Println(raw)
	fmt.Fprintf(os.Stderr, "token %s created for %s%s; it will not be shown again\n",
		tok.Prefix, tok.Username, expirySuffix(tok))
}

// parseExpiry turns a --expires date into the last second of that day
// UTC, so "2026-12-31" works all of the 31st. Empty means never; a date
// that has already passed is refused.
func parseExpiry(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	day, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, fmt.Errorf("--expires wants YYYY-MM-DD, got %q", s)
	}
	at := day.Add(24*time.Hour - time.Second)
	if !at.After(time.Now()) {
		return nil, fmt.Errorf("--expires %s is already in the past", s)
	}
	return &at, nil
}

func expirySuffix(t *reporter.APIToken) string {
	if t.ExpiresAt == nil {
		return ""
	}
	return ", expires " + t.ExpiresAt.Format("2006-01-02")
}

// tokenCreate is the testable core: open the store, resolve the user, mint.
func tokenCreate(dbPath, username string, expires *time.Time) (string, *reporter.APIToken, error) {
	if err := reporter.RequireDatabase(dbPath); err != nil {
		return "", nil, err
	}
	lib, err := reporter.OpenLibraryStore(dbPath)
	if err != nil {
		return "", nil, fmt.Errorf("opening %s: %w", dbPath, err)
	}
	defer lib.Close()
	user, err := lib.UserByUsername(username)
	if err != nil {
		return "", nil, err
	}
	if user == nil {
		return "", nil, fmt.Errorf("no user %q (add one with 'user add')", username)
	}
	return lib.CreateAPIToken(user.ID, expires)
}

func runTokenList(args []string) {
	fs, dbPath := tokenFlagSet("token list")
	if extra := cli.ParseFlagsAnywhere(fs, args); len(extra) > 0 {
		fatal("token list takes no arguments (got %s)", strings.Join(extra, " "))
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	tokens, err := lib.ListAPITokens()
	if err != nil {
		fatal("%v", err)
	}
	if len(tokens) == 0 {
		fmt.Println("no tokens (create one with 'token create <username>')")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PREFIX\tUSERNAME\tCREATED\tLAST USED\tEXPIRES\tSTATUS")
	for _, t := range tokens {
		status := "active"
		switch {
		case t.Revoked:
			status = "revoked"
		case !t.Usable(time.Now()):
			status = "expired"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.Prefix, t.Username,
			t.CreatedAt.Format("2006-01-02"), dateOrNever(t.LastUsedAt), dateOrNever(t.ExpiresAt), status)
	}
	tw.Flush()
}

func dateOrNever(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format("2006-01-02")
}

func runTokenRevoke(args []string) {
	fs, dbPath := tokenFlagSet("token revoke")
	positionals := cli.ParseFlagsAnywhere(fs, args)
	if len(positionals) != 1 {
		fatal("usage: syslog-reporter token revoke <prefix> [--db <path>]")
	}
	lib := openUserStore(*dbPath)
	defer lib.Close()
	t, err := lib.RevokeAPIToken(positionals[0])
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("token %s (%s) revoked\n", t.Prefix, t.Username)
}
