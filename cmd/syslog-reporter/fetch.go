package main

// The fetch command (ait srg-Sm1Is.1): one day of syslog from
// Elasticsearch as NDJSON. Where only certain addresses may reach the
// cluster, the same binary that runs the report is copied to one of them,
// fetches there, and the file is copied back.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/cli"
	"github.com/ohnotnow/syslog-reporter-go/internal/elk"
)

func cmdFetch(args []string) int {
	return runFetch(args, os.Stderr)
}

// runFetch returns 0 on success, 1 when the dump finished with a document
// count that does not match the search total, and 2 on any other failure.
func runFetch(args []string, logw io.Writer) int {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	setUsage(fs, fetchHelpIntro, fetchHelpEnv)
	url := fs.String("url", os.Getenv("ELK_URL"), "Elasticsearch base URL")
	index := fs.String("index", os.Getenv("ELK_INDEX"), "Index pattern or data stream, e.g. logs-system.syslog-default")
	day := fs.String("day", time.Now().AddDate(0, 0, -1).Format("2006-01-02"), "The day to dump, YYYY-MM-DD (default: yesterday)")
	tz := fs.String("tz", "Europe/London", "Time zone the day's boundaries are in (IANA name or +hh:mm)")
	out := fs.String("out", "", "Output file; a .gz suffix compresses it (default: syslog-<day>.ndjson)")
	batch := fs.Int("batch-size", 5000, "Documents per search request (1-10000)")
	timeout := fs.Int("timeout", 60, "Per-request timeout, seconds")
	keyFile := fs.String("key-file", "", "File whose first line is the API key (default: ELK_API_KEY)")
	username := fs.String("username", os.Getenv("ELK_USERNAME"), "Basic-auth username; the password comes from ELK_PASSWORD")
	defaultInsecure, err := cli.ParseBoolEnv("ELK_INSECURE")
	if err != nil {
		fmt.Fprintf(logw, "syslog-reporter: %v\n", err)
		return 2
	}
	insecure := fs.Bool("insecure", defaultInsecure, "Skip TLS certificate verification")
	caCert := fs.String("ca-cert", os.Getenv("ELK_CA_CERT"), "PEM file of a CA to trust, for a self-signed cluster")
	fs.Parse(args)

	fail := func(format string, a ...any) int {
		fmt.Fprintf(logw, "syslog-reporter: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() > 0 {
		return fail("unrecognised extra arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *url == "" {
		return fail("no URL: pass --url or set ELK_URL")
	}
	if *index == "" {
		return fail("no index: pass --index or set ELK_INDEX")
	}
	if *batch < 1 || *batch > 10000 {
		return fail("--batch-size must be between 1 and 10000")
	}
	if _, err := time.Parse("2006-01-02", *day); err != nil {
		return fail("--day must be YYYY-MM-DD, got %q", *day)
	}
	apiKey := strings.TrimSpace(os.Getenv("ELK_API_KEY"))
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return fail("reading --key-file: %v", err)
		}
		apiKey, _, _ = strings.Cut(string(b), "\n")
		apiKey = strings.TrimSpace(apiKey)
	}
	auth, err := elk.AuthHeader(apiKey, strings.TrimSpace(*username), strings.TrimSpace(os.Getenv("ELK_PASSWORD")))
	if err != nil {
		return fail("%v", err)
	}
	authDesc := "api key"
	if apiKey == "" {
		authDesc = "basic auth, user " + *username
	}
	if *out == "" {
		*out = "syslog-" + *day + ".ndjson"
	}

	fmt.Fprintf(logw, "dumping %s for %s (%s) as %s\n", *index, *day, *tz, authDesc)
	if *insecure {
		fmt.Fprintln(logw, "tls: VERIFICATION DISABLED")
	} else {
		fmt.Fprintln(logw, "tls: verified")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := elk.Dump(ctx, elk.Config{
		URL: *url, Index: *index, Auth: auth, Day: *day, TZ: *tz,
		BatchSize: *batch, Timeout: time.Duration(*timeout) * time.Second,
		Insecure: *insecure, CACert: *caCert,
	}, *out, logw)
	if errors.Is(err, elk.ErrIncomplete) {
		fmt.Fprintf(logw, "warning: %v; nothing written\n", err)
		return 1
	}
	if err != nil {
		return fail("FATAL: %v", err)
	}
	abs, _ := filepath.Abs(*out)
	size := int64(0)
	if info, err := os.Stat(*out); err == nil {
		size = info.Size()
	}
	fmt.Fprintf(logw, "\nwrote %d documents to %s (%d bytes)\n", res.Written, abs, size)
	if res.First != "" {
		fmt.Fprintf(logw, "timestamps %s .. %s\n", res.First, res.Last)
	}
	fmt.Fprintf(logw, "requests: 1 PIT open, %d searches, 1 PIT close (all read-only)\n", res.Searches)
	return 0
}
