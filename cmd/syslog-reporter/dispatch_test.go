package main

// Dispatch tests (ait srg-M2nyl): explicit commands only, no guessed batch
// run. Fictional hostnames only.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBareInvocationPrintsCommandListAndFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch(nil, &stdout, &stderr)
	if code == 0 {
		t.Error("bare invocation should exit non-zero")
	}
	for _, c := range commands {
		if !strings.Contains(stderr.String(), c.name) {
			t.Errorf("usage output missing command %q", c.name)
		}
	}
	if !strings.Contains(stderr.String(), "syslog-reporter run dump.ndjson.gz") {
		t.Error("usage output missing the everyday run example")
	}
}

func TestUnknownCommandNamesTheArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"frobnicate"}, &stdout, &stderr)
	if code == 0 {
		t.Error("unknown command should exit non-zero")
	}
	if !strings.Contains(stderr.String(), `"frobnicate"`) {
		t.Errorf("error should name the offending argument, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--help") {
		t.Errorf("error should suggest --help, got: %s", stderr.String())
	}
}

// The bare words work like their flag spellings: 'version' prints the
// version, 'help <command>' forwards to that command's own --help.
func TestBareVersionAndHelpForwarding(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := dispatch([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Errorf("bare 'version' should exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "syslog-reporter") {
		t.Errorf("bare 'version' output looks wrong: %s", stdout.String())
	}

	var helpErr bytes.Buffer
	code := dispatch([]string{"help", "nosuch"}, &stdout, &helpErr)
	if code == 0 {
		t.Error("'help nosuch' should exit non-zero")
	}
	if !strings.Contains(helpErr.String(), `"nosuch"`) {
		t.Errorf("'help nosuch' should name the argument, got: %s", helpErr.String())
	}
}

func TestTopLevelHelpAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := dispatch([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Errorf("--help should exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "serve") || !strings.Contains(stdout.String(), "self-update") {
		t.Error("--help should list every command")
	}
	stdout.Reset()
	if code := dispatch([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Errorf("--version should exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "syslog-reporter") {
		t.Errorf("--version output looks wrong: %s", stdout.String())
	}
}

// TestRunCommandOwnsTheBatchPath drives the real batch path through dispatch
// using --dump-filtered, which exits after the deterministic filter stage.
func TestRunCommandOwnsTheBatchPath(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", "")
	t.Setenv("SYSLOG_KNOWN_KNOWNS", filepath.Join(t.TempDir(), "absent.toml"))
	logPath := filepath.Join(t.TempDir(), "sample.log")
	line := "Jan 12 03:04:05 web01.example.test badservice[123]: catastrophic widget failure\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	// The batch path writes its dump straight to os.Stdout, so swap it for
	// a pipe around the dispatch call.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := dispatch([]string{"run", logPath, "--dump-filtered"}, io.Discard, io.Discard)
	w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Errorf("run --dump-filtered should exit 0, got %d", code)
	}
	if !strings.Contains(string(out), "catastrophic widget failure") {
		t.Errorf("filtered dump missing the test line, got: %s", out)
	}
}

// The full deterministic pipeline (--no-llm --no-store) honours --out-dir
// for the report file drops.
func TestRunWritesReportFilesToOutDir(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", "")
	t.Setenv("SYSLOG_KNOWN_KNOWNS", filepath.Join(t.TempDir(), "absent.toml"))
	logPath := filepath.Join(t.TempDir(), "sample.log")
	line := "Jan 12 03:04:05 web01.example.test badservice[123]: catastrophic widget failure\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := dispatch([]string{"run", logPath, "--no-llm", "--no-store", "--out-dir", outDir},
		io.Discard, io.Discard)
	w.Close()
	os.Stdout = old
	io.ReadAll(r)
	if code != 0 {
		t.Fatalf("run should exit 0, got %d", code)
	}
	for _, name := range []string{"email_body.md", "email_attachment.md"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("%s not written to --out-dir: %v", name, err)
		}
		if _, err := os.Stat(name); err == nil {
			t.Errorf("%s also appeared in the working directory", name)
		}
	}
}
