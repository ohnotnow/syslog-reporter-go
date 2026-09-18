package main

// Tests for knowns discover. Fictional hosts only; Jev is a stand-in.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/jev"
	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

func TestSelectDumpsPicksDatedFilesAndReportsGaps(t *testing.T) {
	dir := t.TempDir()
	end := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	for _, day := range []string{"2026-09-15", "2026-09-17"} {
		if err := os.WriteFile(filepath.Join(dir, "syslog-"+day+".ndjson.gz"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// an empty (partial) file does not count
	if err := os.WriteFile(filepath.Join(dir, "syslog-2026-09-16.ndjson.gz"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	found, missing := selectDumps(dir, end, 4)
	if len(found) != 2 || !strings.HasSuffix(found[0].path, "2026-09-15.ndjson.gz") || !found[1].day.Equal(end) {
		t.Errorf("found = %+v", found)
	}
	if strings.Join(missing, ",") != "2026-09-14,2026-09-16" {
		t.Errorf("missing = %v", missing)
	}
	if found, _ := selectDumps(dir, end.AddDate(0, 0, 30), 3); len(found) != 0 {
		t.Errorf("no files in range should find nothing, got %+v", found)
	}
}

var discoverDays = map[string][]string{
	"2026-09-15": {
		"Sep 15 03:00:01 web01.example.test fwupd[900]: 12:00:01.000 FuMain fwupd 1.9.5 ready for requests",
		"Sep 15 03:00:02 web02.example.test fwupd[901]: 12:00:02.000 FuMain fwupd 1.9.5 ready for requests",
		"Sep 15 04:00:00 db01.example.test kernel: EXT4-fs error (device sda1): bad block 77",
	},
	"2026-09-16": {
		"Sep 16 03:00:01 web01.example.test fwupd[902]: 12:00:01.000 FuMain fwupd 1.9.5 ready for requests",
		"Sep 16 05:00:00 db01.example.test kernel: EXT4-fs error (device sda1): bad block 78",
		"Sep 16 06:00:00 web03.example.test motd-news[12]: * Canonical Workshop gives developers reproducible builds",
	},
	"2026-09-17": {
		"Sep 17 03:00:01 web01.example.test fwupd[903]: 12:00:01.000 FuMain fwupd 1.9.5 ready for requests",
		"Sep 17 07:00:00 web03.example.test motd-news[13]: * Canonical Workshop gives developers reproducible builds",
	},
}

func accumulateFixture(t *testing.T) map[string]*shape {
	t.Helper()
	shapes := map[string]*shape{}
	for day, lines := range discoverDays {
		accumulate(shapes, lines, day)
	}
	return shapes
}

func TestAccumulateCountsLinesHostsAndDaysPerShape(t *testing.T) {
	shapes := accumulateFixture(t)
	if len(shapes) != 3 {
		t.Fatalf("want 3 shapes, got %d", len(shapes))
	}
	var fwupd *shape
	for _, s := range shapes {
		if s.Program == "fwupd" {
			fwupd = s
		}
	}
	if fwupd == nil || fwupd.Lines != 4 || len(fwupd.Hosts) != 2 || len(fwupd.Days) != 3 {
		t.Errorf("fwupd shape: %+v", fwupd)
	}
	if strings.Contains(fwupd.Template, "1.9.5") || !strings.Contains(fwupd.Template, "<n>.<n>.<n>") {
		t.Errorf("version not masked: %q", fwupd.Template)
	}
}

// fakeScorer scores by program: fwupd and motd-news are routine, kernel
// errors are not; it also tallies usage the way the real one does.
func fakeScorer(ctx context.Context, s *shape) (float64, jev.Usage, error) {
	switch s.Program {
	case "fwupd", "motd-news":
		return 0.03, jev.Usage{InputTokens: 100, OutputTokens: 10}, nil
	default:
		return 0.9, jev.Usage{InputTokens: 100, OutputTokens: 10}, nil
	}
}

func TestCandidatesRespectThresholdsAndBuildWorkingRegexes(t *testing.T) {
	shapes := accumulateFixture(t)
	usage, _, err := scoreShapes(context.Background(), shapes, 2, fakeScorer)
	if err != nil {
		t.Fatal(err)
	}
	if usage.InputTokens != 300 {
		t.Errorf("usage not summed: %+v", usage)
	}
	// fwupd: 3 days, motd-news: 2 days, kernel: low score fails
	got := selectCandidates(shapes, 0.1, 3, 1)
	if len(got) != 1 || got[0].Program != "fwupd" {
		t.Fatalf("min-days 3 should leave only fwupd, got %+v", got)
	}
	got = selectCandidates(shapes, 0.1, 2, 1)
	if len(got) != 2 || got[0].Program != "fwupd" || got[1].Program != "motd-news" {
		t.Fatalf("min-days 2 should give fwupd then motd-news by lines, got %+v", got)
	}
	inputs, err := candidateInputs(got)
	if err != nil {
		t.Fatal(err)
	}
	for i, in := range inputs {
		if in.Host != "*" || in.Source != reporter.KnownSourceJev || !strings.HasPrefix(in.Reason, "jev: score 0.03, ") {
			t.Errorf("input %d: %+v", i, in)
		}
		re := regexp.MustCompile("(?m)" + in.Match)
		for _, lines := range discoverDays {
			for _, line := range lines {
				rest := strings.SplitN(strings.Join(strings.Fields(line), " "), " ", 5)[4]
				isSame := strings.HasPrefix(rest, got[i].Program)
				if re.MatchString(rest) != isSame {
					t.Errorf("regex %q on %q: match=%v, want %v", in.Match, rest, !isSame, isSame)
				}
			}
		}
	}
	if !strings.Contains(inputs[0].Reason, "4 lines on 2 hosts over 3 days") {
		t.Errorf("reason: %q", inputs[0].Reason)
	}
}

func TestScoreShapesStopsOnTheFirstError(t *testing.T) {
	shapes := accumulateFixture(t)
	failing := func(ctx context.Context, s *shape) (float64, jev.Usage, error) {
		return 0, jev.Usage{}, context.DeadlineExceeded
	}
	if _, _, err := scoreShapes(context.Background(), shapes, 3, failing); err == nil {
		t.Error("expected the scorer's error")
	}
}

func TestPreviewPrintsAndConfirmReadsYes(t *testing.T) {
	shapes := accumulateFixture(t)
	if _, _, err := scoreShapes(context.Background(), shapes, 1, fakeScorer); err != nil {
		t.Fatal(err)
	}
	candidates := selectCandidates(shapes, 0.1, 2, 1)
	inputs, err := candidateInputs(candidates)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printCandidates(&out, candidates, inputs)
	text := out.String()
	if !strings.Contains(text, "SCORE") || !strings.Contains(text, "fwupd") || !strings.Contains(text, "1. fwupd") {
		t.Errorf("preview:\n%s", text)
	}
	if strings.Contains(text, "web01") {
		t.Errorf("preview should show templates, not hosts:\n%s", text)
	}
	for in, want := range map[string]bool{"y\n": true, "yes\n": true, "n\n": false, "\n": false, "": false} {
		if got := confirm(strings.NewReader(in), &bytes.Buffer{}, "? "); got != want {
			t.Errorf("confirm(%q) = %v", in, got)
		}
	}
}
