package reporter

// Tests for the deterministic noise filter. Hostnames are
// fictional, as there.

import (
	"fmt"
	"reflect"
	"testing"
)

const blanketLine = "Aug 26 14:00:05 labbox widgetd[12]: probe from 203.0.113.9"

func TestBlanketIgnoreEnvEntriesDropMatchingLines(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", "203.0.113.9, oldprinter")
	if got := NewLogFilter([]string{blanketLine}, nil).Run(); len(got) != 0 {
		t.Errorf("expected line dropped, got %#v", got)
	}
}

func TestBlanketIgnoreUnsetEnvKeepsTheLine(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", "")
	got := NewLogFilter([]string{blanketLine}, nil).Run()
	if !reflect.DeepEqual(got, []string{blanketLine}) {
		t.Errorf("expected line kept, got %#v", got)
	}
}

func TestBlanketIgnoreWhitespaceAndEmptyEntriesAreIgnored(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", " , ,oldprinter , ")
	f := NewLogFilter(nil, nil)
	if !reflect.DeepEqual(f.BlanketIgnores, []string{"oldprinter"}) {
		t.Errorf("BlanketIgnores = %#v, want [oldprinter]", f.BlanketIgnores)
	}
}

func TestPidDifferencesDoNotDefeatTheDedupeCap(t *testing.T) {
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, fmt.Sprintf(
			"Aug 26 0%d:17:01 cronbox CRON[%d]: (munin) CMD (/usr/bin/munin-cron)", i, 1000+i))
	}
	// a pid-varying line dedupes to the 3-copy cap like an identical one
	if got := NewLogFilter(nil, nil).removeDuplicates(lines); len(got) != 3 {
		t.Errorf("expected 3 lines after dedupe, got %d", len(got))
	}
}

func filterOne(t *testing.T, line string) []string {
	t.Helper()
	t.Setenv("SYSLOG_BLANKET_IGNORE", "")
	return NewLogFilter([]string{line}, nil).Run()
}

func TestNamedRefusedScannerChatterIsDropped(t *testing.T) {
	for _, message := range []string{
		"client @0x7f6d 167.248.133.11#31871 (1.2.3.4.in-addr.arpa): " +
			"query (cache) '1.2.3.4.in-addr.arpa/MX/IN' denied",
		"client @0x7f6d 167.248.133.11#31871 (1.2.3.4.in-addr.arpa): " +
			"query failed (REFUSED) for 1.2.3.4.in-addr.arpa/IN/MX at query.c:7148",
		"client @0x7f6d 1.2.3.4#5 (4.4.8.in-addr.arpa): " +
			"rate limit slip REFUSED error response to 1.2.3.4/24",
	} {
		line := "Aug 26 14:00:05 dnsbox named[32325]: " + message
		if got := filterOne(t, line); len(got) != 0 {
			t.Errorf("expected drop for %q, got %#v", message, got)
		}
	}
}

func TestNamedServfailIsNormalisedNotDropped(t *testing.T) {
	line := "Aug 26 14:00:05 dnsbox named[32325]: client @0x7f6d 10.0.0.1#31871 " +
		"(x.example.com): query failed (SERVFAIL) for x.example.com/IN/A at query.c:7100"
	want := []string{"Aug 26 14:00:05 dnsbox named SERVFAIL query failure"}
	if got := filterOne(t, line); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCronJobAnnouncementsAreDropped(t *testing.T) {
	for _, line := range []string{
		"Aug 26 06:25:01 dhcpbox CRON[288]: (root) CMD (/var/dhcp/check.update.needed >/dev/null 2>&1)",
		"Aug 26 06:25:01 dnsbox CROND[288]: (root) CMD (run-parts /etc/cron.hourly)",
		"Aug 26 06:25:01 gatebox crontab[132]: (root) LIST (root)",
		"Aug 26 06:25:01 scanbox CRON[301]: (CRON) info (No MTA installed, discarding output)",
	} {
		if got := filterOne(t, line); len(got) != 0 {
			t.Errorf("expected drop for %q, got %#v", line, got)
		}
	}
}

func TestErrorShapedLinesStillSurvive(t *testing.T) {
	for _, line := range []string{
		"Aug 26 14:00:05 labbox dhcpcd[884]: dhcpcd is not running",
		"Aug 26 14:00:05 dnsbox named[32325]: zone example.ac.uk/IN: " +
			"refresh: could not refresh zone",
	} {
		if got := filterOne(t, line); !reflect.DeepEqual(got, []string{line}) {
			t.Errorf("expected %q kept, got %#v", line, got)
		}
	}
}
