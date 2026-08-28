package reporter

// Port of tests/test_known_knowns.py from the Python original.

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var sliceDate = day(2026, 8, 27)

func mustEntry(t *testing.T, host, reason, match, program string, expires *time.Time) *KnownEntry {
	t.Helper()
	e, err := newKnownEntry(host, reason, match, program, nil, expires)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	return e
}

func datePtr(y int, m time.Month, d int) *time.Time {
	t := day(y, m, d)
	return &t
}

func TestKnownEntryNeedsMatchOrProgram(t *testing.T) {
	if _, err := newKnownEntry("scopebox", "no matcher given", "", "", nil, nil); err == nil {
		t.Error("expected an error for an entry with neither match nor program")
	}
}

func TestKnownEntryBadRegexFailsAtConstructionNotPerLine(t *testing.T) {
	if _, err := newKnownEntry("scopebox", "broken", "port [", "", nil, nil); err == nil {
		t.Error("expected an error for a broken regex")
	}
}

func TestKnownsNoExpiryIsForever(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", nil)}, sliceDate)
	if len(kk.Active) != 1 {
		t.Errorf("active = %d, want 1", len(kk.Active))
	}
}

func TestKnownsExpiryIsInclusiveOfTheSliceDate(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", &sliceDate)}, sliceDate)
	if len(kk.Active) != 1 || len(kk.Expired) != 0 {
		t.Errorf("active = %d, expired = %d", len(kk.Active), len(kk.Expired))
	}
}

func TestKnownsLapsedEntryMovesToExpired(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", datePtr(2026, 8, 26))}, sliceDate)
	if len(kk.Active) != 0 || len(kk.Expired) != 1 {
		t.Errorf("active = %d, expired = %d", len(kk.Active), len(kk.Expired))
	}
}

func TestKnownsExpiryJudgedAgainstSliceDateNotToday(t *testing.T) {
	// A backfill of an old slice should see the entry as it was then.
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", datePtr(2026, 1, 1))},
		day(2025, 12, 25))
	if len(kk.Active) != 1 {
		t.Errorf("active = %d, want 1", len(kk.Active))
	}
}

func TestKnownsLineIgnoredScopesToTheHost(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", nil)}, sliceDate)
	if !kk.LineIgnored("scopebox", "widgetd[9]: retry on port 1234") {
		t.Error("expected match on scopebox")
	}
	if kk.LineIgnored("otherbox", "widgetd[9]: retry on port 1234") {
		t.Error("expected no match on otherbox")
	}
}

func TestKnownsHostIsAGlobPattern(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "lab*", "lab kit", "usb reset", "", nil)}, sliceDate)
	if !kk.LineIgnored("lab042", "kernel: usb reset") {
		t.Error("expected lab* to match lab042")
	}
	if kk.LineIgnored("office1", "kernel: usb reset") {
		t.Error("expected lab* not to match office1")
	}
}

func TestKnownsStarHostMatchesEverywhere(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "*", "fleet-wide", "widget spam", "", nil)}, sliceDate)
	if !kk.LineIgnored("anybox", "widgetd: widget spam") {
		t.Error("expected * to match any host")
	}
}

func TestKnownsAnomalyMutedUsesProgramNotMatch(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "mcastbox", "igmp eye-roll", "", "kernel", nil)}, sliceDate)
	if !kk.AnomalyMuted("mcastbox", "kernel") {
		t.Error("expected mute for mcastbox/kernel")
	}
	if kk.AnomalyMuted("mcastbox", "postfix/smtpd") {
		t.Error("expected no mute for a different program")
	}
	if kk.AnomalyMuted("otherbox", "kernel") {
		t.Error("expected no mute for a different host")
	}
}

func TestKnownsMatchOnlyEntryNeverMutesAnomalies(t *testing.T) {
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", nil)}, sliceDate)
	if kk.AnomalyMuted("scopebox", "kernel") {
		t.Error("a match-only entry must never mute anomalies")
	}
}

func TestKnownsHitsAreCountedPerEntry(t *testing.T) {
	entry := mustEntry(t, "scopebox", "microscope", "port 1234", "", nil)
	kk := NewKnownKnowns([]*KnownEntry{entry}, sliceDate)
	kk.LineIgnored("scopebox", "retry on port 1234")
	kk.LineIgnored("scopebox", "retry on port 1234")
	kk.LineIgnored("otherbox", "retry on port 1234") // no match, no hit
	if entry.Hits != 2 {
		t.Errorf("hits = %d, want 2", entry.Hits)
	}
	if hit := kk.HitEntries(); len(hit) != 1 || hit[0] != entry {
		t.Errorf("hit entries = %#v", hit)
	}
}

const knownsDoc = `
[[known]]
host = "scopebox"
match = "port 1234"
reason = "microscope attached for the optics experiment"
added = 2026-08-27
expires = 2030-09-01

[[known]]
host = "*"
program = "kernel"
reason = "fleet-wide igmp eye-roll"
`

func loadKnownsDoc(t *testing.T, doc string, logDate time.Time) (*KnownKnowns, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_knowns.toml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadKnownKnowns(path, logDate)
}

func TestKnownsFileParsesEntriesAndTomlDates(t *testing.T) {
	kk, err := loadKnownsDoc(t, knownsDoc, sliceDate)
	if err != nil {
		t.Fatal(err)
	}
	if len(kk.Active) != 2 {
		t.Fatalf("active = %d, want 2", len(kk.Active))
	}
	want := day(2030, 9, 1)
	if kk.Active[0].Expires == nil || !kk.Active[0].Expires.Equal(want) {
		t.Errorf("expires = %v, want %v", kk.Active[0].Expires, want)
	}
}

func TestKnownsFileEntriesLapseBySliceDate(t *testing.T) {
	kk, err := loadKnownsDoc(t, knownsDoc, day(2030, 9, 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(kk.Active) != 1 || len(kk.Expired) != 1 {
		t.Errorf("active = %d, expired = %d", len(kk.Active), len(kk.Expired))
	}
}

func TestKnownsMissingFileMeansNoEntries(t *testing.T) {
	kk, err := LoadKnownKnowns("does-not-exist.toml", sliceDate)
	if err != nil {
		t.Fatal(err)
	}
	if len(kk.Active) != 0 || len(kk.Expired) != 0 {
		t.Errorf("expected no entries, got %+v", kk)
	}
}

func TestKnownsEntryWithoutReasonIsRejected(t *testing.T) {
	_, err := loadKnownsDoc(t, "[[known]]\nhost = \"scopebox\"\nmatch = \"port 1234\"\n", sliceDate)
	if err == nil {
		t.Error("expected an error for an entry without a reason")
	}
}

func TestKnownLinesDroppedHostAware(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", "")
	lines := []string{
		"Aug 26 14:00:05 scopebox widgetd[12]: retry on port 1234",
		"Aug 26 14:00:06 otherbox widgetd[12]: retry on port 1234",
	}
	kk := NewKnownKnowns([]*KnownEntry{
		mustEntry(t, "scopebox", "microscope", "port 1234", "", nil)}, sliceDate)
	got := NewLogFilter(lines, kk).Run()
	if !reflect.DeepEqual(got, []string{lines[1]}) {
		t.Errorf("got %#v, want just the otherbox line", got)
	}
}

func TestNoKnownsChangesNothing(t *testing.T) {
	t.Setenv("SYSLOG_BLANKET_IGNORE", "")
	lines := []string{
		"Aug 26 14:00:05 scopebox widgetd[12]: retry on port 1234",
		"Aug 26 14:00:06 otherbox widgetd[12]: retry on port 1234",
	}
	if got := NewLogFilter(lines, nil).Run(); !reflect.DeepEqual(got, lines) {
		t.Errorf("got %#v, want unchanged", got)
	}
}
