package reporter

// Tests for the database-backed known-knowns (migration 5).

import (
	"path/filepath"
	"testing"
	"time"
)

func newKnownsStore(t *testing.T) *LibraryStore {
	t.Helper()
	s, err := OpenLibraryStore(filepath.Join(t.TempDir(), "knowns.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func cliInput(host, program, match, reason string, expires *time.Time) KnownEntryInput {
	return KnownEntryInput{Host: host, Program: program, Match: match, Reason: reason,
		Added: sliceDate, Expires: expires, Source: KnownSourceCLI}
}

func TestKnownsStoreAddReturnsIDsInOrder(t *testing.T) {
	s := newKnownsStore(t)
	got, err := s.AddKnownEntries([]KnownEntryInput{
		cliInput("scopebox", "kernel", "", "microscope", nil),
		cliInput("dhcp-a.example.test", "dhcpd", "no free leases", "pool-less by design", nil),
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(got) != 2 || got[0].ID == 0 || got[1].ID <= got[0].ID {
		t.Fatalf("ids not ascending: %+v", got)
	}
	if got[1].Match != "no free leases" || got[1].Program != "dhcpd" {
		t.Errorf("fields not kept: %+v", got[1])
	}
}

func TestKnownsStoreBadRegexWritesNothing(t *testing.T) {
	s := newKnownsStore(t)
	_, err := s.AddKnownEntries([]KnownEntryInput{
		cliInput("scopebox", "kernel", "", "fine", nil),
		cliInput("scopebox", "", "port [", "broken", nil),
	})
	if err == nil {
		t.Fatal("expected a regex error")
	}
	rows, err := s.ListKnownEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("expected nothing written, got %d rows", len(rows))
	}
}

func TestKnownsStoreRefusesNeitherProgramNorMatch(t *testing.T) {
	s := newKnownsStore(t)
	if _, err := s.AddKnownEntries([]KnownEntryInput{cliInput("scopebox", "", "", "nothing", nil)}); err == nil {
		t.Error("expected an error for an entry with neither program nor match")
	}
}

func TestKnownsStoreRefusesUnknownSource(t *testing.T) {
	s := newKnownsStore(t)
	in := cliInput("scopebox", "kernel", "", "r", nil)
	in.Source = "carrier pigeon"
	if _, err := s.AddKnownEntries([]KnownEntryInput{in}); err == nil {
		t.Error("expected an error for an unknown source")
	}
}

func TestKnownsStoreProvenanceRoundTrips(t *testing.T) {
	s := newKnownsStore(t)
	fid := int64(1234)
	exp := datePtr(2026, 9, 1)
	_, err := s.AddKnownEntries([]KnownEntryInput{{
		Host: "dhcp-a.example.test", Program: "dhcpd", Match: "no free leases", Reason: "pool-less",
		Added: sliceDate, Expires: exp, Source: KnownSourceAPI,
		CreatedBy: "jbloggs", TokenPrefix: "5210c8e0", FindingID: &fid,
	}, cliInput("scopebox", "kernel", "", "microscope", nil)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	rows, err := s.ListKnownEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	api, cli := rows[0], rows[1]
	if api.Source != KnownSourceAPI || api.CreatedBy != "jbloggs" || api.TokenPrefix != "5210c8e0" ||
		api.FindingID == nil || *api.FindingID != 1234 {
		t.Errorf("api provenance lost: %+v", api)
	}
	if !api.Added.Equal(sliceDate) || api.Expires == nil || !api.Expires.Equal(*exp) {
		t.Errorf("dates not round-tripped: added %v expires %v", api.Added, api.Expires)
	}
	if cli.Source != KnownSourceCLI || cli.CreatedBy != "" || cli.TokenPrefix != "" || cli.FindingID != nil || cli.Expires != nil {
		t.Errorf("cli row should have NULL provenance: %+v", cli)
	}
	forFinding, err := s.KnownEntriesForFinding(1234)
	if err != nil {
		t.Fatal(err)
	}
	if len(forFinding) != 1 || forFinding[0].ID != api.ID {
		t.Errorf("KnownEntriesForFinding = %+v, want just the api row", forFinding)
	}
}

func TestKnownsStoreLoadSplitsActiveAndExpiredBySliceDate(t *testing.T) {
	s := newKnownsStore(t)
	_, err := s.AddKnownEntries([]KnownEntryInput{
		cliInput("scopebox", "kernel", "", "forever", nil),
		cliInput("scopebox", "sshd", "", "lapses on the slice date itself", datePtr(2026, 8, 27)),
		cliInput("scopebox", "cron", "", "lapsed", datePtr(2026, 8, 26)),
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	k, err := s.LoadKnownKnowns(sliceDate)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Active) != 2 || len(k.Expired) != 1 || k.Expired[0].Program != "cron" {
		t.Errorf("active %d expired %d (%+v)", len(k.Active), len(k.Expired), k.Expired)
	}
	// Judged against the slice date, not today: a historical backfill sees
	// the lapsed entry as still active.
	k, err = s.LoadKnownKnowns(day(2026, 8, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Active) != 3 {
		t.Errorf("backfill should see all 3 active, got %d", len(k.Active))
	}
	if !k.LineIgnored("scopebox", "kernel", "anything") {
		t.Error("loaded program entry should drop the line")
	}
}

func TestKnownsStoreDeleteReportsWhetherARowWent(t *testing.T) {
	s := newKnownsStore(t)
	got, err := s.AddKnownEntries([]KnownEntryInput{cliInput("scopebox", "kernel", "", "r", nil)})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.DeleteKnownEntry(got[0].ID + 100); err != nil || ok {
		t.Errorf("unknown id: ok=%v err=%v, want false,nil", ok, err)
	}
	if ok, err := s.DeleteKnownEntry(got[0].ID); err != nil || !ok {
		t.Errorf("first delete: ok=%v err=%v, want true,nil", ok, err)
	}
	if ok, _ := s.DeleteKnownEntry(got[0].ID); ok {
		t.Error("second delete should report no row")
	}
}
