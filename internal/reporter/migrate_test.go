package reporter

// Tests for the shared open path: pragmas, the migration ladder, and
// adoption of databases created before schema_version existed. Fictional
// hostnames only.

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow("SELECT version FROM schema_version WHERE id = 1").Scan(&v); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	return v
}

func tableNames(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names[n] = true
	}
	return names
}

func TestMigrateFreshInMemory(t *testing.T) {
	db, err := openDatabase(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	want := migrations[len(migrations)-1].version
	if v := schemaVersion(t, db); v != want {
		t.Errorf("schema version = %d, want %d", v, want)
	}
	names := tableNames(t, db)
	for _, tbl := range []string{"aggregates", "runs", "findings", "finding_hosts", "feedback", "users"} {
		if !names[tbl] {
			t.Errorf("table %s missing after fresh migration", tbl)
		}
	}
}

func TestMigratePragmasOnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pragmas.db")
	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	var fk int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
	// Enforcement must actually be live, not just declared.
	_, err = db.Exec(
		"INSERT INTO findings (run_id, kind, title, payload) VALUES (999999, 'issue', 't', '{}')")
	if err == nil {
		t.Error("insert with nonexistent run_id succeeded; foreign keys not enforced")
	}
}

// TestMigrateAdoptsPreVersionedFile builds the full schema the pre-ladder
// way (runs without the stats columns, no schema_version), inserts data,
// and reopens through the runner: version stamped, data intact, columns
// added.
func TestMigrateAdoptsPreVersionedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adopt.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	oldSchema := `
CREATE TABLE aggregates (
    date TEXT NOT NULL, host TEXT NOT NULL, program TEXT NOT NULL,
    window TEXT NOT NULL, count INTEGER NOT NULL,
    PRIMARY KEY (date, host, program, window)
);
CREATE TABLE runs (
    id INTEGER PRIMARY KEY, log_date TEXT NOT NULL,
    created_at TEXT NOT NULL, model TEXT
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
    kind TEXT NOT NULL, severity TEXT, title TEXT NOT NULL, service TEXT,
    payload TEXT NOT NULL
);
CREATE TABLE finding_hosts (finding_id INTEGER NOT NULL REFERENCES findings(id), host TEXT NOT NULL);
CREATE TABLE feedback (
    id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
    user_id INTEGER REFERENCES users(id),
    verdict TEXT NOT NULL CHECK (verdict IN ('worked', 'didnt_work')),
    comment TEXT, created_at TEXT NOT NULL
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE,
    forenames TEXT, surname TEXT, password_hash TEXT, created_at TEXT NOT NULL
);
INSERT INTO aggregates VALUES ('2026-06-01', 'oldhost', 'sshd', '09:00', 42);
INSERT INTO runs (log_date, created_at, model) VALUES ('2026-06-01', '2026-06-02T06:00:00Z', 'test-model');
`
	if _, err := raw.Exec(oldSchema); err != nil {
		t.Fatalf("build old-style db: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("adopting open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if v := schemaVersion(t, db); v != migrations[len(migrations)-1].version {
		t.Errorf("schema version = %d after adoption", v)
	}
	var count int
	if err := db.QueryRow(
		"SELECT count FROM aggregates WHERE host = 'oldhost'").Scan(&count); err != nil {
		t.Fatalf("aggregates row lost in adoption: %v", err)
	}
	if count != 42 {
		t.Errorf("aggregates count = %d, want 42", count)
	}
	var model string
	if err := db.QueryRow(
		"SELECT model FROM runs WHERE log_date = '2026-06-01'").Scan(&model); err != nil {
		t.Fatalf("runs row lost in adoption: %v", err)
	}
	// The stats columns must have been added, NULL for the pre-existing row.
	var raw2, filtered sql.NullInt64
	if err := db.QueryRow(
		"SELECT raw_lines, filtered_lines FROM runs WHERE log_date = '2026-06-01'").
		Scan(&raw2, &filtered); err != nil {
		t.Fatalf("stats columns not added: %v", err)
	}
	if raw2.Valid || filtered.Valid {
		t.Errorf("pre-existing run row should have NULL stats, got %v/%v", raw2, filtered)
	}
}

// TestMigrateAdoptsAggregatesOnlyFile covers a pre-milestone-3 dev db:
// aggregates alone, no library tables, no schema_version.
func TestMigrateAdoptsAggregatesOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aggonly.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE aggregates (
    date TEXT NOT NULL, host TEXT NOT NULL, program TEXT NOT NULL,
    window TEXT NOT NULL, count INTEGER NOT NULL,
    PRIMARY KEY (date, host, program, window)
);
INSERT INTO aggregates VALUES ('2026-06-01', 'lonehost', 'cron', '03:00', 7);`); err != nil {
		t.Fatalf("build aggregates-only db: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("adopting open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	names := tableNames(t, db)
	for _, tbl := range []string{"runs", "findings", "finding_hosts", "feedback", "users"} {
		if !names[tbl] {
			t.Errorf("library table %s not created on adoption", tbl)
		}
	}
	var count int
	if err := db.QueryRow(
		"SELECT count FROM aggregates WHERE host = 'lonehost'").Scan(&count); err != nil {
		t.Fatalf("aggregates row lost: %v", err)
	}
	if count != 7 {
		t.Errorf("count = %d, want 7", count)
	}
}

// Both stores open the same file back-to-back in normal operation; the
// ladder must tolerate that and end-to-end writes must still work.
func TestMigrateSharedFileBothStores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	agg, err := OpenAggregateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agg.Close() })
	lib, err := OpenLibraryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })

	if _, err := agg.WriteAggregates(
		time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		singleCount("hostA", "sshd", "09:00", 3)); err != nil {
		t.Fatalf("write aggregates: %v", err)
	}
	runID, err := lib.BeginRun(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), "m")
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	if _, err := lib.AddFinding(runID, "issue", "low", "t", "sshd",
		[]string{"hostA"}, map[string]string{}); err != nil {
		t.Fatalf("add finding: %v", err)
	}
}
