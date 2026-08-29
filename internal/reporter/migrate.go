package reporter

// The shared SQLite open path. Both stores (aggregates + findings library)
// live in ONE database file and open it through openDatabase, which sets the
// standard pragmas and runs the numbered migration ladder - so no caller can
// forget either. The ladder is idempotent, so the two stores opening the
// same file back-to-back is harmless.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// RequireDatabase errors when the SQLite file does not exist yet. Every
// command that only READS the store (serve, findings, mgmt-report, user)
// calls this before opening: without it a typo'd path silently creates an
// empty database and the operator sees "no findings" instead of their
// mistake. Only a batch run may create the file. :memory: and file: URI
// paths are exempt, matching openDatabase's own creation guard.
func RequireDatabase(path string) error {
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(
				"database %s does not exist (a report run creates it; check --db or SYSLOG_DB_PATH)", path)
		}
		return fmt.Errorf("checking database %s: %w", path, err)
	}
	return nil
}

// openDatabase opens the SQLite file, applies the standard pragmas and
// brings the schema up to date.
func openDatabase(path string) (*sql.DB, error) {
	// A NEW database file is created 0600 before the driver touches the
	// path: the file carries log-derived detail, account emails and bcrypt
	// hashes, so it must not default to the umask (srg-so8ja.10). An
	// existing file keeps whatever mode its administrator chose. WAL
	// sidecars inherit the main file's permissions.
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
		} else if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("creating %s: %w", path, err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// journal_mode=WAL is a persistent property of the file; foreign_keys
	// and busy_timeout are per-connection, so all three run on every open.
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

type migration struct {
	version     int
	description string
	apply       func(tx *sql.Tx) error
}

// One forward-only ladder for the whole file; aggregates and library tables
// share it. Append new migrations as plain DDL; never modify an existing
// one. Migration 1 alone is idempotent by construction (IF NOT EXISTS plus
// guarded column-adds) because it doubles as the adoption path for any
// database created before schema_version existed - empty, aggregates-only,
// or the full schema.
var migrations = []migration{
	{1, "baseline schema", applyBaselineSchema},
}

const baselineSchema = `
CREATE TABLE IF NOT EXISTS aggregates (
    date    TEXT    NOT NULL,   -- ISO 'YYYY-MM-DD' the log slice covers
    host    TEXT    NOT NULL,
    program TEXT    NOT NULL,
    window  TEXT    NOT NULL,   -- 'HH:MM' time-of-day bucket (see ParseLine)
    count   INTEGER NOT NULL,
    PRIMARY KEY (date, host, program, window)
);
CREATE INDEX IF NOT EXISTS idx_aggregates_series ON aggregates (host, program, date);
CREATE INDEX IF NOT EXISTS idx_aggregates_window ON aggregates (host, program, window, date);
CREATE TABLE IF NOT EXISTS runs (
    id             INTEGER PRIMARY KEY,
    log_date       TEXT NOT NULL,       -- ISO 'YYYY-MM-DD' the report covered
    created_at     TEXT NOT NULL,       -- RFC3339 UTC
    model          TEXT,                -- NULL on --no-llm runs
    raw_lines      INTEGER,             -- dump size before filtering (srg-YHETx.1)
    filtered_lines INTEGER              -- after LogFilter; NULL = not recorded
);
CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY,
    run_id   INTEGER NOT NULL REFERENCES runs(id),
    kind     TEXT NOT NULL,             -- 'issue' | 'peer' | 'baseline' | 'temporal'
    severity TEXT,                      -- issues only: critical/high/medium/low
    title    TEXT NOT NULL,             -- Issue.Issue, or anomaly Headline
    service  TEXT,                      -- AffectedService, or anomaly Program
    payload  TEXT NOT NULL              -- full record as JSON (IssuePayload / ExplainedAnomaly)
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id);
CREATE TABLE IF NOT EXISTS finding_hosts (
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    host       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_hosts_host ON finding_hosts (host);
CREATE TABLE IF NOT EXISTS feedback (
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id),
    user_id    INTEGER REFERENCES users(id),   -- NULL = anonymous (auth mode 'none')
    verdict    TEXT NOT NULL CHECK (verdict IN ('worked', 'didnt_work')),
    comment    TEXT,
    created_at TEXT NOT NULL
);
-- SQLite treats NULLs as distinct in unique indexes; COALESCE makes the
-- anonymous vote a singleton per finding too.
CREATE UNIQUE INDEX IF NOT EXISTS idx_feedback_once
    ON feedback (finding_id, COALESCE(user_id, 0));
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,
    forenames     TEXT,
    surname       TEXT,
    password_hash TEXT,                 -- bcrypt; NULL for SSO-created users
    created_at    TEXT NOT NULL
);
`

func applyBaselineSchema(tx *sql.Tx) error {
	if _, err := tx.Exec(baselineSchema); err != nil {
		return err
	}
	// A runs table from before the srg-YHETx.1 stats columns landed needs an
	// explicit ADD COLUMN: CREATE TABLE IF NOT EXISTS never alters an
	// existing table. Rows from before the change keep NULL in both columns
	// (meaning "not recorded", distinct from a genuine zero-line day).
	rows, err := tx.Query("PRAGMA table_info(runs)")
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, col := range []string{"raw_lines", "filtered_lines"} {
		if have[col] {
			continue
		}
		if _, err := tx.Exec("ALTER TABLE runs ADD COLUMN " + col + " INTEGER"); err != nil {
			return err
		}
	}
	return nil
}

// runMigrations applies every migration newer than the file's stamped
// version. A database without a schema_version table is simply at version 0.
func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 0);`); err != nil {
		return err
	}
	var current int
	if err := db.QueryRow("SELECT version FROM schema_version WHERE id = 1").Scan(&current); err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := m.apply(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d (%s): %w", m.version, m.description, err)
		}
		if _, err := tx.Exec("UPDATE schema_version SET version = ? WHERE id = 1", m.version); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d (%s): stamp version: %w", m.version, m.description, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
