package reporter

// The findings library (milestone 3, ait srg-2KY5X): report runs and their
// findings persisted so each morning's report stops being throwaway. Lives in
// the SAME SQLite file as the aggregates baseline, and keeps store.go's
// minimal-pragma style on purpose: default rollback journal (no WAL), no
// PRAGMA foreign_keys (the REFERENCES clauses stay declarative), and
// CREATE TABLE IF NOT EXISTS as the whole migration story. The Python
// original is archived, so unlike the aggregates schema these tables carry
// no compatibility constraint - see ADR srg-VXQvH for the reasoning.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

const librarySchema = `
CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY,
    log_date   TEXT NOT NULL,           -- ISO 'YYYY-MM-DD' the report covered
    created_at TEXT NOT NULL,           -- RFC3339 UTC
    model      TEXT                     -- NULL on --no-llm runs
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

// IssuePayload is the stored JSON form of an issue-kind finding: the Issue
// fields inlined at top level, with the paired Resolution as a sibling key
// (null when the resolution stage produced no match).
type IssuePayload struct {
	Issue
	Resolution *Resolution `json:"resolution"`
}

// LibraryStore is the SQLite-backed findings library. It opens its own
// single-connection pool on the same file as the AggregateStore; the shared
// busy_timeout keeps the two writers polite with each other.
type LibraryStore struct {
	db *sql.DB
}

func OpenLibraryStore(path string) (*LibraryStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(librarySchema); err != nil {
		db.Close()
		return nil, err
	}
	return &LibraryStore{db: db}, nil
}

func (s *LibraryStore) Close() error {
	return s.db.Close()
}

// BeginRun records a report run and returns its id. Idempotent per day,
// mirroring WriteAggregates: any earlier run for the same log date is deleted
// first, together with its findings, hosts and feedback. Re-running a day is
// a testing/backfill operation; losing that day's votes is accepted, and
// duplicate findings polluting the library forever would be worse.
func (s *LibraryStore) BeginRun(logDate time.Time, model string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	iso := isoDate(logDate)
	// Explicit child-first deletes: foreign keys are declarative only here.
	staleFindings := "(SELECT id FROM findings WHERE run_id IN " +
		"(SELECT id FROM runs WHERE log_date = ?))"
	for _, del := range []string{
		"DELETE FROM feedback WHERE finding_id IN " + staleFindings,
		"DELETE FROM finding_hosts WHERE finding_id IN " + staleFindings,
		"DELETE FROM findings WHERE run_id IN (SELECT id FROM runs WHERE log_date = ?)",
		"DELETE FROM runs WHERE log_date = ?",
	} {
		if _, err := tx.Exec(del, iso); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	var modelVal any
	if model != "" {
		modelVal = model
	}
	res, err := tx.Exec(
		"INSERT INTO runs (log_date, created_at, model) VALUES (?, ?, ?)",
		iso, time.Now().UTC().Format(time.RFC3339), modelVal)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	return id, tx.Commit()
}

// AddFinding persists one finding plus its per-host rows in one transaction
// and returns the finding id. payload is marshalled as the stored record: an
// IssuePayload for kind 'issue', an ExplainedAnomaly for the anomaly kinds.
// Anomaly kinds pass severity as the empty string (queries treat the empty
// string as absent); an empty hosts slice writes no finding_hosts rows.
func (s *LibraryStore) AddFinding(runID int64, kind, severity, title, service string, hosts []string, payload any) (int64, error) {
	blob, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(
		"INSERT INTO findings (run_id, kind, severity, title, service, payload) "+
			"VALUES (?, ?, ?, ?, ?, ?)",
		runID, kind, severity, title, service, string(blob))
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	for _, host := range hosts {
		if _, err := tx.Exec(
			"INSERT INTO finding_hosts (finding_id, host) VALUES (?, ?)", id, host); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	return id, tx.Commit()
}

// User is a users-table row. Forenames, surname and the password hash are
// nullable: local `user add` leaves the names NULL (OIDC fills them in
// later), and SSO-created users carry a NULL password hash, which the local
// login form treats as "can never sign in here".
type User struct {
	ID           int64
	Email        string
	Username     string
	Forenames    sql.NullString
	Surname      sql.NullString
	PasswordHash sql.NullString
	CreatedAt    string
}

// CreateUser inserts a user with the names left NULL. An empty passwordHash
// is stored as NULL (an SSO-created user with no local login).
func (s *LibraryStore) CreateUser(username, email, passwordHash string) (int64, error) {
	var hash any
	if passwordHash != "" {
		hash = passwordHash
	}
	res, err := s.db.Exec(
		"INSERT INTO users (email, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
		email, username, hash, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UserByUsername returns nil, nil when no user matches.
func (s *LibraryStore) UserByUsername(username string) (*User, error) {
	return s.userWhere("username = ?", username)
}

// UserByID returns nil, nil when no user matches.
func (s *LibraryStore) UserByID(id int64) (*User, error) {
	return s.userWhere("id = ?", id)
}

func (s *LibraryStore) userWhere(cond string, arg any) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		"SELECT id, email, username, forenames, surname, password_hash, created_at "+
			"FROM users WHERE "+cond, arg).
		Scan(&u.ID, &u.Email, &u.Username, &u.Forenames, &u.Surname,
			&u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}
