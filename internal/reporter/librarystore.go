package reporter

// The findings library (milestone 3, ait srg-2KY5X): report runs and their
// findings persisted so each morning's report stops being throwaway. Lives in
// the SAME SQLite file as the aggregates baseline, and keeps store.go's
// minimal-pragma style on purpose: default rollback journal (no WAL), no
// PRAGMA foreign_keys (the REFERENCES clauses stay declarative), and
// CREATE TABLE IF NOT EXISTS plus ALTER-if-missing column checks as the
// whole migration story. The Python
// original is archived, so unlike the aggregates schema these tables carry
// no compatibility constraint - see ADR srg-VXQvH for the reasoning.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const librarySchema = `
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
	if err := ensureRunsStatsColumns(db); err != nil {
		db.Close()
		return nil, err
	}
	return &LibraryStore{db: db}, nil
}

// ensureRunsStatsColumns retrofits the srg-YHETx.1 stats columns onto a runs
// table created by an older binary: CREATE TABLE IF NOT EXISTS never alters
// an existing table, so databases from before the columns landed need an
// explicit ADD COLUMN. Rows from before the change keep NULL in both columns
// (meaning "not recorded", distinct from a genuine zero-line day).
func ensureRunsStatsColumns(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(runs)")
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
	for _, col := range []string{"raw_lines", "filtered_lines"} {
		if have[col] {
			continue
		}
		if _, err := db.Exec("ALTER TABLE runs ADD COLUMN " + col + " INTEGER"); err != nil {
			return err
		}
	}
	return nil
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

// SetRunStats records the day's ingest funnel on the run row: the dump's
// line count before filtering and the count LogFilter left behind. Written
// at capture time so the numbers survive the aggregate store's prune (ant
// ADR srg-9X77J); the management report reads them, never writes them.
func (s *LibraryStore) SetRunStats(runID int64, rawLines, filteredLines int) error {
	_, err := s.db.Exec(
		"UPDATE runs SET raw_lines = ?, filtered_lines = ? WHERE id = ?",
		rawLines, filteredLines, runID)
	return err
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

// FindingFilter narrows a findings search. Zero values mean "any". Host,
// Service and Query are substring matches ("mik" finds host mikonos; owner
// decision 2026-08-28, severity and kind stay exact - they are dropdowns);
// From/To bound the run's log_date (inclusive, ISO YYYY-MM-DD).
type FindingFilter struct {
	Host     string
	Service  string
	Severity string
	Kind     string
	Query    string
	From     string
	To       string
	Limit    int
	Offset   int
}

// FindingSummary is one findings-list row: the promoted columns joined to
// the run date, the host list, and the feedback verdict counts. The json
// tags serve the CLI's --json output.
type FindingSummary struct {
	ID        int64  `json:"id"`
	RunID     int64  `json:"run_id"`
	LogDate   string `json:"log_date"`
	Kind      string `json:"kind"`
	Severity  string `json:"severity"` // '' for anomaly kinds
	Title     string `json:"title"`
	Service   string `json:"service"`
	Hosts     string `json:"hosts"` // comma-joined, insertion order
	Worked    int    `json:"worked"`
	DidntWork int    `json:"didnt_work"`
}

// escapeLike backslash-escapes the SQL LIKE wildcards in a user-supplied
// term, for use with ESCAPE '\'.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// SearchFindings lists findings newest run first (ties by insertion order),
// honouring Limit/Offset for pagination.
func (s *LibraryStore) SearchFindings(f FindingFilter) ([]*FindingSummary, error) {
	where := []string{"1=1"}
	var args []any
	add := func(cond string, vals ...any) {
		where = append(where, cond)
		args = append(args, vals...)
	}
	if f.Host != "" {
		add(`EXISTS (SELECT 1 FROM finding_hosts fh WHERE fh.finding_id = fnd.id `+
			`AND fh.host LIKE ? ESCAPE '\')`, "%"+escapeLike(f.Host)+"%")
	}
	if f.Service != "" {
		add(`fnd.service LIKE ? ESCAPE '\'`, "%"+escapeLike(f.Service)+"%")
	}
	if f.Severity != "" {
		add("fnd.severity = ?", f.Severity)
	}
	if f.Kind != "" {
		add("fnd.kind = ?", f.Kind)
	}
	if f.Query != "" {
		add(`fnd.title LIKE ? ESCAPE '\'`, "%"+escapeLike(f.Query)+"%")
	}
	if f.From != "" {
		add("r.log_date >= ?", f.From)
	}
	if f.To != "" {
		add("r.log_date <= ?", f.To)
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Query(
		"SELECT fnd.id, fnd.run_id, r.log_date, fnd.kind, COALESCE(fnd.severity, ''), "+
			"fnd.title, COALESCE(fnd.service, ''), "+
			"COALESCE((SELECT GROUP_CONCAT(fh.host, ', ') FROM finding_hosts fh "+
			"WHERE fh.finding_id = fnd.id), ''), "+
			"(SELECT COUNT(*) FROM feedback fb WHERE fb.finding_id = fnd.id AND fb.verdict = 'worked'), "+
			"(SELECT COUNT(*) FROM feedback fb WHERE fb.finding_id = fnd.id AND fb.verdict = 'didnt_work') "+
			"FROM findings fnd JOIN runs r ON fnd.run_id = r.id "+
			"WHERE "+strings.Join(where, " AND ")+" "+
			"ORDER BY r.log_date DESC, fnd.id LIMIT ? OFFSET ?",
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FindingSummary
	for rows.Next() {
		fs := &FindingSummary{}
		if err := rows.Scan(&fs.ID, &fs.RunID, &fs.LogDate, &fs.Kind, &fs.Severity,
			&fs.Title, &fs.Service, &fs.Hosts, &fs.Worked, &fs.DidntWork); err != nil {
			return nil, err
		}
		out = append(out, fs)
	}
	return out, rows.Err()
}

// FindingDetail is one finding in full: the promoted columns joined to the
// run, the host list, and the payload unmarshalled per kind (Issue for kind
// 'issue', Anomaly for the rest). The json tags serve the CLI's --json
// output.
type FindingDetail struct {
	ID       int64             `json:"id"`
	RunID    int64             `json:"run_id"`
	LogDate  string            `json:"log_date"`
	Model    string            `json:"model"` // '' when the run was --no-llm
	Kind     string            `json:"kind"`
	Severity string            `json:"severity"`
	Title    string            `json:"title"`
	Service  string            `json:"service"`
	Hosts    []string          `json:"hosts"`
	Issue    *IssuePayload     `json:"issue,omitempty"`
	Anomaly  *ExplainedAnomaly `json:"anomaly,omitempty"`
}

// GetFinding loads one finding by id; a missing id returns sql.ErrNoRows.
func (s *LibraryStore) GetFinding(id int64) (*FindingDetail, error) {
	d := &FindingDetail{}
	var model sql.NullString
	var hosts, payload string
	err := s.db.QueryRow(
		"SELECT fnd.id, fnd.run_id, r.log_date, COALESCE(r.model, ''), fnd.kind, "+
			"COALESCE(fnd.severity, ''), fnd.title, COALESCE(fnd.service, ''), "+
			"COALESCE((SELECT GROUP_CONCAT(fh.host, ',') FROM finding_hosts fh "+
			"WHERE fh.finding_id = fnd.id), ''), fnd.payload "+
			"FROM findings fnd JOIN runs r ON fnd.run_id = r.id WHERE fnd.id = ?", id).
		Scan(&d.ID, &d.RunID, &d.LogDate, &model, &d.Kind, &d.Severity,
			&d.Title, &d.Service, &hosts, &payload)
	if err != nil {
		return nil, err
	}
	d.Model = model.String
	if hosts != "" {
		d.Hosts = strings.Split(hosts, ",")
	}
	if d.Kind == "issue" {
		d.Issue = &IssuePayload{}
		err = json.Unmarshal([]byte(payload), d.Issue)
	} else {
		d.Anomaly = &ExplainedAnomaly{}
		err = json.Unmarshal([]byte(payload), d.Anomaly)
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

// ErrBadVerdict rejects any verdict other than the two the schema allows.
var ErrBadVerdict = errors.New("verdict must be 'worked' or 'didnt_work'")

// RecordFeedback upserts one user's verdict on a finding (userID nil is the
// single anonymous vote). A re-vote always updates verdict and created_at;
// an empty comment KEEPS the existing one (owner decision 2026-08-28: the
// UI's comment box is blank on every visit, so a later verdict flip must
// not wipe the voter's own note). There is no comment-clearing path.
func (s *LibraryStore) RecordFeedback(findingID int64, userID *int64, verdict, comment string) error {
	if verdict != "worked" && verdict != "didnt_work" {
		return ErrBadVerdict
	}
	var commentVal, userVal any
	if comment != "" {
		commentVal = comment
	}
	if userID != nil {
		userVal = *userID
	}
	_, err := s.db.Exec(
		"INSERT INTO feedback (finding_id, user_id, verdict, comment, created_at) "+
			"VALUES (?, ?, ?, ?, ?) "+
			"ON CONFLICT (finding_id, COALESCE(user_id, 0)) "+
			"DO UPDATE SET verdict = excluded.verdict, "+
			"comment = COALESCE(excluded.comment, feedback.comment), "+
			"created_at = excluded.created_at",
		findingID, userVal, verdict, commentVal,
		time.Now().UTC().Format(time.RFC3339))
	return err
}

// FeedbackRow is one recorded verdict, with the voter's username joined
// (” for the anonymous vote).
type FeedbackRow struct {
	UserID    *int64
	Username  string
	Verdict   string
	Comment   string
	CreatedAt string
}

// FeedbackFor lists a finding's feedback, newest first.
func (s *LibraryStore) FeedbackFor(findingID int64) ([]*FeedbackRow, error) {
	rows, err := s.db.Query(
		"SELECT fb.user_id, COALESCE(u.username, ''), fb.verdict, "+
			"COALESCE(fb.comment, ''), fb.created_at "+
			"FROM feedback fb LEFT JOIN users u ON fb.user_id = u.id "+
			"WHERE fb.finding_id = ? ORDER BY fb.created_at DESC, fb.id DESC",
		findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FeedbackRow
	for rows.Next() {
		fr := &FeedbackRow{}
		var userID sql.NullInt64
		if err := rows.Scan(&userID, &fr.Username, &fr.Verdict, &fr.Comment, &fr.CreatedAt); err != nil {
			return nil, err
		}
		if userID.Valid {
			fr.UserID = &userID.Int64
		}
		out = append(out, fr)
	}
	return out, rows.Err()
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
