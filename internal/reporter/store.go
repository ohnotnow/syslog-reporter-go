package reporter

// Port of agents/aggregate_store.py: the persisted daily aggregate store, the
// baseline that outlives the rotated raw log. Same schema as the Python
// original so an accumulated syslog_aggregates.db carries straight over.
//
// Deliberately no WAL pragma: the Python original leaves SQLite's default
// rollback journal in place, WAL mode is a persistent property of the file,
// and a once-a-day single-writer batch gains nothing from it. Keeping the
// default preserves drop-in compatibility with a Python-created database.

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

const DefaultKeepDays = 90

const storeSchema = `
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
`

func isoDate(t time.Time) string {
	return t.Format("2006-01-02")
}

// AggregateStore is a tiny SQLite-backed store of per-(host, program, window)
// daily counts.
type AggregateStore struct {
	db *sql.DB
}

func OpenAggregateStore(path string) (*AggregateStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// Python's sqlite3.connect defaults to a 5 second busy timeout; match it.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(storeSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &AggregateStore{db: db}, nil
}

func (s *AggregateStore) Close() error {
	return s.db.Close()
}

// WriteAggregates persists a day's counts. Idempotent: re-running a day
// overwrites it. Returns the number of rows written.
func (s *AggregateStore) WriteAggregates(logDate time.Time, counts *Counts) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(
		"INSERT INTO aggregates (date, host, program, window, count) " +
			"VALUES (?, ?, ?, ?, ?) " +
			"ON CONFLICT (date, host, program, window) " +
			"DO UPDATE SET count = excluded.count")
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	iso := isoDate(logDate)
	for _, k := range counts.Keys() {
		n, _ := counts.Get(k)
		if _, err := stmt.Exec(iso, k.Host, k.Program, k.Window, n); err != nil {
			stmt.Close()
			tx.Rollback()
			return 0, err
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return counts.Len(), nil
}

// PairHistory holds per-(host, program) day totals in first-seen row order,
// mirroring the Python dict the SQL cursor built up.
type PairHistory struct {
	keys []PairKey
	m    map[PairKey]map[string]int
}

func (h *PairHistory) Keys() []PairKey { return h.keys }

func (h *PairHistory) Get(k PairKey) (map[string]int, bool) {
	days, ok := h.m[k]
	return days, ok
}

// HistoryPairTotals returns per-(host, program) day totals over the window
// [before-lookback, before-1]. beforeDate is excluded so a day never sits in
// its own baseline.
func (s *AggregateStore) HistoryPairTotals(beforeDate time.Time, lookbackDays int) (*PairHistory, error) {
	end := isoDate(beforeDate)
	start := isoDate(beforeDate.AddDate(0, 0, -lookbackDays))
	rows, err := s.db.Query(
		"SELECT host, program, date, SUM(count) FROM aggregates "+
			"WHERE date >= ? AND date < ? "+
			"GROUP BY host, program, date",
		start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &PairHistory{m: map[PairKey]map[string]int{}}
	for rows.Next() {
		var host, program, day string
		var total int
		if err := rows.Scan(&host, &program, &day, &total); err != nil {
			return nil, err
		}
		key := PairKey{Host: host, Program: program}
		if result.m[key] == nil {
			result.keys = append(result.keys, key)
			result.m[key] = map[string]int{}
		}
		result.m[key][day] = total
	}
	return result, rows.Err()
}

// HistoryWindowCounts returns per-(host, program, window) day counts over
// [before-lookback, before-1]. Keeping the time-of-day window lets the
// temporal detector compare like with like (10:00 today vs 10:00 on prior
// days) and not trip over morning reboots.
func (s *AggregateStore) HistoryWindowCounts(beforeDate time.Time, lookbackDays int) (map[AggKey]map[string]int, error) {
	end := isoDate(beforeDate)
	start := isoDate(beforeDate.AddDate(0, 0, -lookbackDays))
	rows, err := s.db.Query(
		"SELECT host, program, window, date, SUM(count) FROM aggregates "+
			"WHERE date >= ? AND date < ? "+
			"GROUP BY host, program, window, date",
		start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[AggKey]map[string]int{}
	for rows.Next() {
		var host, program, window, day string
		var total int
		if err := rows.Scan(&host, &program, &window, &day, &total); err != nil {
			return nil, err
		}
		key := AggKey{Host: host, Program: program, Window: window}
		if result[key] == nil {
			result[key] = map[string]int{}
		}
		result[key][day] = total
	}
	return result, rows.Err()
}

// Prune drops rows older than keepDays (judged against the wall clock, like
// the Python original) so the file stays small. Returns rows removed.
func (s *AggregateStore) Prune(keepDays int) (int, error) {
	cutoff := isoDate(time.Now().AddDate(0, 0, -keepDays))
	res, err := s.db.Exec("DELETE FROM aggregates WHERE date < ?", cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
