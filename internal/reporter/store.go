package reporter

// The persisted daily aggregate store: the baseline of per-(host, program,
// window) counts that outlives the rotated raw log. Schema and pragmas are
// handled by the shared open path in migrate.go.

import (
	"database/sql"
	"time"
)

const DefaultKeepDays = 90

func isoDate(t time.Time) string {
	return t.Format("2006-01-02")
}

// AggregateStore is a tiny SQLite-backed store of per-(host, program, window)
// daily counts.
type AggregateStore struct {
	db *sql.DB
}

func OpenAggregateStore(path string) (*AggregateStore, error) {
	db, err := openDatabase(path)
	if err != nil {
		return nil, err
	}
	return &AggregateStore{db: db}, nil
}

func (s *AggregateStore) Close() error {
	return s.db.Close()
}

// WriteAggregates persists a day's counts. Idempotent: re-running a day
// REPLACES it wholesale (the day's old rows are deleted first, so a re-run
// with fewer keys leaves no stale rows to contaminate the baseline).
// Returns the number of rows written.
func (s *AggregateStore) WriteAggregates(logDate time.Time, counts map[AggKey]int) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	iso := isoDate(logDate)
	if _, err := tx.Exec("DELETE FROM aggregates WHERE date = ?", iso); err != nil {
		tx.Rollback()
		return 0, err
	}
	stmt, err := tx.Prepare(
		"INSERT INTO aggregates (date, host, program, window, count) " +
			"VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	for k, n := range counts {
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
	return len(counts), nil
}

// HistoryPairTotals returns per-(host, program) day totals over the window
// [before-lookback, before-1]. beforeDate is excluded so a day never sits in
// its own baseline.
func (s *AggregateStore) HistoryPairTotals(beforeDate time.Time, lookbackDays int) (map[PairKey]map[string]int, error) {
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
	result := map[PairKey]map[string]int{}
	for rows.Next() {
		var host, program, day string
		var total int
		if err := rows.Scan(&host, &program, &day, &total); err != nil {
			return nil, err
		}
		key := PairKey{Host: host, Program: program}
		if result[key] == nil {
			result[key] = map[string]int{}
		}
		result[key][day] = total
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

// Prune drops rows older than keepDays (judged against the wall clock, not
// the slice date) so the file stays small. Returns rows removed.
func (s *AggregateStore) Prune(keepDays int) (int, error) {
	cutoff := isoDate(time.Now().AddDate(0, 0, -keepDays))
	res, err := s.db.Exec("DELETE FROM aggregates WHERE date < ?", cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
