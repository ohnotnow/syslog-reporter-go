package web

// The sysadmin API's read endpoints (ait srg-Kj5Q8.5, ant ADR srg-yYpms).
// Rows out, no query language: Claude does the reasoning. Every handler
// here sits behind bearerAuth (see Handler in server.go).

import (
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const (
	apiDefaultLimit = 50
	apiMaxLimit     = 500
	// apiMaxSpanDays bounds an aggregates query: a year of the whole estate
	// is already a lot of rows for anyone to reason over.
	apiMaxSpanDays = 366
)

// apiFeedback is a feedback row as the API shows it: the username, never
// the user id.
type apiFeedback struct {
	User      string `json:"user"` // '' for the anonymous singleton
	Verdict   string `json:"verdict"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
}

func toAPIFeedback(rows []*reporter.FeedbackRow) []apiFeedback {
	out := make([]apiFeedback, 0, len(rows))
	for _, r := range rows {
		out = append(out, apiFeedback{User: r.Username, Verdict: r.Verdict,
			Comment: r.Comment, CreatedAt: r.CreatedAt})
	}
	return out
}

// parseAPIDate accepts YYYY-MM-DD or empty; anything else is a 400.
func parseAPIDate(w http.ResponseWriter, name, value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, true
	}
	d, err := time.Parse("2006-01-02", value)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, name+" must be a date (YYYY-MM-DD)")
		return time.Time{}, false
	}
	return d, true
}

func parseAPIInt(w http.ResponseWriter, name, value string, fallback int) (int, bool) {
	if value == "" {
		return fallback, true
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		writeJSONError(w, http.StatusBadRequest, name+" must be a non-negative integer")
		return 0, false
	}
	return n, true
}

// GET /api/findings - the same filters as 'findings list'.
func (s *Server) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, ok := parseAPIDate(w, "since", q.Get("since")); !ok {
		return
	}
	if _, ok := parseAPIDate(w, "until", q.Get("until")); !ok {
		return
	}
	limit, ok := parseAPIInt(w, "limit", q.Get("limit"), apiDefaultLimit)
	if !ok {
		return
	}
	if limit == 0 || limit > apiMaxLimit {
		limit = apiMaxLimit
	}
	offset, ok := parseAPIInt(w, "offset", q.Get("offset"), 0)
	if !ok {
		return
	}
	if err := reporter.CheckRunKindFilter(q.Get("run_kind")); err != nil {
		writeJSONError(w, http.StatusBadRequest, "run_kind must be daily or digest")
		return
	}
	results, err := s.lib.SearchFindings(reporter.FindingFilter{
		Host:     q.Get("host"),
		Service:  q.Get("service"),
		Severity: q.Get("severity"),
		Kind:     q.Get("kind"),
		RunKind:  q.Get("run_kind"),
		Query:    q.Get("q"),
		From:     q.Get("since"),
		To:       q.Get("until"),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	if results == nil {
		results = []*reporter.FindingSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": results, "limit": limit, "offset": offset})
}

// loadAPIFinding resolves {id} or writes the 404 / 500 itself.
func (s *Server) loadAPIFinding(w http.ResponseWriter, r *http.Request) *reporter.FindingDetail {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no such finding")
		return nil
	}
	d, err := s.lib.GetFinding(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "no such finding")
		return nil
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return nil
	}
	return d
}

// writeAPIFindingDetail is the show shape, shared with the feedback write.
func (s *Server) writeAPIFindingDetail(w http.ResponseWriter, d *reporter.FindingDetail) {
	feedback, err := s.lib.FeedbackFor(d.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding": d, "feedback": toAPIFeedback(feedback)})
}

// GET /api/findings/{id}
func (s *Server) handleAPIFinding(w http.ResponseWriter, r *http.Request) {
	if d := s.loadAPIFinding(w, r); d != nil {
		s.writeAPIFindingDetail(w, d)
	}
}

// GET /api/runs?since=&until= - default the last 30 days ending today.
func (s *Server) handleAPIRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, until := q.Get("since"), q.Get("until")
	if _, ok := parseAPIDate(w, "since", since); !ok {
		return
	}
	if _, ok := parseAPIDate(w, "until", until); !ok {
		return
	}
	if since == "" && until == "" {
		today := time.Now().UTC()
		since = today.AddDate(0, 0, -30).Format("2006-01-02")
		until = today.Format("2006-01-02")
	}
	runs, err := s.lib.ListRuns(since, until)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	if runs == nil {
		runs = []*reporter.RunSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "since": since, "until": until})
}

// GET /api/aggregates?since=&until=&host=&program= - both dates required.
func (s *Server) handleAPIAggregates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("since") == "" || q.Get("until") == "" {
		writeJSONError(w, http.StatusBadRequest, "since and until are required (YYYY-MM-DD)")
		return
	}
	since, ok := parseAPIDate(w, "since", q.Get("since"))
	if !ok {
		return
	}
	until, ok := parseAPIDate(w, "until", q.Get("until"))
	if !ok {
		return
	}
	if until.Before(since) {
		writeJSONError(w, http.StatusBadRequest, "until is before since")
		return
	}
	if until.Sub(since) > apiMaxSpanDays*24*time.Hour {
		writeJSONError(w, http.StatusBadRequest, "span too long (at most 366 days)")
		return
	}
	rows, err := s.lib.DailyTotals(since, until, q.Get("host"), q.Get("program"))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	if rows == nil {
		rows = []*reporter.DailyTotal{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

// GET /api/knowns?host=&finding_id=&all=1 - every known-knowns entry with
// its provenance, by id. Active only (judged against today UTC) unless
// all=1. host is exact; finding_id narrows to one mute's entries.
func (s *Server) handleAPIKnowns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var findingID *int64
	if raw := q.Get("finding_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "finding_id must be an integer")
			return
		}
		findingID = &id
	}
	entries, err := s.lib.ListKnownEntries()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	kk := reporter.NewKnownKnowns(entries, time.Now().UTC().Truncate(24*time.Hour))
	entries = kk.Active
	if q.Get("all") == "1" {
		entries = append(entries, kk.Expired...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	}
	out := []muteEntry{}
	for _, e := range entries {
		if h := q.Get("host"); h != "" && e.Host != h {
			continue
		}
		if findingID != nil && (e.FindingID == nil || *e.FindingID != *findingID) {
			continue
		}
		out = append(out, newMuteEntry(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}
