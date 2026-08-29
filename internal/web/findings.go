package web

// The findings library list page (ait srg-2KY5X.6): browse, search and
// filter the persisted findings. The full page and the htmx partial share
// the same template blocks; a request carrying HX-Request gets just the
// results region, plus an out-of-band innerHTML update of the status line.
// That status line is the aria-live region and must PERSIST across swaps
// (a replaced live-region node is not reliably announced), which is why it
// sits outside the swap target and is only ever updated in place.

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const findingsPageSize = 50

// maxCommentRunes bounds a feedback note (srg-so8ja.8): long enough for a
// real war story, short enough that the form cannot be used as a dump.
const maxCommentRunes = 2000

type findingsFilters struct {
	Query    string
	Host     string
	Service  string
	Severity string
	Kind     string
	From     string
	To       string
}

func (f findingsFilters) active() bool {
	return f != findingsFilters{}
}

// values rebuilds the shareable query string for pagination links.
func (f findingsFilters) values(page int) string {
	v := url.Values{}
	set := func(key, val string) {
		if val != "" {
			v.Set(key, val)
		}
	}
	set("q", f.Query)
	set("host", f.Host)
	set("service", f.Service)
	set("severity", f.Severity)
	set("kind", f.Kind)
	set("from", f.From)
	set("to", f.To)
	if page > 1 {
		v.Set("page", strconv.Itoa(page))
	}
	return v.Encode()
}

type findingsView struct {
	Filters    findingsFilters
	Filtered   bool // any filter active; picks the right empty state
	Results    []*reporter.FindingSummary
	Page       int
	HasMore    bool
	PrevQuery  string // query string for the previous-page link ("" = none)
	NextQuery  string // query string for the next-page link ("" = none)
	StatusLine string
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	filters := findingsFilters{
		Query:    strings.TrimSpace(q.Get("q")),
		Host:     strings.TrimSpace(q.Get("host")),
		Service:  strings.TrimSpace(q.Get("service")),
		Severity: q.Get("severity"),
		Kind:     q.Get("kind"),
		From:     q.Get("from"),
		To:       q.Get("to"),
	}
	offset := (page - 1) * findingsPageSize
	// One row beyond the page tells us whether a next page exists.
	results, err := s.lib.SearchFindings(reporter.FindingFilter{
		Query:    filters.Query,
		Host:     filters.Host,
		Service:  filters.Service,
		Severity: filters.Severity,
		Kind:     filters.Kind,
		From:     filters.From,
		To:       filters.To,
		Limit:    findingsPageSize + 1,
		Offset:   offset,
	})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	hasMore := len(results) > findingsPageSize
	if hasMore {
		results = results[:findingsPageSize]
	}
	view := findingsView{
		Filters:    filters,
		Filtered:   filters.active(),
		Results:    results,
		Page:       page,
		HasMore:    hasMore,
		StatusLine: findingsStatusLine(len(results), offset, hasMore, filters.active()),
	}
	if page > 1 {
		view.PrevQuery = filters.values(page - 1)
	}
	if hasMore {
		view.NextQuery = filters.values(page + 1)
	}
	d := pageData{
		Version: s.cfg.Version,
		Path:    "/",
		User:    s.auth.CurrentUser(r),
		Data:    view,
	}
	if r.Header.Get("HX-Request") != "" {
		renderBlock(w, "findings.html", "results-partial", d)
		return
	}
	render(w, "findings.html", d)
}

// detailView is the finding detail page plus its feedback state. The
// comment box is deliberately never prefilled: a recorded note's home is
// the Notes list (owner decision 2026-08-28).
type detailView struct {
	Finding   *reporter.FindingDetail
	Feedback  []*reporter.FeedbackRow
	Worked    int
	DidntWork int
	YourVote  string // '' until this visitor has voted
	Anonymous bool   // auth mode none: one shared anonymous vote, honest copy
	HasNotes  bool   // any feedback row carries a comment
}

func (s *Server) buildDetailView(r *http.Request, d *reporter.FindingDetail) (detailView, error) {
	feedback, err := s.lib.FeedbackFor(d.ID)
	if err != nil {
		return detailView{}, err
	}
	view := detailView{
		Finding:   d,
		Feedback:  feedback,
		Anonymous: s.auth.CurrentUser(r) == nil,
	}
	user := s.auth.CurrentUser(r)
	for _, row := range feedback {
		switch row.Verdict {
		case "worked":
			view.Worked++
		case "didnt_work":
			view.DidntWork++
		}
		if row.Comment != "" {
			view.HasNotes = true
		}
		mine := (user == nil && row.UserID == nil) ||
			(user != nil && row.UserID != nil && *row.UserID == user.ID)
		if mine {
			view.YourVote = row.Verdict
		}
	}
	return view, nil
}

// loadFinding parses {id} and fetches the row, rendering the 404 page (and
// returning nil) when either fails.
func (s *Server) loadFinding(w http.ResponseWriter, r *http.Request) *reporter.FindingDetail {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var d *reporter.FindingDetail
		if d, err = s.lib.GetFinding(id); err == nil {
			return d
		}
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange) {
		renderStatus(w, "notfound.html", http.StatusNotFound, pageData{
			Version: s.cfg.Version,
			Path:    r.URL.Path,
			User:    s.auth.CurrentUser(r),
		})
		return nil
	}
	http.Error(w, "server error", http.StatusInternalServerError)
	return nil
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	d := s.loadFinding(w, r)
	if d == nil {
		return
	}
	view, err := s.buildDetailView(r, d)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	render(w, "finding.html", pageData{
		Version: s.cfg.Version,
		Path:    r.URL.Path,
		User:    s.auth.CurrentUser(r),
		Data:    view,
	})
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	d := s.loadFinding(w, r)
	if d == nil {
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var userID *int64
	if user := s.auth.CurrentUser(r); user != nil {
		userID = &user.ID
	}
	verdict := r.PostFormValue("verdict")
	comment := strings.TrimSpace(r.PostFormValue("comment"))
	if utf8.RuneCountInString(comment) > maxCommentRunes {
		http.Error(w, fmt.Sprintf("comment too long (%d character limit)", maxCommentRunes),
			http.StatusBadRequest)
		return
	}
	if err := s.lib.RecordFeedback(d.ID, userID, verdict, comment); err != nil {
		if errors.Is(err, reporter.ErrBadVerdict) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") != "" {
		view, err := s.buildDetailView(r, d)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		renderBlock(w, "finding.html", "feedback-partial", pageData{
			Version: s.cfg.Version,
			Path:    r.URL.Path,
			User:    s.auth.CurrentUser(r),
			Data:    view,
		})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/findings/%d", d.ID), http.StatusSeeOther)
}

func findingsStatusLine(n, offset int, hasMore, filtered bool) string {
	switch {
	case n == 0 && filtered:
		return "No findings match these filters."
	case n == 0:
		return "No findings captured yet."
	case offset == 0 && !hasMore:
		if n == 1 {
			return "1 finding."
		}
		return fmt.Sprintf("%d findings.", n)
	default:
		line := fmt.Sprintf("Findings %d to %d", offset+1, offset+n)
		if hasMore {
			line += ", more available"
		}
		return line + "."
	}
}
