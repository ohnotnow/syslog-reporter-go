package web

// The findings library list page (ait srg-2KY5X.6): browse, search and
// filter the persisted findings. The full page and the htmx partial share
// the same template blocks; a request carrying HX-Request gets just the
// results region, plus an out-of-band innerHTML update of the status line.
// That status line is the aria-live region and must PERSIST across swaps
// (a replaced live-region node is not reliably announced), which is why it
// sits outside the swap target and is only ever updated in place.

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const findingsPageSize = 50

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
