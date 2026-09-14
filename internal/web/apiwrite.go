package web

// The sysadmin API's write endpoints (ait srg-Kj5Q8.6): mute a finding by
// id, and record feedback. Both name the token's user.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ohnotnow/syslog-reporter-go/internal/reporter"
)

const maxReasonRunes = 200

// apiParams reads the request body as JSON (Content-Type application/json)
// or as a form, into a flat string map. Either is fine from curl.
func apiParams(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	limitForm(w, r)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad JSON body")
			return nil, false
		}
		params := url.Values{}
		for k, v := range body {
			switch val := v.(type) {
			case string:
				params.Add(k, val)
			case []any: // a repeatable key, e.g. "host": ["a", "b"]
				for _, item := range val {
					params.Add(k, fmt.Sprint(item))
				}
			case nil:
			default:
				params.Add(k, fmt.Sprint(val))
			}
		}
		return params, true
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body")
		return nil, false
	}
	return r.PostForm, true
}

// cleanReason validates the operator's reason: present, one line, bounded.
func cleanReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", errors.New("reason is required")
	}
	if utf8.RuneCountInString(reason) > maxReasonRunes {
		return "", fmt.Errorf("reason too long (%d character limit)", maxReasonRunes)
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return "", errors.New("reason must be a single line without control characters")
		}
	}
	return reason, nil
}

// muteEntry is one known_knowns row as the API shows it: the shape the
// mute endpoint returns and the knowns list and delete endpoints reuse.
type muteEntry struct {
	ID          int64   `json:"id"`
	Host        string  `json:"host"`
	Program     string  `json:"program"`
	Match       string  `json:"match"`
	Reason      string  `json:"reason"`
	Added       string  `json:"added"`
	Expires     *string `json:"expires"`
	Source      string  `json:"source"`
	FindingID   *int64  `json:"finding_id"`
	CreatedBy   string  `json:"created_by"`
	TokenPrefix string  `json:"token_prefix"`
}

func newMuteEntry(e *reporter.KnownEntry) muteEntry {
	m := muteEntry{ID: e.ID, Host: e.Host, Program: e.Program, Match: e.Match, Reason: e.Reason,
		Source: e.Source, FindingID: e.FindingID, CreatedBy: e.CreatedBy, TokenPrefix: e.TokenPrefix}
	if e.Added != nil {
		m.Added = e.Added.Format("2006-01-02")
	}
	if e.Expires != nil {
		exp := e.Expires.Format("2006-01-02")
		m.Expires = &exp
	}
	return m
}

// POST /api/findings/{id}/mute - reason (required), expires (optional
// YYYY-MM-DD after today), host (optional, repeatable: narrows the mute to
// those of the finding's hosts), match (optional regex: drop only matching
// lines rather than all of the program's). Program comes from the finding,
// never the client (ant ADRs srg-yYpms, srg-gzXn6). Entries land in the
// known_knowns table with the caller's username and token prefix.
func (s *Server) handleAPIMute(w http.ResponseWriter, r *http.Request) {
	d := s.loadAPIFinding(w, r)
	if d == nil {
		return
	}
	params, ok := apiParams(w, r)
	if !ok {
		return
	}
	reason, err := cleanReason(params.Get("reason"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	var expires *time.Time
	if raw := strings.TrimSpace(params.Get("expires")); raw != "" {
		day, err := time.Parse("2006-01-02", raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "expires must be a date (YYYY-MM-DD)")
			return
		}
		if !day.After(time.Now().UTC().Truncate(24 * time.Hour)) {
			writeJSONError(w, http.StatusBadRequest, "expires must be after today")
			return
		}
		expires = &day
	}
	var hosts []string
	for _, h := range params["host"] {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	match := strings.TrimSpace(params.Get("match"))
	user, tok := apiUser(r), apiToken(r)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	inputs, err := reporter.DeriveKnownEntries(d, hosts, match, reason, today, expires)
	var notOnFinding *reporter.HostNotOnFindingError
	if errors.As(err, &notOnFinding) {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if errors.Is(err, reporter.ErrBadMatch) {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if errors.Is(err, reporter.ErrCannotDeriveProgram) {
		writeJSONError(w, http.StatusUnprocessableEntity,
			"cannot derive a program name for this finding; mute it on the box")
		return
	}
	if errors.Is(err, reporter.ErrCannotDeriveHost) {
		writeJSONError(w, http.StatusUnprocessableEntity,
			"a host on this finding is not a plain hostname; mute it on the box")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	for i := range inputs {
		inputs[i].CreatedBy, inputs[i].TokenPrefix = user.Username, tok.Prefix
	}
	// An identical active entry for this finding is not written twice.
	existing, err := s.lib.KnownEntriesForFinding(d.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	fresh := inputs[:0]
	for _, in := range inputs {
		dup := false
		for _, e := range reporter.NewKnownKnowns(existing, today).Active {
			if e.Host == in.Host && e.Program == in.Program && e.Match == in.Match {
				dup = true
				break
			}
		}
		if !dup {
			fresh = append(fresh, in)
		}
	}
	if len(fresh) == 0 {
		writeJSONError(w, http.StatusConflict, "already muted")
		return
	}
	// The cap counts attempts that would write, checked before the write so
	// a refused call costs nothing.
	key := strconv.FormatInt(tok.ID, 10)
	if blocked, wait := s.mutes.blocked(key); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSONError(w, http.StatusTooManyRequests,
			fmt.Sprintf("mute limit reached (%d per token per 24 hours)", s.cfg.MuteLimit))
		return
	}
	written, err := s.lib.AddKnownEntries(fresh)
	if err != nil {
		s.cfg.logWarn("mute of finding %d by %s failed: %v", d.ID, user.Username, err)
		writeJSONError(w, http.StatusInternalServerError, "could not store the mute")
		return
	}
	s.mutes.record(key)
	s.cfg.logWarn("finding %d muted by %s: %d new known-knowns entries", d.ID, user.Username, len(written))
	out := make([]muteEntry, 0, len(written))
	for _, e := range written {
		out = append(out, newMuteEntry(e))
	}
	writeJSON(w, http.StatusCreated, map[string]any{"entries": out})
}

// POST /api/findings/{id}/feedback - verdict (worked | didnt_work), comment.
func (s *Server) handleAPIFeedback(w http.ResponseWriter, r *http.Request) {
	d := s.loadAPIFinding(w, r)
	if d == nil {
		return
	}
	params, ok := apiParams(w, r)
	if !ok {
		return
	}
	comment := strings.TrimSpace(params.Get("comment"))
	if utf8.RuneCountInString(comment) > maxCommentRunes {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("comment too long (%d character limit)", maxCommentRunes))
		return
	}
	user := apiUser(r)
	if err := s.lib.RecordFeedback(d.ID, &user.ID, params.Get("verdict"), comment); err != nil {
		if errors.Is(err, reporter.ErrBadVerdict) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	s.writeAPIFindingDetail(w, d)
}

// DELETE /api/knowns/{id} - remove one known-knowns entry. Deletes are not
// counted against the mute cap: un-silencing fails loud, not quiet.
func (s *Server) handleAPIUnmuteEntry(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no such known-knowns entry")
		return
	}
	ok, err := s.lib.DeleteKnownEntry(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no such known-knowns entry")
		return
	}
	s.cfg.logWarn("known-knowns entry %d removed by %s", id, apiUser(r).Username)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": 1, "id": id})
}

// DELETE /api/findings/{id}/mute - remove every entry this finding's mutes
// created. 404 only for a missing finding; a finding with no entries is an
// idempotent undo, deleted 0.
func (s *Server) handleAPIUnmuteFinding(w http.ResponseWriter, r *http.Request) {
	d := s.loadAPIFinding(w, r)
	if d == nil {
		return
	}
	entries, err := s.lib.KnownEntriesForFinding(d.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	ids := []int64{}
	for _, e := range entries {
		ok, err := s.lib.DeleteKnownEntry(e.ID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "server error")
			return
		}
		if ok {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) > 0 {
		s.cfg.logWarn("finding %d unmuted by %s: %d entries removed", d.ID, apiUser(r).Username, len(ids))
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": len(ids), "ids": ids})
}
