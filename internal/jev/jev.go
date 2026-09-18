// Package jev is a stdlib-only client for TypeSafe's System One API (the
// model called Jev): one JSON POST with a state object and a map of typed
// questions, back come probabilities. It generates no text. The project
// uses it to score message shapes for "is this routine" (ant ADR srg-FGSKN
// for the evaluation, srg-uHwCr for the decisions). Only the noul
// (probability of yes) answer is decoded; choice and score answers are
// kept raw for a later caller.
//
// Verified against the live endpoint on 2026-09-18: the object-form
// instructions and criteria from the vendor's SDK examples are accepted
// over plain REST, and the reply carries model, answers and usage.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ohnotnow/syslog-reporter-go/internal/llm"
)

const (
	// DefaultModel is the vendor's floating alias; SYSLOG_JEV_MODEL pins one.
	DefaultModel = "jev-latest"
	envKey       = "TYPESAFE_API_KEY"
	envModel     = "SYSLOG_JEV_MODEL"
	maxAttempts  = 5
	maxBodyInErr = 500
)

var (
	// BaseURL is a variable so tests can point it at an httptest server.
	BaseURL = "https://api.typesafe.ai/v1/systemone"
	// HTTPClient carries the per-call timeout.
	HTTPClient = &http.Client{Timeout: 60 * time.Second}
	// retryBase is the first backoff; tests shrink it.
	retryBase = time.Second
)

// Question is one typed question. Type is "noul", "choice" or "score";
// Instructions and Criteria take the vendor's object forms verbatim
// (question / inspect / compare / focus; what / not_for / examples).
type Question struct {
	Type         string         `json:"type"`
	Instructions map[string]any `json:"instructions"`
	Criteria     any            `json:"criteria"`
}

// Response is the decoded reply. Answers are left raw per question so a
// caller decodes only the type it asked for.
type Response struct {
	Model   string                     `json:"model"`
	Answers map[string]json.RawMessage `json:"answers"`
	Usage   Usage                      `json:"usage"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Noul decodes the probability of yes for the named noul question.
func Noul(r Response, name string) (float64, error) {
	raw, ok := r.Answers[name]
	if !ok {
		return 0, fmt.Errorf("jev: no answer named %q in the reply", name)
	}
	var a struct {
		Type string   `json:"type"`
		Noul *float64 `json:"noul"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return 0, fmt.Errorf("jev: answer %q: %w", name, err)
	}
	if a.Type != "noul" || a.Noul == nil {
		return 0, fmt.Errorf("jev: answer %q is not a noul answer (type %q)", name, a.Type)
	}
	return *a.Noul, nil
}

// CheckCredentials fails fast when the key is unset, for startup checks.
func CheckCredentials() error {
	if os.Getenv(envKey) == "" {
		return fmt.Errorf("jev needs %s set", envKey)
	}
	return nil
}

// Model is the model id a call will use.
func Model() string {
	if m := os.Getenv(envModel); m != "" {
		return m
	}
	return DefaultModel
}

// Ask sends one state with its questions and returns the reply. The
// marshalled state passes through llm.Redact (SYSLOG_REDACT) before it
// leaves the box. 429 and 5xx are retried with exponential backoff from
// retryBase, honouring a Retry-After in seconds when the server sends
// one; other statuses fail at once with the start of the body in the
// error.
func Ask(ctx context.Context, state any, questions map[string]Question) (Response, error) {
	if err := CheckCredentials(); err != nil {
		return Response{}, err
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return Response{}, fmt.Errorf("jev: marshalling state: %w", err)
	}
	body, err := json.Marshal(map[string]any{
		"model":     Model(),
		"state":     json.RawMessage(llm.Redact(string(stateJSON))),
		"questions": questions,
	})
	if err != nil {
		return Response{}, fmt.Errorf("jev: marshalling request: %w", err)
	}
	delay := retryBase
	for attempt := 1; ; attempt++ {
		resp, err := post(ctx, body)
		if err == nil {
			return resp, nil
		}
		var re *retryable
		if !errors.As(err, &re) || attempt == maxAttempts {
			return Response{}, err
		}
		wait := delay
		if re.after > 0 {
			wait = re.after
		}
		select {
		case <-ctx.Done():
			return Response{}, ctx.Err()
		case <-time.After(wait):
		}
		delay *= 2
	}
}

// retryable marks a 429/5xx or transport failure worth another attempt.
type retryable struct {
	err   error
	after time.Duration
}

func (r *retryable) Error() string { return r.err.Error() }
func (r *retryable) Unwrap() error { return r.err }

func post(ctx context.Context, body []byte) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv(envKey))
	req.Header.Set("Content-Type", "application/json")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return Response{}, &retryable{err: fmt.Errorf("jev: %w", err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Response{}, &retryable{err: fmt.Errorf("jev: reading reply: %w", err)}
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		var after time.Duration
		if secs, perr := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); perr == nil && secs > 0 {
			after = time.Duration(secs * float64(time.Second))
		}
		return Response{}, &retryable{err: fmt.Errorf("jev: HTTP %d: %s", resp.StatusCode, head(data)), after: after}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Response{}, fmt.Errorf("jev: HTTP %d: %s", resp.StatusCode, head(data))
	}
	var out Response
	if err := json.Unmarshal(data, &out); err != nil {
		return Response{}, fmt.Errorf("jev: decoding reply: %w (%s)", err, head(data))
	}
	return out, nil
}

func head(data []byte) string {
	if len(data) > maxBodyInErr {
		return string(data[:maxBodyInErr]) + "..."
	}
	return string(data)
}
