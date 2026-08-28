# Technical Overview

Last updated: 2026-08-28

## What this is

A command-line tool that turns a noisy org-wide syslog into a short,
prioritised report of genuine issues (each with paste-ready investigate/fix
commands) plus a statistical anomaly check, intended as a morning email for a
sysadmin team. Input is raw rsyslog text or an NDJSON dump from an ELK
cluster. A plain-language tour for non-developers lives in
[HOW_IT_WORKS.md](HOW_IT_WORKS.md).

This is the production implementation. The pipeline was first proven in a
Python project ([syslog_reporter](https://github.com/ohnotnow/syslog_reporter),
now archived); this Go version is a drop-in replacement for it - identical
SQLite schema (accumulated baseline history carries over), environment
variables, CLI flags, `known_knowns.toml` format, and report layout, so a
cron host can swap the binary in without losing anything. The only deliberate
report differences: plain hyphens where the Python literals had em dashes,
and a model-attribution footer on both report layouts.

## Stack

- Go (stdlib-first; `flag`, `net/smtp`, `database/sql`, `text/template`)
- modernc.org/sqlite (pure Go, no CGO, cross-compiles cleanly)
- Official provider SDKs: openai-go and anthropic-sdk-go
- pelletier/go-toml (known-knowns file), joho/godotenv (.env loading)
- Tests use the stdlib `testing` package only

## Directory structure

```
main.go                     CLI entry point; wires the pipeline
internal/reporter/
  pyfmt.go                  Python-semantics helpers (split, number formatting,
                            repr); report parity with the original pipeline
                            depends on these, pinned by CPython-captured vectors
  filters_data.go           the noise filter rule list (edit per estate)
  filter.go                 LogFilter: deterministic noise removal
  knowns.go                 known-knowns TOML suppression
  anomaly.go                line parsing, robust z-scores, peer detector,
                            anomaly combining
  store.go                  SQLite daily-aggregate store
  baseline.go               host-vs-own-history detector (incl. "gone silent")
  temporal.go               time-of-day burst detector
  elksource.go              ELK NDJSON dump renderer (dump -> rsyslog lines)
  models.go                 issue / resolution / explained-anomaly models
  llmagents.go prompts/     the four LLM agents + embedded system prompts
  report.go                 both report layouts (digest + full attachment)
  emailer.go                SMTP send: digest body + markdown attachment
internal/llm/               provider seam: model-string prefix -> official SDK
tools/elk_dump.py           day-bounded NDJSON dumper for an ELK cluster
                            (stdlib-only python3; runs on any box with read
                            access to the log store)
.github/workflows/          release build (six OS/arch targets on v* tags)
```

## Pipeline

Raw lines feed two branches that merge at the report:

```
raw log lines
   |
   +-- LogFilter --> filtered lines --> IssueDetector --> IssueList
   |                                        |
   |                                  IssueDeduplicator (merges cross-chunk dupes)
   |                                        |
   |                                  ResolutionAgent --> ResolutionList
   |                                                          |
   +-- PeerDetector.Aggregate() (RAW lines, no LLM)           |
             |                                                |
             +-> AggregateStore -> SQLite history --+         |
             +-> peer anomalies                     |         |
             +-> baseline anomalies  <--------------+         |
             +-> temporal anomalies  <--------------+         |
             |         |  (history-based two read SQLite)     |
             |   CombineAnomalies: dedupe, rank by |score|    |
             |         |                                      |
             |   AnomalyExplainer --> []ExplainedAnomaly      |
             |                            |                   |
             +----------------------------+--> ReportAgent <--+
                                                 |
                          email_body.md (digest) + email_attachment.md (full)
                                                 |
                                     EmailAgent (--send-email)
```

Anomaly detection runs on the RAW log, upstream of the filter, so it can see
the high-volume programs the denylist removes. Everything else runs on the
filtered log.

Operator-acknowledged "known knowns" (a gitignored TOML file) apply in two
places: the filter drops matching lines host-aware, and matching
(host, program) anomalies are muted before the explainer spends LLM money.
Suppression stays visible: the report footer lists which entries fired and
flags lapsed ones. Expiry compares against the slice date, not the wall
clock, so backfills behave historically.

## Anomaly detection

Three detectors feed one combined list, all sharing a robust median/MAD
z-score (mean-abs-dev fallback when MAD is zero), pure stdlib:

- **peer**: a host emits far more of a program than its fleet peers. Works
  from day one, no history needed.
- **baseline**: a host is unlike its own trailing-N-day normal - louder,
  quieter, or gone silent. Needs the SQLite history.
- **temporal**: a burst in a time-of-day window beyond what that host usually
  does at that time (the seasonality guard that stops morning lab reboots
  crying wolf). Needs history.

The history-based two are no-ops until the store has accumulated a week or
two of daily aggregates; `--no-llm` with `--date`/`--db` is the free backfill
tool. `CombineAnomalies` keeps one entry per (host, program), strongest
signal wins, so a colleague never gets the same host three times.

## LLM stages and provider routing

Model strings use the litellm format the pipeline has always used
(`openai/gpt-4o-mini`, `anthropic/claude-haiku-4-5-20251001`): the prefix
picks the official SDK, the rest passes through as the provider's model id.
`internal/llm.Complete` is the whole seam - four structured-output calls
exist in the entire pipeline (issue detection, dedupe, resolutions, anomaly
explanations), constrained by hand-written JSON schemas that mirror the data
models. OpenAI gets a strict `json_schema` response format; Anthropic gets
`output_config.format`.

`SYSLOG_REASONING_EFFORT` passes to OpenAI verbatim (`none` is right for
batch runs); for Anthropic it maps onto `output_config.effort`, with
`none`/`minimal` clamped to `low` (Anthropic's floor).

System prompts are embedded in the binary (`internal/reporter/prompts/`,
via `go:embed`), so there is nothing to ship but the one file. Report
prompts require a one-line `#` comment above every suggested command;
state-changing commands must start `# CHANGES STATE:`.

Both report layouts end with `_Analysis by <model>_` when the LLM stages
ran, so teams comparing models can tell reports apart.

## Configuration

### CLI flags

```
logfile          positional: path to the syslog file; omit (or pass --) to
                 read raw text from stdin. --file is an alternative spelling.
--model          model to use, litellm format (default SYSLOG_DEFAULT_MODEL)
--format         auto | raw | ndjson. auto picks ndjson for *.ndjson(.gz)
                 paths, raw otherwise (stdin is always raw)
--date           ISO date (YYYY-MM-DD) the log slice covers, keying the
                 aggregate store. Defaults to yesterday, or for NDJSON input
                 to the date found in the data
--db             SQLite aggregate-store path (default syslog_aggregates.db)
--known-knowns   path to the known-knowns TOML (default known_knowns.toml;
                 a missing file just means none)
--no-store       don't persist aggregates or run the history-based
                 detectors (peer comparison still runs)
--no-llm         skip every LLM stage so the run costs nothing
--send-email     email the report; --recipients takes a comma-separated
                 list (falls back to SYSLOG_SMTP_RECIPIENTS)
--dump-filtered  print the post-filter log lines and exit: the quickest way
                 to see what your ignore rules are letting through when
                 tuning the filter for your estate
--debug          extra progress detail on stderr
--version        print the version and exit
```

### Environment variables

Read from the environment or a `.env` beside the working directory
(never commit one):

- `SYSLOG_DEFAULT_MODEL` default model, litellm format
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` for whichever provider is used
- `SYSLOG_REASONING_EFFORT` reasoning effort, see above; unset = provider default
- `SYSLOG_SMTP_SERVER`, `SYSLOG_SMTP_SENDER`, `SYSLOG_SMTP_RECIPIENTS` for
  `--send-email` (recipients ride the SMTP envelope as BCC)
- `SYSLOG_DB_PATH` SQLite aggregate-store path (default
  `syslog_aggregates.db`; CLI `--db` overrides; `--no-store` skips
  persistence and the history-based detectors)
- `SYSLOG_DB_KEEP_DAYS` store retention, pruned each run (default 90)
- `SYSLOG_BLANKET_IGNORE` comma-separated substrings appended to the filter
  at runtime - the home for estate-identifying entries (hostnames, internal
  IPs) so the committed filter stays estate-neutral
- `SYSLOG_KNOWN_KNOWNS` path to the known-knowns TOML (default
  `known_knowns.toml`; CLI `--known-knowns` overrides; missing file means none)
- `ELK_URL`, `ELK_USERNAME`/`ELK_PASSWORD` or `ELK_API_KEY`, `ELK_INDEX` are
  read by `tools/elk_dump.py` only

The store is keyed by the date the log slice covers: `--date YYYY-MM-DD`,
defaulting to yesterday or, for NDJSON input, to the date found in the data.
`--no-llm` skips every LLM stage so a run costs nothing; the filter, the
three detectors and the store writes still happen, and the report says the
analysis was skipped rather than pretending the day was clean.

If your estate forwards syslog to an ELK cluster, `tools/elk_dump.py`
pulls one day of documents into the NDJSON format the tool ingests. It is
stdlib-only python3, needs read-only access to the log store, and is run
on whichever box has that access; see the usage notes at the top of the
script.

## Testing

- Stdlib `testing`; run with `go test ./...`.
- Pure logic is unit-tested; LLM round-trips are validated by live runs, not
  mocks. The store/baseline/temporal tests seed in-memory SQLite with
  synthetic history.
- `pyfmt.go` helpers (Python split semantics, number formatting, `repr`
  quoting) are pinned to CPython-captured vectors; if a report number ever
  mismatches the original pipeline, look there first.
- Test fixtures use fictional hostnames only. Real estate names live solely
  in gitignored dumps, reports and the `.env`.

## Local development

```bash
go build -o syslog-reporter .
go test ./...
./syslog-reporter dump.ndjson.gz --no-llm --db /tmp/scratch.db   # free run
./syslog-reporter dump.ndjson.gz --model openai/gpt-4o-mini      # full run
./syslog-reporter --dump-filtered dump.ndjson.gz                 # filter debug
```

## Releases

Pushing a `v*` tag builds linux/darwin/windows on amd64/arm64, generates
SHA256SUMS, and attaches everything to a GitHub release. The tag is stamped
into the binary (`syslog-reporter --version`).
