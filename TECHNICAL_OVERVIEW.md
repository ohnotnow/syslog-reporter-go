# Technical Overview

Last updated: 2026-08-29

## What this is

A command-line tool that turns a noisy org-wide syslog into a short,
prioritised report of genuine issues (each with paste-ready investigate/fix
commands) plus a statistical anomaly check, intended as a morning email for a
sysadmin team. Input is raw rsyslog text or an NDJSON dump from an ELK
cluster. Every run also files its findings into a queryable library in the
same SQLite file, served by the same binary as a small web UI (`serve`) and
a findings CLI. A plain-language tour for non-developers lives in
[HOW_IT_WORKS.md](HOW_IT_WORKS.md).

The pipeline design was first proven in a prototype, since archived; this
implementation replaced it outright and maintains no compatibility with it.

## Stack

- Go (stdlib-first; `flag`, `net/smtp`, `database/sql`, `text/template`,
  `net/http` with Go 1.22+ pattern routing, `html/template`, `go:embed`)
- modernc.org/sqlite (pure Go, no CGO, cross-compiles cleanly)
- Official provider SDKs: openai-go and anthropic-sdk-go
- pelletier/go-toml (known-knowns file), joho/godotenv (.env loading)
- Web UI: htmx, vendored and pinned (no CDN); alexedwards/scs for
  sessions; x/crypto bcrypt and x/term for local accounts
- Tests use the stdlib `testing` package only

## Directory structure

```
cmd/syslog-reporter/        CLI entry point; explicit command dispatch (run,
                            eval, serve, user, findings, mgmt-report,
                            self-update) from one registry - no default mode
internal/selfupdate/        Version/RepoURL (ldflags-stamped), the --version
                            latest-release check, and the self-update command
internal/reporter/
  lineformat.go             line parsing + number formatting helpers (splitWS,
                            thousands, compactFloat), pinned by test vectors
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
  capture.go                files one run's findings into the library
  librarystore.go           the findings library: runs/findings/feedback/users
                            tables, search, feedback upserts (same SQLite file
                            as the aggregates)
internal/web/               serve mode: stdlib+htmx findings UI, auth seam
                            (none/local drivers), hot-reloading TLS; templates
                            and static assets embedded via go:embed
internal/cli/               the findings subcommands (list/show/feedback) and
                            the argparse-style flag helper
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

Model strings use the litellm format, eg `openai/gpt-5.6-luna`, `anthropic/claude-sonnet-5`): the prefix
picks the official SDK, the rest passes through as the provider's model id.
`internal/llm.Complete` is the core - four structured-output calls
exist in the entire pipeline (issue detection, dedupe, resolutions, anomaly
explanations), constrained by JSON schemas that mirror the data
models. OpenAI gets a strict `json_schema` response format; Anthropic gets
`output_config.format`.

An `azure/` prefix targets OpenAI models hosted on Azure OpenAI: it uses
the same openai-go chat path with the client pointed at the resource's v1
endpoint, configured by `AZURE_OPENAI_ENDPOINT`
(`https://<resource>.openai.azure.com/openai/v1/`) and
`AZURE_OPENAI_API_KEY` (sent as a bearer token). The v1 GA surface takes
the model id in the request body like OpenAI proper, so there is no
per-deployment URL rewriting, no api-version parameter, and no Azure SDK
dependency; older non-v1 endpoints are not supported.

`SYSLOG_REASONING_EFFORT` passes to OpenAI verbatim (`none` is right for
batch runs); for Anthropic it maps onto `output_config.effort`, with
`none`/`minimal` clamped to `low` (Anthropic's floor).

System prompts are embedded in the binary (`internal/reporter/prompts/`,
via `go:embed`), so there is nothing to ship but the one file. Report
prompts require a one-line `#` comment above every suggested command;
state-changing commands must start `# CHANGES STATE:`.

Both report layouts end with `_Analysis by <model>_` when the LLM stages
ran, so teams comparing models can tell reports apart.

## The findings library

Every batch run files its findings into the library at report time
(`capture.go`): each issue is stored merged with its resolution (the same
title-match pairing the report itself uses), and each explained anomaly is
stored whole. The library lives in the SAME SQLite file as the aggregates
(`librarystore.go`). Both stores open through `migrate.go`, which sets the
standard pragmas (WAL journal, enforced foreign keys, 5s busy timeout) and
runs a numbered `schema_version` migration ladder shared by the whole
file; schema changes are new migrations there, never inline DDL. The
library tables are `runs`, `findings`, `finding_hosts`, `feedback`, and
`users`.

Capture semantics worth knowing:

- Idempotent per day: re-running a date REPLACES that day's run, findings
  AND any feedback votes on them. Backfills and re-runs stay clean;
  losing a re-run day's votes is the accepted cost.
- `--no-store` skips capture entirely (as it skips the aggregates);
  `--dump-filtered` never reaches capture.
- A capture failure is logged as a warning and costs the library one
  day, never the report or the email.
- On `--no-llm` runs the run's model is stored as NULL and issue-kind
  findings simply don't exist (no LLM, no issues); the anomaly facts are
  still captured.

### serve mode

`syslog-reporter serve` is the findings library web UI: one binary, no
extra services. Stdlib `net/http` with Go 1.22+ pattern routing,
`html/template`, and `go:embed` for every asset; htmx (vendored, pinned)
progressively enhances the list page's filtering and the feedback form,
which both work without JavaScript. Every setting is a flag (`--listen`,
`--db`, `--auth`, `--tls-cert`/`--tls-key`, `--secure-cookies`) whose
default comes from the matching `SYSLOG_WEB_*`/`SYSLOG_DB_PATH` variable,
so systemd units can stay env-shaped while a shell session just types
flags; the flag wins. The listen default is `127.0.0.1:7373`. The store
must already exist - serve refuses a missing db file rather than creating
an empty one and reporting "no findings yet". Routes: the findings list
at `/` (substring filters for host/service and title search, exact-match
severity/kind dropdowns, an inclusive date range, pagination at 50), the
detail page at `/findings/{id}`, and `POST /findings/{id}/feedback`.
Cross-origin POSTs are rejected via `http.CrossOriginProtection`. The
list page's status line is an aria-live region that persists across htmx
swaps (a replaced live-region node is not reliably announced).

Feedback is one vote per user per finding (a partial-unique upsert;
anonymous is a single shared voter). A re-vote always updates the verdict,
and an empty comment on a re-vote KEEPS the existing note - the comment
box is deliberately never prefilled, so flipping a verdict cannot wipe a
voter's own note. There is no comment-clearing path.

### Auth modes

`SYSLOG_AUTH_MODE` selects a driver behind one seam (`auth.go`); the rest
of the app only asks "who is the current user, if anyone?".

- `none` (default): no login, every page open, feedback is the single
  anonymous vote. The right mode for a solo sysadmin on localhost.
- `local`: form login against a bcrypt `users` table in the same SQLite
  file. Accounts are created with
  `syslog-reporter user add <username> <email>` (password prompted
  without echo, or `--password-stdin` for scripted use; never a CLI
  argument). Sessions are held in memory, so a restart logs everyone
  out - accepted for this tool. Failed logins pay the bcrypt cost even
  for unknown usernames, so response time is not a username oracle.
- `oidc`: not built yet; errors at startup.

### TLS

Set `SYSLOG_WEB_TLS_CERT` and `SYSLOG_WEB_TLS_KEY` together for HTTPS
(neither means plain HTTP; exactly one is a startup error). The
certificate pair hot-reloads on mtime change at the next handshake, so an
external renewal script can drop new files in place without a restart; a
half-written or mismatched pair mid-renewal keeps serving the previous
good one.

Risky-but-supported combinations warn at startup rather than refuse
(plain HTTP on a trusted LAN is a deliberate first-class case): no auth
on a non-loopback listen, and local auth over non-loopback plain HTTP,
each get one loud warning and then run as configured.

For TLS terminated at a reverse proxy (proxy speaks HTTPS to browsers,
this binary listens on loopback plain HTTP behind it), set
`SYSLOG_WEB_SECURE_COOKIES=1` so the session cookie carries the `Secure`
flag the browser-facing transport deserves; without it the flag is
derived from the built-in TLS setting alone. The app never reads
forwarded/client-IP headers, so the login throttle sees the proxy's
address - keep any per-client rate limiting at the proxy if you need it
there.

### The findings CLI

For terminal-only use, the same library over plain commands - same
binary, same SQLite file, no server needed; a local shell on the box IS
the auth:

```bash
syslog-reporter findings list [--host S] [--service S] [--severity X]
                              [--kind X] [--search S] [--since D] [--until D]
                              [--limit N] [--json]
syslog-reporter findings show <id> [--json]
syslog-reporter findings feedback <id> (worked|didnt-work)
                              [--comment "..."] [--user NAME]
```

Filters match the web UI's semantics (substring for host/service/search,
exact for severity/kind). Output is plain tabwriter text, or `--json` for
scripting. Feedback votes are attributed by matching your OS username
against the users table, falling back to the anonymous vote; an explicit
`--user` must match a users-table row (unknown is an error, never a
silent anonymous fallback). All findings subcommands take `--db`.

### The management report

`mgmt-report` renders a periodic summary for senior IT management as a
self-contained, email-safe HTML page (tables and inline styles only, no
scripts or SVG, so Outlook's Word renderer copes): headline numbers, a
daily volume bar chart, issues by severity, most flagged services, and
the team's feedback votes.

```bash
syslog-reporter mgmt-report [--days N] [--send-email] [--db PATH]
                            [--out FILE] [--debug]
```

The period is the last `--days` days (default 30) ending yesterday; days
the tool did not run show as "no data" rather than being papered over.
It is a pure reader of the never-pruned runs/findings/feedback tables
(ant ADR srg-9X77J): per-run `raw_lines`/`filtered_lines` provide the
volume trend, and days predating those columns borrow an approximate
volume from the aggregates table while the prune window still holds
them (marked with an asterisk in the chart). The HTML always lands in
`--out` (default `mgmt_report.html`); `--send-email` posts it as a
text+HTML alternative message to `SYSLOG_MGMT_RECIPIENTS`, which is
deliberately separate from the daily digest's list with no fallback
between them.

## Configuration

### CLI flags

The first argument is always a command: `run` (the daily batch report),
`eval` (model comparison), `serve` (web UI), `user` (local accounts:
add/list/passwd/remove), `findings` (list/show/feedback), `mgmt-report`
(management summary) and `self-update`. A bare invocation or an unknown
command prints the command list and exits non-zero; there is no default
mode. `--help`, `--version`, the bare words `help <command>` and
`version`, all work at top level.

Exit codes, for cron and monitoring: 0 success; 1 any runtime failure
(the message on stderr names the cause); 2 usage errors (unknown command,
bad flag). `self-update --check` alone uses 0 = current, 1 = newer
available, 2 = lookup failed. A run that cannot possibly succeed (missing
API key, missing SMTP settings with `--send-email`, a `--db` or
`--out-dir` that does not exist for a command that never creates one)
fails at startup before any work or spend.

The `run` flags:

```
logfile          positional: path to the syslog file; omit (or pass --) to
                 read raw text from stdin
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
--out-dir        directory for the email_body.md / email_attachment.md
                 drops (default .; must already exist)
--dump-filtered  print the post-filter log lines and exit: the quickest way
                 to see what your ignore rules are letting through when
                 tuning the filter for your estate
--debug          extra progress detail on stderr
```

`eval --model <provider/model>` compares provider/model combinations
cheaply: it runs the noise filter and then the real detection -> dedupe ->
resolution stages through the production provider seam, over a bundled
fictional-hostname sample (`--input <file>` overrides it, raw or filtered
lines), and writes `eval_<sanitised-model>_<timestamp>.md` (`--out`
overrides): front-matter with input/filtered line counts, per-stage
durations and the SDK-reported prompt/completion token counts, then the
report fragment. No cost is computed - multiply the tokens by your own
price sheet. Compare several models with a shell loop over `--model`
invocations.

### Environment variables

Read from the environment or a `.env` beside the working directory
(never commit one):

- `SYSLOG_DEFAULT_MODEL` default model, litellm format
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` for whichever provider is used
- `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` for `azure/` models
  (the resource's v1 endpoint; see the provider routing section)
- `SYSLOG_REASONING_EFFORT` reasoning effort, see above; unset = provider default
- `SYSLOG_REDACT` comma-separated literal strings stripped
  (case-insensitively, replaced with `[redacted]`) from every
  provider-bound message, e.g. `SYSLOG_REDACT=example.ac.uk,10.20.` to
  keep your domain and address range out of API traffic. A count of
  replacements is printed, never the values. This is an estate-identity
  courtesy, not PII or compliance redaction: if your log classification
  needs that, use `--no-llm` or a suitably contracted endpoint
- `SYSLOG_SMTP_SERVER`, `SYSLOG_SMTP_SENDER`, `SYSLOG_SMTP_RECIPIENTS` for
  `--send-email` (recipients ride the SMTP envelope as BCC). The daily
  email is a text+HTML alternative pair - the plain part is the digest
  markdown verbatim, the HTML part its on-brand rendering - with both
  markdown files attached (`email_body.md`, `email_attachment.md`) for
  copy/paste or feeding to an agent
- `SYSLOG_MGMT_RECIPIENTS` recipients for `mgmt-report --send-email`;
  separate audience from the daily digest, so no fallback to
  `SYSLOG_SMTP_RECIPIENTS` in either direction
- `SYSLOG_DB_PATH` SQLite aggregate-store path (default
  `syslog_aggregates.db`; CLI `--db` overrides; `--no-store` skips
  persistence and the history-based detectors). The file is in WAL mode:
  a plain `cp` of a live database drops commits still in the `-wal`
  sidecar, so back up with `sqlite3 <file> ".backup <dest>"` or copy
  only while nothing is running
- `SYSLOG_DB_KEEP_DAYS` store retention, pruned each run (default 90)
- `SYSLOG_BLANKET_IGNORE` comma-separated substrings appended to the filter
  at runtime - the home for estate-identifying entries (hostnames, internal
  IPs) so the committed filter stays estate-neutral
- `SYSLOG_KNOWN_KNOWNS` path to the known-knowns TOML (default
  `known_knowns.toml`; CLI `--known-knowns` overrides; missing file means none)
- `SYSLOG_WEB_LISTEN` serve mode's host:port (default `127.0.0.1:7373`)
- `SYSLOG_WEB_TLS_CERT` / `SYSLOG_WEB_TLS_KEY` certificate pair for HTTPS
- `SYSLOG_WEB_SECURE_COOKIES` set to `1` to force the session cookie's
  `Secure` flag when TLS is terminated at a reverse proxy (see the TLS
  section)
  in serve mode; both or neither (see the TLS section above)
- `SYSLOG_AUTH_MODE` serve mode's auth driver: `none` (default), `local`,
  or `oidc` (not built yet)
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
- `lineformat.go` helpers (split semantics, number formatting) and the
  explainer payload's `quoteField` quoting are pinned to captured test
  vectors; if a report number ever looks odd, look there first.
- Test fixtures use fictional hostnames only. Real estate names live solely
  in gitignored dumps, reports and the `.env`.

## Local development

```bash
go build -o syslog-reporter ./cmd/syslog-reporter
go test ./...
./syslog-reporter run dump.ndjson.gz --no-llm --db /tmp/scratch.db   # free run
./syslog-reporter run dump.ndjson.gz --model openai/gpt-4o-mini      # full run
./syslog-reporter run --dump-filtered dump.ndjson.gz                 # filter debug
SYSLOG_DB_PATH=/tmp/scratch.db ./syslog-reporter serve           # findings UI
```

## Releases

Pushing a `v*` tag builds linux/darwin/windows on amd64/arm64, generates
SHA256SUMS, and attaches everything to an immutable GitHub release. The tag is stamped
into the binary (`syslog-reporter --version`).
