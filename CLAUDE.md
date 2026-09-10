# syslog-reporter-go

A batch CLI tool that turns a noisy, org-wide syslog stream into a short,
prioritised email report for a small university sysadmin team. Deterministic
code (filters, counts, robust statistics) decides *what* is worth surfacing;
the LLM only explains findings and writes paste-ready commands. Alert
fatigue is the enemy. The same binary also keeps a findings library (every
run's findings captured to SQLite) served as a stdlib+htmx web UI (`serve`),
a findings CLI, and a management summary (`mgmt-report`).

The project grew out of an archived Python prototype; that history binds
NOTHING (ant ADR srg-7qsQV, owner decision 2026-08-29): no schema, flag,
report-byte or idiom parity survives, and no comment should justify Go
behaviour by what the prototype did. The first production try-out began
2026-09-01; until the owner confirms it stuck, treat what real data exists
as unknown.

## Start here, in this order

1. **`ant foundation`** - what the project is and deliberately is not.
2. **`ant show srg-AkRXV`** - the cold-start pointer: settled rules,
   current state, open work.
3. **`ant recent --limit 5`** and **`ait status`** - recent decisions and
   open work.
4. `TECHNICAL_OVERVIEW.md` - the canonical pipeline map.

## Layout

```
cmd/syslog-reporter/        CLI entry point; explicit command dispatch (run,
                            eval, serve, user, token, findings,
                            mgmt-report, digest, self-update) from one
                            registry - no default mode; digest.go is the
                            weekly digest command
internal/selfupdate/        Version/RepoURL, --version latest-release check,
                            and the self-update command
internal/reporter/
  lineformat.go             line parsing + number formatting helpers (splitWS,
                            thousands, compactFloat), pinned by tests
  filters_data.go           the noise filter rule list (edit per estate)
  filter.go                 LogFilter (deterministic noise removal)
  knowns.go                 known-knowns TOML suppression
  anomaly.go                ParseLine / RobustZ / peer detector / CombineAnomalies
  store.go                  SQLite daily-aggregate store
  baseline.go temporal.go   history-based detectors
  elksource.go              ELK NDJSON dump renderer
  models.go report.go       report data models + both report layouts
  logcontext.go             LogIndex: per-host surrounding-line windows fed
                            to the resolution writer (raw lines; radius from
                            SYSLOG_CONTEXT_LINES / --context-lines, 0 = off)
  llmagents.go prompts/     the four LLM agents + embedded system prompts
  emailer.go                SMTP digest + markdown-attachment sender
  capture.go                files one run's findings into the library
  librarystore.go           findings library store (runs/findings/feedback/users)
  apitokens.go              sysadmin API bearer tokens (sha256 + 8-char prefix)
  knownsmute.go             mute-by-finding-id: derive host+program entries
                            from a finding, append them to the TOML atomically
  mgmtreport.go             management summary (HTML + plain text)
  digest.go                 weekly digest: BuildDigest groups library
                            findings across days (issues by service + host
                            set, anomalies by host + program), ranks by
                            days seen; DigestIssue/DigestAnomaly feed the
                            existing LLM agents
  digestreport.go           the weekly digest's email body + attachment
internal/web/               serve mode: findings UI, auth seam, hot-reload TLS,
                            and the bearer-token JSON API under /api/
                            (apiauth.go, api.go, apiwrite.go)
skills/syslog-reporter/     Claude Code skill for the API; the team's only
                            "client" (curl + this file), see README
internal/cli/               findings subcommands + ParseFlagsAnywhere
internal/llm/               provider seam: litellm-style prefix -> official SDK
tools/elk_dump.py           ELK NDJSON dumper (stdlib-only python3; runs on
                            whichever box can read the log store)
scripts/                    end-user bash wrappers: backfill.sh (bootstrap N
                            days of history, --no-llm) and daily-run.sh (the
                            cron job); self-contained, production defaults,
                            both cd into WORK_DIR (/var/lib/syslog-reporter)
                            so the cwd-relative .env and db resolve - deploy
                            walkthrough in GETTING_STARTED.md

```

## Commands

```bash
go build -o syslog-reporter ./cmd/syslog-reporter   # single static-ish binary
go test ./...                        # stdlib testing only
./syslog-reporter run <dump.ndjson.gz> --no-llm --db /tmp/scratch.db   # free run
./syslog-reporter eval --model openai/gpt-5.6-luna    # model comparison (bundled fixture)
SYSLOG_DB_PATH=/tmp/scratch.db ./syslog-reporter serve   # findings web UI, 127.0.0.1:7373
./syslog-reporter findings list --db /tmp/scratch.db     # findings CLI (list/show/feedback)
./syslog-reporter user add <username> <email>            # local-auth account (--password-stdin)
```

## Conventions and gotchas

- **Load the `golang` skill before writing Go here** (owner's rule).
- **Licence is AGPL-3.0, deliberately.** Verbatim FSF text in LICENSE,
  copyright notice in the README. Never soften to MIT/Apache.
- **No em dashes anywhere, including output** (owner decision 2026-08-28):
  plain hyphens only. Both report layouts end with a model footer
  (`_Analysis by <model>_`, owner decision 2026-08-28) when the LLM stages
  ran. No cheery greeting line (owner decision 2026-08-29, "Eddie the
  Computer" fatigue) - only a factual truncation notice, and only when
  issues were actually truncated.
- The LLM stages live in `internal/reporter/llmagents.go` with system
  prompts embedded from `internal/reporter/prompts/`; `internal/llm`
  routes `openai/` and `anthropic/` model prefixes to the official SDKs;
  `azure/` rides the openai-go client against an Azure OpenAI v1 endpoint
  (AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY, no Azure SDK dependency).
  `SYSLOG_REASONING_EFFORT` takes `low`/`medium`/`high`/`xhigh`/`max`
  (unset = `low`) and goes to both providers verbatim; `none` and
  `minimal` were dropped (owner decision 2026-09-06, ant ADR srg-heCEJ)
  and are refused at startup by llm.CheckReasoningEffort.
  `SYSLOG_REDACT` strips operator-listed literals from every
  provider-bound user message (llm.Complete is the choke point) - an
  estate-identity courtesy, deliberately NOT PII scrubbing (ant ADR
  srg-Mzvjf). All four prompts carry a trust-boundary block and both
  report layouts a paste caution, each pinned by tests - keep them.
- `--send-email` was verified against a local mailhog: recipients ride the
  SMTP envelope only (BCC), the To header carries the sender. Since
  srg-kOKT9 (owner decision 2026-08-29) the daily email body is
  multipart/alternative - plain part = digest markdown VERBATIM, HTML part
  = goldmark render (GFM only: never Typographer, which smartens hyphens
  into banned dashes; never WithUnsafe, the body embeds LLM prose) - with
  both markdown files attached.
- Report ordering is deterministic by explicit sorting: ranked lists sort
  by score with a lexicographic (host, program[, window]) tie-break. Never
  let output depend on map iteration order.
- lineformat.go's helpers are pinned by tests; if a report number ever
  looks odd, look there first.
- Storage: the aggregates and the findings library share ONE SQLite file.
  Both stores open through migrate.go's openDatabase, which sets the
  pragmas (WAL, foreign_keys ON, busy_timeout 5000) and runs the
  schema_version migration ladder. Schema changes are new numbered
  migrations in migrate.go - never inline DDL in the stores. The file is
  WAL, so a plain cp of a live db loses the -wal sidecar; use
  sqlite3 .backup.
- Findings capture is idempotent per day - re-running a date REPLACES that
  day's run, findings AND feedback votes. Feedback is one vote per user
  per finding (anonymous is a shared singleton); a re-vote updates the
  verdict but an EMPTY comment keeps the existing note (owner decision
  2026-08-28) - there is no comment-clearing path.
- serve mode takes flags (--listen, --db, --auth, --tls-cert/--tls-key,
  --secure-cookies), each defaulting from its SYSLOG_WEB_*/SYSLOG_DB_PATH
  variable; the flag wins. Read-only commands (serve, findings,
  mgmt-report, user) refuse a missing db file via
  reporter.RequireDatabase; only a run creates the store.
  Default port 7373 is a Blake's 7 joke
  (Vila weighs 73 kilos); do not "fix" it. Auth mode oidc errors at
  startup - deferred (ait srg-2KY5X.5) until the owner is present for a
  Keycloak round-trip. Risky listen/auth combos WARN at startup, never
  refuse - plain HTTP on a LAN is a supported case (owner stance).
- `--dump-filtered` prints the post-filter lines and exits - the
  documented filter-tuning aid (owner decision 2026-08-28).
- Sample dumps (syslog-*.ndjson.gz) and the aggregate db are gitignored
  and local-only; they carry real estate hostnames, so they must never be
  committed, quoted in tests, or pasted into notes. Test fixtures use
  fictional hostnames only.
- British English throughout, including report output.
- The default model is `openai/gpt-5.6-luna` (owner decision 2026-09-02).
  gpt-4o-mini was never the owner's choice; do not reintroduce it in code,
  docs, or examples. The pipeline can split across two models (owner
  decision 2026-09-06): `SYSLOG_LOGSCAN_MODEL` drives the issue detector
  and deduplicator (bulk, schema-enforced JSON), `SYSLOG_ISSUE_MODEL` the
  resolution writer and anomaly explainer (prose people read); each falls
  back to `--model`. When they differ, the footer and the library's run
  model read `<issue model> (scan: <scan model>)` via reporter.ModelLabel.

- The weekly digest (`digest`, epic srg-xiBoC, ant ADR srg-WtzbG) is the
  intended delivery: quiet daily runs on cheap models, one email a week.
  It reads the library only (no dump, no log scan, no "last digest"
  state; the window is `--days` ending yesterday, a missed Monday is
  `--days 14` by hand), files itself as a run of kind `digest` under the
  window's end date (migration 4; replace-on-rerun keys on date + kind;
  mgmt-report counts daily runs only), and its finding ids are what the
  email prints. Model: `SYSLOG_DIGEST_MODEL` > `SYSLOG_ISSUE_MODEL` >
  `--model`. On digest day the digest REPLACES the daily email
  (daily-run.sh `--digest`; `--no-email` for the other days). Keys are
  service + sorted host set and host + program, never titles (LLM prose).
  Two issue lists, deliberately: recurring (2+ days, top 10, smart model)
  and worst one-offs (single-day critical/high, top 5, the daily run's
  own resolution, no model call); single-day medium/low are attachment
  only. Caps are small on purpose (owner 2026-09-10: a scrollbar in the
  email client means nobody reads it).
- `eval` follows the same model env defaults as `run`, with additional
  `--scan-model` / `--issue-model` flags that win over their stage env vars.
  Stage env vars still win over `--model`. It evaluates detection, dedupe
  and resolutions only, not anomalies. Output records both models, shared
  reasoning effort and per-stage plus total token usage. Use both stage
  flags to force a single model when a split is configured in `.env`.
