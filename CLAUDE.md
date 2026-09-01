# CLAUDE.md

A batch CLI tool that turns a noisy, org-wide syslog stream into a short,
prioritised email report for a small university sysadmin team. Deterministic
code (filters, counts, robust statistics) decides *what* is worth surfacing;
the LLM only explains findings and writes paste-ready commands. Alert
fatigue is the enemy. The same binary also keeps a findings library (every
run's findings captured to SQLite) served as a stdlib+htmx web UI (`serve`),
a findings CLI, and a management summary (`mgmt-report`).

The project grew out of an archived Python prototype; that history binds
NOTHING (ant ADR srg-7qsQV, owner decision 2026-08-29) - no schema, flag,
or report-byte parity obligation survives, and no doc or comment should
present one. Not yet deployed to production; no real data exists beyond
local development stores.

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
                            eval, serve, user, findings, mgmt-report,
                            self-update) from one registry - no default mode
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
  llmagents.go prompts/     the four LLM agents + embedded system prompts
  emailer.go                SMTP digest + markdown-attachment sender
  capture.go                files one run's findings into the library
  librarystore.go           findings library store (runs/findings/feedback/users)
  mgmtreport.go             management summary (HTML + plain text)
internal/web/               serve mode: findings UI, auth seam, hot-reload TLS
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
./syslog-reporter eval --model openai/gpt-4o-mini    # model comparison (bundled fixture)
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
  `SYSLOG_REASONING_EFFORT` passes to OpenAI verbatim; for Anthropic it
  maps onto `output_config.effort` (`none`/`minimal` clamp to `low`).
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
  variable; the flag wins. (It was briefly env-only; the owner never
  agreed to that - srg-NJzXv.) Read-only commands (serve, findings,
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
