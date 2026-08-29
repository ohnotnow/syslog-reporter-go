# CLAUDE.md

The Go port of syslog_reporter: a batch CLI tool that turns a noisy,
org-wide syslog stream into a short, prioritised email report for a small
university sysadmin team. Deterministic code (filters, counts, robust
statistics) decides *what* is worth surfacing; the LLM only explains
findings and writes paste-ready commands. Alert fatigue is the enemy.
Since milestone 3 the same binary also keeps a findings library (every
run's findings captured to SQLite) served as a stdlib+htmx web UI
(`serve`) and a findings CLI.

This repo is a **replacement, not a sibling** of the Python original at
`~/Documents/code/syslog_reporter` (GitHub: ohnotnow's
syslog_reporter, archived). The compatibility contract: identical SQLite schema, env
vars, CLI flags, known_knowns.toml format, and report markdown behaviour,
so a cron host can swap the binary in without losing its accumulated
baseline history.

## Start here, in this order

1. **`ant show srg-AkRXV`** - the cold-start pointer. The port plan (the
   full ADR, compatibility contract, provider routing design) lives in the
   *Python* repo's ant database; that note tells you how to read it.
2. **`ant recent --limit 5`** and **`ait status`** - current decisions and
   open work in this repo.
3. The Python repo's `TECHNICAL_OVERVIEW.md` - the pipeline map. The Go
   code mirrors it agent-for-agent.

## Layout

```
main.go                     CLI entry point; wires the pipeline (mirrors main.py)
internal/reporter/
  pyfmt.go                  Python-semantics helpers (split, number formatting);
                            byte parity with the original depends on these
  filters_data.go           port of agents/log_filters.py (edit per estate)
  filter.go                 LogFilter (deterministic noise removal)
  knowns.go                 known-knowns TOML suppression
  anomaly.go                ParseLine / RobustZ / peer detector / CombineAnomalies
  store.go                  SQLite aggregate store (same schema as Python)
  baseline.go temporal.go   history-based detectors
  elksource.go              ELK NDJSON dump renderer
  models.go report.go       report data models + both report layouts
  llmagents.go prompts/     the four LLM agents + embedded system prompts
  emailer.go                SMTP digest + markdown-attachment sender
  capture.go                files one run's findings into the library
  librarystore.go           findings library store (runs/findings/feedback/users)
internal/web/               serve mode: findings UI, auth seam, hot-reload TLS
internal/cli/               findings subcommands + ParseFlagsAnywhere
internal/llm/               provider seam: litellm-style prefix -> official SDK
tools/elk_dump.py           ELK NDJSON dumper (copied verbatim from the Python repo)
```

## Commands

```bash
go build -o syslog-reporter .        # single static-ish binary
go test ./...                        # stdlib testing only
./syslog-reporter <dump.ndjson.gz> --no-llm --db /tmp/scratch.db   # free run
SYSLOG_DB_PATH=/tmp/scratch.db ./syslog-reporter serve   # findings web UI, 127.0.0.1:7373
./syslog-reporter findings list --db /tmp/scratch.db     # findings CLI (list/show/feedback)
./syslog-reporter user add <username> <email>            # local-auth account (--password-stdin)
```

## Conventions and gotchas

- **Load the `golang` skill before writing Go here** (owner's rule).
- **Licence is AGPL-3.0, deliberately.** Verbatim FSF text in LICENSE,
  copyright notice in the README. Never soften to MIT/Apache.
- **No em dashes anywhere, including output** (owner decision 2026-08-28):
  the Go report emits plain hyphens where the Python original emits em
  dashes. The other deliberate report divergences: the model footer
  (`_Analysis by <model>_`, owner decision 2026-08-28) appended to both
  layouts when the LLM stages ran, and the digest's cheery greeting line
  removed (owner decision 2026-08-29, "Eddie the Computer" fatigue) -
  only a factual truncation notice remains, and only when issues were
  actually truncated. Everything else is byte-identical; parity tooling
  must canonicalise dashes and strip the footer before diffing.
- The LLM stages live in `internal/reporter/llmagents.go` with prompts
  embedded from `internal/reporter/prompts/` (ports of the Python
  `agents/prompts/*.j2`, em dashes replaced per the dash rule);
  `internal/llm` routes `openai/` and `anthropic/` model prefixes to the
  official SDKs; `azure/` rides the openai-go client against an Azure
  OpenAI v1 endpoint (AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY, no
  Azure SDK dependency). `SYSLOG_REASONING_EFFORT` passes to
  OpenAI verbatim; for Anthropic it maps onto `output_config.effort`
  (`none`/`minimal` clamp to `low`). `--send-email` is ported and was
  verified against a local mailhog: recipients ride the SMTP envelope
  only (BCC), the To header carries the sender. Since srg-kOKT9 (owner
  decision 2026-08-29) the daily email body is multipart/alternative -
  plain part = digest markdown VERBATIM, HTML part = goldmark render
  (GFM only: never Typographer, which smartens hyphens into banned
  dashes; never WithUnsafe, the body embeds LLM prose) - with both
  markdown files attached. The Python original sent plain-only; it is
  an archived prototype, so this divergence is deliberate.
- `internal/reporter` reproduces Python dict insertion order with ordered
  map types (Counts, PairTotals, PairHistory) so stable-sort tie-breaks
  land where the original's do. Don't swap them for plain Go maps.
- pyfmt.go's helpers are pinned by tests to CPython-captured vectors; if a
  report number ever mismatches, look there first.
- The aggregate store deliberately does NOT enable WAL: the Python
  original leaves SQLite's default journal mode, and drop-in db
  compatibility wins over the usual Go conventions.
- The findings library lives in the SAME SQLite file as the aggregates
  (librarystore.go, same no-WAL style). Its tables are additive: the
  aggregates compatibility contract is unchanged and the new tables
  carry no Python burden. Capture is idempotent per day - re-running a
  date REPLACES that day's run, findings AND feedback votes. Feedback is
  one vote per user per finding (anonymous is a shared singleton);
  a re-vote updates the verdict but an EMPTY comment keeps the existing
  note (owner decision 2026-08-28) - there is no comment-clearing path.
- serve mode is env-configured only (SYSLOG_WEB_LISTEN, SYSLOG_AUTH_MODE,
  SYSLOG_WEB_TLS_CERT/_KEY). Default port 7373 is a Blake's 7 joke
  (Vila weighs 73 kilos); do not "fix" it. Auth mode oidc errors at
  startup - deferred (ait srg-2KY5X.5) until the owner is present for a
  Keycloak round-trip.
- `--dump-filtered` prints the post-filter lines and exits. Born as the
  milestone-1 parity diff tool, promoted to a documented filter-tuning
  aid (owner decision 2026-08-28) now the Python repo is archived.
- Sample dumps (syslog-*.ndjson.gz) and the aggregate db are gitignored
  and local-only; they carry real estate hostnames, so they must never be
  committed, quoted in tests, or pasted into notes. Test fixtures use
  fictional hostnames only.
- British English throughout, including report output.
