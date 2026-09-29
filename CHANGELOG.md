# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first stable release. syslog-reporter turns an organisation's syslog
into a short, prioritised email for its sysadmins. Deterministic filters
strip out the routine noise and an LLM decides which of the remaining
lines are real problems and suggests commands to investigate them, while
statistical detectors flag hosts that are suddenly louder or quieter
than usual for the LLM to explain. Every finding is kept in a library
with a web UI, a sysadmin API and a weekly digest. It is now a single
binary: the ELK fetch, the hourly cron job and the history backfill are
commands of it.

### Added
- `fetch`: dump one day of syslog from Elasticsearch as NDJSON. The file
  appears only once the whole day has arrived. Copy the binary to a
  whitelisted box to fetch where only some addresses may reach the cluster.
- `daily`: the hourly cron job. Fetches yesterday, runs the pipeline and
  emails the report (`--no-email` files it quietly, `--digest` sends the
  weekly digest instead). Later attempts that day exit at once, a failed
  digest is retried on its own, and only one attempt runs at a time.
- `backfill`: run the last N days (default 14) through the pipeline with
  no LLM, fetching missing dumps and skipping days that fail.
- `budget`: show today's LLM prompt-token spend; `budget reset` clears it.

### Changed
- `SYSLOG_MAX_PROMPT_TOKENS` is now a budget per calendar day, shared by
  every run and digest that day and kept in the database, so hourly
  retries of a run that failed part-way can no longer each spend it again.
- `install.sh` installs only the binary and no longer needs python3 or
  flock. Its cron lines run `syslog-reporter daily` from the state
  directory. It no longer runs the backfill or `knowns seed` (a re-run
  could replace analysed days with free ones); it prints them as next
  steps. It no longer asks for a cron `MAILTO`: all output goes to
  `daily-run.log`, so use your own job monitor for alerts.
- ELK access honours `https_proxy`/`no_proxy` from the `.env`: list the
  cluster in `no_proxy` if it must not go through your proxy.
- The issue detector is told how many hosts logged a message it only sees
  a few examples of (`[on N hosts]`), so an estate-wide fault no longer
  reads as one host's problem. The cap of three example lines is unchanged.
- The management summary counts feedback as votes ("2 of 3 feedback votes
  said the fix worked"), not as reviewed findings.

### Fixed
- An Elasticsearch search that timed out or lost a shard could be saved
  as a complete day; it now fails and is retried.
- A run whose findings could not be saved to the library still counted as
  done, leaving the day out of the weekly digest. It now fails after
  writing and sending its report, so the next hourly attempt files it.
- `SYSLOG_SCRUB` now also covers the system prompt, which carries the
  host list with full hostnames.
- The weekly digest could pair advice or a finding number with the wrong
  issue when two groups shared a title, and could order tied groups
  differently from run to run.
- A mail relay that stops answering no longer hangs the run (30s to
  connect, 5 minutes for the whole exchange).
- A deleted known-known's id is never reused, so retrying a delete cannot
  remove a newer rule.

### Removed
- `scripts/daily-run.sh`, `scripts/backfill.sh` and `tools/elk_dump.py`.
  **Upgrading:** delete `/etc/cron.d/syslog-reporter` (install.sh keeps an
  existing one) and re-run install.sh, or change each cron line to
  `cd /var/lib/syslog-reporter && syslog-reporter daily ...`. The `.sent`
  markers keep their names, so no day is re-run.
- The interactive ELK password prompt; set `ELK_PASSWORD` or an API key.

Releases before 1.0.0 were pre-release; their history is in the git tags.

[Unreleased]: https://github.com/ohnotnow/syslog-reporter-go/compare/v0.32.0...HEAD
