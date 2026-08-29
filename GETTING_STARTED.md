# Getting started

From "I have a pile of syslog" to a daily emailed report and a browsable
findings library. Each step works on its own, and the first run costs
nothing: no API key, no config file.

## 1. Get the binary

Download a release from the
[releases page](https://github.com/ohnotnow/syslog-reporter-go/releases),
or build from source:

```bash
git clone https://github.com/ohnotnow/syslog-reporter-go.git
cd syslog-reporter-go
go build -o syslog-reporter ./cmd/syslog-reporter
```

It is one self-contained binary: the web UI, prompts and templates are
embedded, and the only file it creates is a SQLite database. Release
builds can later update themselves with `syslog-reporter self-update`.

## 2. Get a day of logs

The tool works on one day of syslog at a time, in either of two forms.

**A plain rsyslog text file.** If your hosts forward to a central rsyslog
box, yesterday's rotated file is already the right input:

```bash
./syslog-reporter run /var/log/messages-20260827 --no-llm
```

**An ELK NDJSON dump.** If syslog lands in an Elasticsearch data stream,
`tools/elk_dump.py` pulls one day into the NDJSON format the tool
ingests. It is deliberately stdlib-only python3: copy that one script to
whichever box can reach the cluster. The account only needs the `read`
index privilege on the stream.

```bash
# yesterday, the common case; add --day YYYY-MM-DD for another day
python3 elk_dump.py --url https://elk.example.ac.uk:9200 \
    --username someuser \
    --index 'logs-system.syslog-default' \
    --out syslog-2026-08-27.ndjson.gz
```

Credentials come from the flags, the environment, or a local `.env`
(`ELK_URL`, `ELK_API_KEY` or `ELK_USERNAME`/`ELK_PASSWORD`); they are
never printed. `.gz` output is handled everywhere downstream.

## 3. First run - free, no LLM

```bash
./syslog-reporter run syslog-2026-08-27.ndjson.gz --no-llm
```

`--no-llm` skips every LLM stage, so this costs nothing and needs no API
key. You still get the full deterministic half: the noise filter, the
three anomaly detectors, and a report that honestly says the LLM analysis
was skipped. The run prints the digest to stdout and drops two files in
the working directory: `email_body.md` (the short digest) and
`email_attachment.md` (the full report).

It also creates `syslog_aggregates.db` and stores the day's per-host
counts in it. Two of the three anomaly detectors compare today against
history, so they stay quiet until the database holds a week or two of
days. You can backfill that history cheaply from old log files. NDJSON
dumps carry their own date; raw text files are assumed to be yesterday's,
so backfills of older days need `--date`:

```bash
for d in 20 21 22 23 24 25 26; do
  ./syslog-reporter run /var/log/messages-202608$d --no-llm --date 2026-08-$d
done
```

## 4. Wire up a model

Configuration lives in the environment or a `.env` next to where you run
it. For OpenAI or Anthropic:

```bash
SYSLOG_DEFAULT_MODEL=openai/gpt-5.6-luna   # litellm-style provider/model
OPENAI_API_KEY=sk-...                     # or ANTHROPIC_API_KEY for anthropic/ models
```

For Azure OpenAI, use the deployment name and the resource's v1 endpoint:

```bash
SYSLOG_DEFAULT_MODEL=azure/your-deployment-name
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/openai/v1/
AZURE_OPENAI_API_KEY=...
```

Not sure which model? `eval` runs just the LLM stages over a small
bundled log sample and writes a report fragment with per-stage timings
and token counts, so you can judge speed, quality and price on your own
terms:

```bash
./syslog-reporter eval --model openai/gpt-5.6-luna
./syslog-reporter eval --model anthropic/claude-sonnet-5
```

If you would rather your estate's identity stayed out of API traffic,
`SYSLOG_REDACT=example.ac.uk,10.20.` strips those literals from every
provider-bound message. That is a courtesy, not compliance-grade
redaction - if your logs must not leave the building, stay with
`--no-llm` or use a suitably contracted endpoint.

Then run without `--no-llm`:

```bash
./syslog-reporter run syslog-2026-08-27.ndjson.gz
```

## 5. Tune the noise filter

The filter ships with a general-purpose rule list, but every estate has
its own background hum. Two knobs:

- `--dump-filtered` prints exactly the lines the filter is letting
  through to the LLM and exits. If you see routine noise in there, add
  it to the ignore rules.
- `SYSLOG_BLANKET_IGNORE=chatty-app,10.20.30.` is a comma-separated list
  of substrings dropped at runtime - the home for estate-identifying
  entries (hostnames, internal IPs) so they never need to live in a
  config file or the codebase.

For oddities the team has already diagnosed and accepted ("that host
always does that, it's the microscope"), `known_knowns.toml` suppresses
them while keeping the suppression visible in a report footer:

```toml
[[known]]
host = "lab-42"                # glob: "lab-42", "lab*", or "*"
match = "port 1234"            # optional regex, applied after the hostname
program = "kernel"             # optional glob, also mutes (host, program) anomalies
reason = "microscope attached for the optics experiment"
added = 2026-08-27
expires = 2026-12-01           # optional: entry lapses after this date
```

Each entry needs a `reason` and at least one of `match` / `program`.

## 6. Email it every morning

Set the SMTP details and add `--send-email`:

```bash
SYSLOG_SMTP_SERVER=smtp.example.ac.uk    # port 25 unless you say otherwise
SYSLOG_SMTP_SENDER=syslog-reporter@example.ac.uk
SYSLOG_SMTP_RECIPIENTS=team@example.ac.uk
```

The email is an HTML rendering of the digest, with both markdown files
attached for copy/paste (or for handing to your own tooling). Recipients
ride the SMTP envelope as BCC. A typical crontab
entry, with the dump step on the same box:

```cron
30 6 * * * cd /opt/syslog-reporter && ./syslog-reporter run /srv/dumps/yesterday.ndjson.gz --send-email
```

A failed send exits non-zero so cron notices, and the two markdown files
are already on disk either way.

## 7. Browse the findings library

Every run (including `--no-llm` ones) also records what it found in the
same SQLite file, so the morning report stops being throwaway. Browse it
in a small web UI, or straight from the terminal:

```bash
./syslog-reporter serve        # http://127.0.0.1:7373

./syslog-reporter findings list --host web-01 --severity high
./syslog-reporter findings show 42
./syslog-reporter findings feedback 42 worked --comment "cache cleared, sorted"
```

The UI has search and filters over every past finding, and a
worked / didn't-work vote on each one - that outcome history is the
point of the library. By default it listens on localhost with no login;
for a shared box there is a local-accounts mode
(`SYSLOG_AUTH_MODE=local` plus `syslog-reporter user add <username>
<email>`) and optional TLS (`SYSLOG_WEB_TLS_CERT`/`_KEY`).
`serve --help` lists the environment variables.

One operational note: the database is in SQLite WAL mode, so a plain
`cp` of a live file can silently miss the newest writes. Back it up with
`sqlite3 syslog_aggregates.db ".backup backup.db"`, or copy while
nothing is running.

## 8. The management summary

Once a few weeks of history exist, the same binary renders a periodic
summary for management - headline numbers, a daily volume chart, issues
by severity and the team's feedback votes:

```bash
SYSLOG_MGMT_RECIPIENTS=manager@example.ac.uk ./syslog-reporter mgmt-report --days 7 --send-email
```

## Where next

- `./syslog-reporter --help` and `<command> --help` for the quick
  reference.
- [TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) for the full flag and
  environment-variable reference and how the pipeline works.
- [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for a tour of the web UI with
  screenshots.
