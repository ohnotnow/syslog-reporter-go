# Getting started

Yesterday's syslog goes in, a short prioritised report comes out. Try it
on a real day of your own logs first - the trial run needs no LLM calls or API key so is free.

## Try it

Grab a binary from the
[releases page](https://github.com/ohnotnow/syslog-reporter-go/releases),
or build it if you have the [go compiler](https://go.dev/) installed:

```bash
git clone https://github.com/ohnotnow/syslog-reporter-go.git
cd syslog-reporter-go
go build -o syslog-reporter ./cmd/syslog-reporter
```

Pull a days logs out - `/var/log/syslog` on Debian, or `/var/log/messages` on RHEL-alikes:

```bash
# single-digit days are padded: `Aug 28 ` but `Aug  8 `
grep '^Aug 28 ' /var/log/syslog > yesterday.log
```

(If you're fancy and have ELK instead? `tools/elk_dump.py` pulls a day out of a cluster into a format the tool reads - usage notes at the top of the script.)

Run syslog reporter:

```bash
./syslog-reporter run yesterday.log --no-llm
```

The digest prints to stdout and the full report lands in
`email_attachment.md`. A `--no-llm` run only does the mechanistic
checks, and two of its three anomaly detectors compare against history
that won't exist yet - so a first report is likely to be a bit scanty.

Example output without the fancy LLM part:

```markdown
# Syslog digest - 29/08/2026

_Issue analysis was skipped (--no-llm run) - only the deterministic anomaly checks ran._

## Unusual activity (top 1)

Hosts behaving unlike their peers or their own recent normal - worth a glance.

### auth01.example.test / sshd

_Louder than its peers_ (unknown)

428 events vs a fleet median of 11.5 across peer hosts.

(no explanation generated)
```

## Give it a model

Put a model and its key in the environment, or a `.env` in the
directory you run it from:

```bash
SYSLOG_DEFAULT_MODEL=openai/gpt-5.6-luna
OPENAI_API_KEY=sk-...
```

([TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) has the full environment
reference, including Anthropic and Azure OpenAI.)

**Azure OpenAI: size the deployment before you run.** The issue detector
sends the filtered log in 1000-line chunks, and a chunk of syslog is
roughly 35K tokens before the model writes a word. Azure throttles each
deployment on tokens per minute (TPM), so a 50K TPM deployment holds
barely one chunk a minute: the second request is refused with "retry in
30 seconds", the retry lands in the same minute and is refused again,
and the run waits out its eight retries and then fails. Give the
deployment 200K TPM or more (`--sku-capacity 200` on
`az cognitiveservices account deployment create`, which also raises an
existing deployment in place), and set `SYSLOG_REASONING_EFFORT=none` so
reasoning tokens don't eat the same budget. A throttled run logs each
wait as a WARN line, so `daily-run.log` will tell you if it is still
undersized.

Run the same day again as a full 'agentic' run and feel all superior and futuristic.

```bash
./syslog-reporter run yesterday.log
```

Example output _with_ the LLM part:

```markdown
## 1. Sustained CPU overheating and saturation

**Severity:** critical · **Affected:** example-host · **OS:** Rocky Linux 9

example-host repeatedly reaches near-total CPU utilization while package and core temperatures exceed thresholds and clock throttling occurs, indicating a persistent thermal and workload problem.

**Likely cause:** example-host has a persistent CPU workload combined with inadequate cooling or thermal/hypervisor contention, causing throttling and unsafe temperatures.

**Have a look:**

# Identify CPU consumers, temperatures, frequencies, throttling, and hardware errors on example-host
ssh example-host 'uptime; ps -eo pid,ppid,user,pcpu,pmem,etime,cmd --sort=-pcpu | head -30; vmstat 1 5; sensors 2>/dev/null; for f in /sys/class/thermal/thermal_zone*/temp; do echo "$f $(cat "$f")"; done; grep -iE "thermal|thrott|mce|hardware error" /var/log/messages /var/log/kern.log 2>/dev/null | tail -100'

**Try:**

# Check scheduled jobs and PCP alarm context
ssh example-host 'sudo systemctl list-timers --all; sudo crontab -l -u root; sudo journalctl -u pcp-pmie --since today --no-pager -n 100'
# CHANGES STATE: Stop an identified runaway nonessential job before temperatures worsen
ssh example-host 'sudo systemctl stop <identified-runaway-unit>'
# Recheck temperature and utilization after workload reduction
ssh example-host 'uptime; sensors 2>/dev/null; ps -eo pid,pcpu,pmem,cmd --sort=-pcpu | head -15'

_Note: Replace unit placeholders only after identifying the actual runaway unit; take example-host offline or power it down if temperatures remain beyond hardware limits._
```

## If it looks good

- Cron the daily run with `--send-email` to get the report as a morning
  email - SMTP settings are in TECHNICAL_OVERVIEW.md.
- `--dump-filtered` shows what the noise filter is letting through;
  put your estate's own background noise in `SYSLOG_BLANKET_IGNORE`.
- Every run files its findings into a local SQLite library.
  `syslog-reporter serve` puts a web UI over that history on
  `127.0.0.1:7373`, with a worked / didn't-work vote on each finding -
  [HOW_IT_WORKS.md](HOW_IT_WORKS.md) is a tour with screenshots.
- `mgmt-report` renders a weekly or monthly management summary.
- `--help` on any command for more details.

## Running unattended

The daily run is a cron job. `--out-dir` keeps the report file drops out
of cron's working directory, and a non-zero exit means the report did not
go out, so let cron's own failure mail do its job:

```cron
# Yesterday's dump, emailed to the team at 07:30.
30 7 * * * /usr/local/bin/syslog-reporter run /var/dumps/yesterday.ndjson.gz \
  --send-email --out-dir /var/lib/syslog-reporter >> /var/log/syslog-reporter.log 2>&1
```

### Deploying with the helper scripts

`scripts/daily-run.sh` is that cron job as a ready-made wrapper: it
fetches yesterday's dump with `elk_dump.py`, runs the pipeline, and
exits non-zero if anything failed. Schedule it hourly: once a day's
report has gone out it leaves a `syslog-<day>.sent` marker in the dumps
directory and every later attempt that day exits quietly, so a flaky
ELK proxy just costs a retry an hour later. Its sibling `scripts/backfill.sh`
bootstraps a fresh install by running the last fortnight through
`--no-llm` (free) so the history-based detectors have something to
compare against from day one. A full deployment is:

```bash
# a system user and its state directory
sudo useradd -r -s /usr/sbin/nologin syslog-reporter
sudo install -d -o syslog-reporter -m 750 /var/lib/syslog-reporter

# the binary, the ELK dumper, and the two wrapper scripts
sudo install -m 755 syslog-reporter tools/elk_dump.py \
  scripts/backfill.sh scripts/daily-run.sh /usr/local/bin/

# the settings: model + API key, SMTP, ELK credentials
# (example just below; TECHNICAL_OVERVIEW.md is the full reference)
sudoedit /var/lib/syslog-reporter/.env
sudo chown syslog-reporter /var/lib/syslog-reporter/.env
sudo chmod 600 /var/lib/syslog-reporter/.env

# two weeks of free history so the detectors wake up with context
sudo -u syslog-reporter backfill.sh

# then the daily email: first try at 07:30, retried hourly until it goes out
sudo crontab -u syslog-reporter -e
#   MAILTO=you@example.ac.uk
#   30 7-17 * * * /usr/local/bin/daily-run.sh >> /var/lib/syslog-reporter/daily-run.log 2>&1
```

Both the binary and `elk_dump.py` read their `.env` from the working
directory (real environment variables win), so the scripts `cd` into
`/var/lib/syslog-reporter` before doing anything. That is also where
the SQLite history lands - the same path the systemd example below
points `--db` at. Every path is a variable at the top of each script
(`REPORTER`, `ELK_DUMP`, `WORK_DIR`, `DUMP_DIR`); to try one from a
checkout instead:

```bash
REPORTER=./syslog-reporter ELK_DUMP=./tools/elk_dump.py WORK_DIR=. \
  ./scripts/backfill.sh 3
```

### An example .env

Everything the daily run needs, in one file. This one uses an Azure
OpenAI deployment and an ELK cluster with basic auth; swap the model and
key lines for `openai/` or `anthropic/` as
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) describes.

```bash
# /var/lib/syslog-reporter/.env  (chmod 600, owned by syslog-reporter)

# Where the report goes. Recipients are a comma-separated list and ride
# the SMTP envelope only (BCC); the sender is what appears in To.
SYSLOG_SMTP_SERVER=mail-relay.example.ac.uk:25
SYSLOG_SMTP_SENDER=syslog-reporter@example.ac.uk
SYSLOG_SMTP_RECIPIENTS=sysadmin-team@example.ac.uk,oncall@example.ac.uk
# Only if your relay rejects the machine's own hostname in the greeting.
#SYSLOG_SMTP_HELO=reporter.example.ac.uk

# The model. For azure/ the id is your DEPLOYMENT name, not the model
# name, and the endpoint is the resource's v1 URL. Reasoning effort
# "none" is right for a batch run and keeps the token budget down.
SYSLOG_DEFAULT_MODEL=azure/gpt-5.6-luna
SYSLOG_REASONING_EFFORT=none
AZURE_OPENAI_ENDPOINT=https://my-resource.openai.azure.com/openai/v1/
AZURE_OPENAI_API_KEY=...

# Where elk_dump.py fetches yesterday's logs from. ELK_API_KEY works
# instead of username/password; ELK_INSECURE=1 skips TLS verification
# for a self-signed cluster (ELK_CA_CERT=/path/to/ca.pem trusts a local
# CA instead).
ELK_URL=https://elk.example.ac.uk:9200
ELK_USERNAME=syslog-reporter
ELK_PASSWORD=...
ELK_INDEX=logs-system.syslog-default
ELK_INSECURE=1

# Only on a server with no direct internet route - see "Behind a proxy".
#http_proxy=http://proxy.example.ac.uk:3128
#https_proxy=http://proxy.example.ac.uk:3128
#no_proxy=elk.example.ac.uk
```

Real environment variables win over the file, so a proxy or key
exported in the cron environment overrides what is here.

### Behind a proxy

On a server with no direct internet route, the LLM calls need the
standard proxy variables - and they need to be where the *binary's*
process can see them. `sudo -u` resets the environment and cron starts
with a near-empty one, so a proxy exported in your login shell silently
never arrives; the reliable place is the same `.env`, which both the
binary and `elk_dump.py` load before their first request:

```bash
https_proxy=http://proxy.example.ac.uk:3128
# keep internal traffic direct - without this, elk_dump.py would try
# to reach your ELK cluster THROUGH the proxy too
no_proxy=elk.example.ac.uk
```

Go and Python both honour upper- or lower-case spellings, real
environment variables win over the `.env`, and `no_proxy` takes a
comma-separated list (a bare domain matches its subdomains).

### The web UI

The web UI suits a small systemd service. Flags and environment variables
are interchangeable (the flag wins), so use whichever reads better in a
unit file:

```ini
[Unit]
Description=syslog-reporter findings UI
After=network.target

[Service]
ExecStart=/usr/local/bin/syslog-reporter serve --listen 127.0.0.1:7373 \
  --db /var/lib/syslog-reporter/syslog_aggregates.db --auth local
User=syslog-reporter
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

serve refuses to start if the database file does not exist yet - do a
first `run` (or point `--db` at the right file) before enabling it.


## Quick evaluations

If you want to try out different providers/models against a sample of your logs (or the bundled test ones) you can do something like this :

```sh
for MODEL in openai/gpt-5.6-luna anthropic/claude-sonnet-5; do
  ./syslog-reporter eval --model "${MODEL}" --input yesterday.log
done
```

Leave `--input` off to use the bundled sample. The noise filter runs
first, so the model only sees what a real run would send it - a full day
through eval costs about the same as a full day's real run, per model.

Each run writes its result to its own `eval_<model>_<timestamp>.md`, with
the model name, time taken, line and token counts up top (you'll have to
check your provider to work out how that maps to the cost).
