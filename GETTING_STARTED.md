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

Put a model and its key in the environment, or a `.env` next to the
binary:

```bash
SYSLOG_DEFAULT_MODEL=openai/gpt-5.6-luna
OPENAI_API_KEY=sk-...
```

([TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) has the full environment
reference, including Anthropic and Azure OpenAI.)

Run the same day again as a full 'agentic' run and feel all superior and futuristic.

```bash
./syslog-reporter run yesterday.log
```

Example output _with_ the LLM part:

```markdown
## 1. Sustained CPU overheating and saturation

**Severity:** critical · **Affected:** example-host

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

