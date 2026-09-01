#!/usr/bin/env bash
#
# The daily syslog-reporter run, shaped for cron: fetch yesterday's
# dump from ELK, run the full pipeline, email the report.
#
#   # crontab: yesterday's report to the team at 07:30
#   MAILTO=you@example.ac.uk
#   30 7 * * * /usr/local/bin/daily-run.sh >> /var/lib/syslog-reporter/daily-run.log 2>&1
#
# A non-zero exit means the report did not go out, so cron's own
# failure mail does the alerting. Pass a date to re-run a specific
# day by hand:
#   daily-run.sh 2026-08-27
#
# Defaults match the deployment laid out in GETTING_STARTED.md: binary
# and elk_dump.py in /usr/local/bin, with the .env, database, dumps and
# reports under /var/lib/syslog-reporter. Configuration (model, API
# key, SMTP, ELK credentials) goes in that .env - see
# TECHNICAL_OVERVIEW.md. No ELK? Replace the fetch block with however
# you slice yesterday's log, e.g. copying the rotated file into
# $DUMP_DIR.

set -euo pipefail

REPORTER=${REPORTER:-/usr/local/bin/syslog-reporter}
ELK_DUMP=${ELK_DUMP:-/usr/local/bin/elk_dump.py}
WORK_DIR=${WORK_DIR:-/var/lib/syslog-reporter}
DUMP_DIR=${DUMP_DIR:-$WORK_DIR/dumps}
OUT_DIR=${OUT_DIR:-$WORK_DIR}

# Both the binary and elk_dump.py read a .env from the working
# directory, and the SQLite history lands here too.
cd "$WORK_DIR"

# GNU date (Linux) and BSD date (macOS) disagree on relative dates.
yesterday() {
    if date -d yesterday +%Y-%m-%d >/dev/null 2>&1; then
        date -d yesterday +%Y-%m-%d
    else
        date -v -1d +%Y-%m-%d
    fi
}

day=${1:-$(yesterday)}
dump="$DUMP_DIR/syslog-$day.ndjson.gz"

mkdir -p "$DUMP_DIR"
if [ ! -s "$dump" ]; then
    python3 "$ELK_DUMP" --day "$day" --out "$dump"
fi

"$REPORTER" run "$dump" --date "$day" --send-email --out-dir "$OUT_DIR"

# Optional: tidy up dumps older than two weeks.
# find "$DUMP_DIR" -name 'syslog-*.ndjson.gz' -mtime +14 -delete
