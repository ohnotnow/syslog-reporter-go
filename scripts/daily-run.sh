#!/usr/bin/env bash
#
# The daily syslog-reporter run, shaped for cron: fetch yesterday's
# dump from ELK, run the full pipeline, email the report.
#
# Schedule it hourly rather than once. The first attempt that gets all
# the way through leaves a syslog-<day>.sent marker in DUMP_DIR, and
# every later attempt that day exits 0 without a word, so a flaky ELK
# proxy only costs a retry an hour later. The marker is written after
# the email goes out, so a failed or killed attempt never blocks the
# retries. One attempt runs at a time (flock). Killing this script
# (SIGTERM or SIGINT) also kills whichever fetch or reporter it is
# waiting on, so the lock clears and the next hourly attempt retries.
#
#   # crontab: yesterday's report to the team, first try at 07:30,
#   # retried on the half hour until it goes out
#   MAILTO=you@example.ac.uk
#   30 7-17 * * * /usr/local/bin/daily-run.sh >> /var/lib/syslog-reporter/daily-run.log 2>&1
#
# A non-zero exit means that attempt did not send the report. Pass a
# date to re-run a specific day by hand; an explicit date ignores the
# .sent marker:
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

# One attempt at a time. flock(1) is util-linux; the lock lives on the
# open descriptor, not the file, so a stale daily-run.lock on disk
# blocks nothing. The fetch and the reporter inherit fd 9 on purpose:
# while either is running, even orphaned, the lock stays held and no
# second copy starts against the same database.
command -v flock >/dev/null || { echo "daily-run.sh needs flock (util-linux)" >&2; exit 1; }
lock="$WORK_DIR/daily-run.lock"
exec 9>"$lock"
if ! flock -n 9; then
    echo "another daily-run is still going (lock: $lock; find the holder with: fuser -v $lock); leaving it to finish"
    exit 0
fi

# Run a command as a child we can kill. A signal to this script kills
# the child too, so killing daily-run.sh and killing the reporter come
# to the same thing: the lock clears and the next attempt retries.
# Always TERM, whatever we were sent: bash starts background children
# with SIGINT ignored.
child=
on_signal() {
    if [ -n "$child" ]; then
        kill -TERM "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    exit 143
}
trap on_signal TERM INT
run_child() {
    "$@" &
    child=$!
    wait "$child"
}

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
partial="$DUMP_DIR/syslog-$day.partial.ndjson.gz"
sent="$DUMP_DIR/syslog-$day.sent"

# Already went out today: the hourly retries have nothing to do.
if [ $# -eq 0 ] && [ -e "$sent" ]; then
    exit 0
fi

mkdir -p "$DUMP_DIR"

# elk_dump.py writes straight to --out and leaves a truncated file
# behind when the fetch dies part-way, so fetch under a partial name
# and rename only on success: a file under the final name is always a
# complete day. Both elk_dump.py and the reporter pick gzip by the .gz
# suffix, hence the infix rather than a trailing .part.
if [ ! -s "$dump" ]; then
    run_child python3 "$ELK_DUMP" --day "$day" --out "$partial"
    mv "$partial" "$dump"
fi

run_child "$REPORTER" run "$dump" --date "$day" --send-email --out-dir "$OUT_DIR"
touch "$sent"

# Optional: tidy up dumps, partials and sent markers older than two weeks.
# find "$DUMP_DIR" -name 'syslog-*' -mtime +14 -delete
