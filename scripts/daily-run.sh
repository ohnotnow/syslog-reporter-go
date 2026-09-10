#!/usr/bin/env bash
#
# The daily syslog-reporter run, shaped for cron: fetch yesterday's
# dump from ELK, run the full pipeline, and either email the day's
# report, say nothing, or email the weekly digest instead.
#
#   daily-run.sh [--no-email] [--digest] [YYYY-MM-DD]
#
# With neither option the day's report is emailed, as it always was.
# --no-email runs and files the day into the findings library without
# emailing anyone. --digest does the same and then emails the weekly
# digest: the findings that kept recurring over the last DIGEST_DAYS
# days (default 7), with fresh resolutions from SYSLOG_DIGEST_MODEL.
# The recommended shape is a quiet week and one digest: the team gets
# one email they will actually read, and the expensive model runs once.
#
# Schedule it hourly rather than once. The first attempt that gets all
# the way through leaves a syslog-<day>.sent marker in DUMP_DIR (and,
# with --digest, a syslog-<day>.digest.sent once the digest went out),
# and every later attempt that day exits 0 without a word, so a flaky
# ELK proxy only costs a retry an hour later. Each marker is written
# after its own step succeeds, so a failed or killed attempt never
# blocks the retries, and a digest that failed is retried on its own
# without re-running the day. One attempt runs at a time (flock).
# Killing this script (SIGTERM or SIGINT) also kills whichever fetch or
# reporter it is waiting on, so the lock clears and the next hourly
# attempt retries.
#
#   # crontab: run and file every day, first try at 07:30 and retried
#   # on the half hour; on Mondays email the digest of the week instead
#   MAILTO=you@example.ac.uk
#   30 7-17 * * 0,2-6 /usr/local/bin/daily-run.sh --no-email >> /var/lib/syslog-reporter/daily-run.log 2>&1
#   30 7-17 * * 1     /usr/local/bin/daily-run.sh --digest   >> /var/lib/syslog-reporter/daily-run.log 2>&1
#
# The models live in the .env: SYSLOG_LOGSCAN_MODEL and SYSLOG_ISSUE_MODEL
# (cheap, every day) and SYSLOG_DIGEST_MODEL (smart, once a week).
#
# A non-zero exit means that attempt did not finish (the report or the
# digest did not go out). Pass a date to re-run a specific day by hand;
# an explicit date ignores the .sent marker and cannot be combined with
# --digest. The digest has no date of its own: its window always ends
# yesterday, so a missed Monday is recovered by hand with a wider
# window, on any day:
#   daily-run.sh 2026-08-27
#   syslog-reporter digest --days 14 --send-email   # from WORK_DIR
#
# Defaults match the deployment laid out in GETTING_STARTED.md: binary
# and elk_dump.py in /usr/local/bin, with the .env, database, dumps and
# reports under /var/lib/syslog-reporter. Configuration (models, API
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
DIGEST_DAYS=${DIGEST_DAYS:-7}

usage() {
    echo "usage: daily-run.sh [--no-email] [--digest] [YYYY-MM-DD]" >&2
    exit 2
}

# Options come before the optional date. --digest implies --no-email:
# on digest day the digest replaces the day's report, never joins it.
email_day=1
digest=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-email) email_day=0 ;;
        --digest)   email_day=0; digest=1 ;;
        --help|-h)  usage ;;
        --*)        echo "daily-run.sh: unknown option $1" >&2; usage ;;
        *)          break ;;
    esac
    shift
done
[ $# -le 1 ] || usage
# The digest's window always ends yesterday and re-filing it replaces
# this week's digest (and its feedback votes), so it never rides along
# with a by-hand re-run of an old day: use the binary's digest command.
if [ "$digest" = 1 ] && [ $# -eq 1 ]; then
    echo "daily-run.sh: --digest takes no date (the window always ends yesterday); re-run the day alone, then: $REPORTER digest --days N --send-email" >&2
    exit 2
fi

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
digest_sent="$DUMP_DIR/syslog-$day.digest.sent"

# Already done today: the hourly retries have nothing to do. The day's
# run and the digest keep separate markers, so a digest that failed
# (provider down, relay down) is retried on its own without re-running
# the paid daily pipeline and re-filing the day.
if [ $# -eq 0 ] && [ -e "$sent" ]; then
    if [ "$digest" = 0 ] || [ -e "$digest_sent" ]; then
        exit 0
    fi
    run_child "$REPORTER" digest --days "$DIGEST_DAYS" --send-email --out-dir "$OUT_DIR"
    touch "$digest_sent"
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

if [ "$email_day" = 1 ]; then
    run_child "$REPORTER" run "$dump" --date "$day" --send-email --out-dir "$OUT_DIR"
else
    run_child "$REPORTER" run "$dump" --date "$day" --out-dir "$OUT_DIR"
fi
touch "$sent"
if [ "$digest" = 1 ]; then
    run_child "$REPORTER" digest --days "$DIGEST_DAYS" --send-email --out-dir "$OUT_DIR"
    touch "$digest_sent"
fi

# Optional: tidy up dumps, partials and sent markers older than two weeks.
# find "$DUMP_DIR" -name 'syslog-*' -mtime +14 -delete
