#!/usr/bin/env bash
#
# Bootstrap the syslog-reporter history by running the last N days
# through the pipeline with --no-llm (so it costs nothing). Two of the
# three anomaly detectors compare against stored history, so a fresh
# install benefits from a couple of weeks of backfill before the first
# real run.
#
# Usage:
#   backfill.sh [days]     # default 14
#
# Defaults match the deployment laid out in GETTING_STARTED.md: binary
# and elk_dump.py in /usr/local/bin, with the .env, database and dumps
# under /var/lib/syslog-reporter. Trying it from a checkout instead:
#   REPORTER=./syslog-reporter ELK_DUMP=./tools/elk_dump.py WORK_DIR=. \
#     ./scripts/backfill.sh 3
#
# For each day it looks for syslog-<day>.ndjson.gz in DUMP_DIR and, if
# missing, fetches it from ELK with elk_dump.py (configure ELK_URL,
# ELK_INDEX and credentials in the .env - see the notes at the top of
# tools/elk_dump.py). No ELK? Put per-day files in DUMP_DIR yourself
# and adjust the dump= line to match your naming - raw rsyslog text
# works too, e.g.
#   grep '^Aug 28 ' /var/log/syslog > dumps/syslog-2026-08-28.log
#
# Days run oldest first so each day's detectors see the history built
# up before it. Re-running a day is safe: it replaces that day's
# stored aggregates and findings.

set -euo pipefail

REPORTER=${REPORTER:-/usr/local/bin/syslog-reporter}
ELK_DUMP=${ELK_DUMP:-/usr/local/bin/elk_dump.py}
WORK_DIR=${WORK_DIR:-/var/lib/syslog-reporter}
DUMP_DIR=${DUMP_DIR:-$WORK_DIR/dumps}
DAYS=${1:-14}

# Both the binary and elk_dump.py read a .env from the working
# directory, and the SQLite history lands here too.
cd "$WORK_DIR"

# GNU date (Linux) and BSD date (macOS) disagree on relative dates.
days_ago() {
    if date -d yesterday +%Y-%m-%d >/dev/null 2>&1; then
        date -d "$1 days ago" +%Y-%m-%d
    else
        date -v -"$1"d +%Y-%m-%d
    fi
}

mkdir -p "$DUMP_DIR"
failures=0

for ((i = DAYS; i >= 1; i--)); do
    day=$(days_ago "$i")
    dump="$DUMP_DIR/syslog-$day.ndjson.gz"

    if [ ! -s "$dump" ]; then
        echo "== $day: fetching from ELK"
        if ! python3 "$ELK_DUMP" --day "$day" --out "$dump"; then
            echo "WARN: $day: dump failed, skipping" >&2
            rm -f "$dump"
            failures=$((failures + 1))
            continue
        fi
    fi

    echo "== $day: running (no LLM)"
    if ! "$REPORTER" run "$dump" --date "$day" --no-llm; then
        echo "WARN: $day: run failed" >&2
        failures=$((failures + 1))
    fi
done

if [ "$failures" -gt 0 ]; then
    echo "backfill finished with $failures failed day(s)" >&2
    exit 1
fi
echo "backfill complete: $DAYS day(s) of history stored"
