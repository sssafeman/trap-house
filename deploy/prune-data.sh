#!/usr/bin/env bash
# prune-data.sh: Enforce the Trap House retention policy.
# Deletes intel-store rows and honeypot JSONL log lines older than the
# configured retention windows. Safe to run repeatedly; intended as a cron job.
#
# Container stdout is already rotated by the json-file logging driver
# (docker-compose.yml). This script handles the two unbounded stores that
# driver does not touch: the SQLite database and the bind-mounted JSONL logs
# that Cowrie and deception-gw append to.
#
# Usage:
#   bash deploy/prune-data.sh                 # uses .env.hetzner if present
#   DB_RETENTION_DAYS=180 LOG_RETENTION_DAYS=90 bash deploy/prune-data.sh
#
# Suggested cron (daily at 04:15):
#   15 4 * * * cd /opt/trap-house && bash deploy/prune-data.sh >> data/prune.log 2>&1

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

# Load retention values from the env file if it exists, then fall back to
# environment, then to defaults.
if [ -f .env.hetzner ]; then
  # shellcheck disable=SC1091
  set -a; . ./.env.hetzner; set +a
elif [ -f .env ]; then
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
fi

DB_RETENTION_DAYS="${DB_RETENTION_DAYS:-180}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
DB_PATH="${PROJECT_DIR}/data/db/trap-house.db"
COWRIE_LOG="${PROJECT_DIR}/data/logs/cowrie/cowrie.json"
DECEPTION_LOG="${PROJECT_DIR}/data/logs/deception-gw/deception-gw.json"

echo "=== Trap House prune $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "DB retention: ${DB_RETENTION_DAYS}d, log retention: ${LOG_RETENTION_DAYS}d"

python3 - "$DB_PATH" "$DB_RETENTION_DAYS" "$COWRIE_LOG" "$DECEPTION_LOG" "$LOG_RETENTION_DAYS" <<'PY'
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

db_path, db_days, cowrie_log, deception_log, log_days = sys.argv[1:6]
db_days = int(db_days)
log_days = int(log_days)

# 1) Prune the intel store.
db_cutoff = (datetime.now(timezone.utc) - timedelta(days=db_days)).isoformat()
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    old = conn.execute("SELECT COUNT(*) FROM events WHERE timestamp < ?", (db_cutoff,)).fetchone()[0]
    conn.execute("DELETE FROM events WHERE timestamp < ?", (db_cutoff,))
    # Drop bookkeeping rows that no longer reference a live event.
    conn.execute("DELETE FROM techniques WHERE event_id NOT IN (SELECT event_id FROM events)")
    conn.execute("DELETE FROM mapping_state WHERE event_id NOT IN (SELECT event_id FROM events)")
    conn.execute("DELETE FROM sessions WHERE session_id NOT IN (SELECT DISTINCT session_id FROM events)")
    conn.commit()
    conn.close()
    print(f"  DB: deleted {old} events older than {db_cutoff}")
else:
    print(f"  DB: {db_path} not found, skipping")

# 2) Prune the append-only JSONL logs by their embedded timestamps.
# The shipper tracks byte offsets and resets when a file shrinks, so rewriting
# these files smaller is safe.
log_cutoff = (datetime.now(timezone.utc) - timedelta(days=log_days)).isoformat()

def prune_jsonl(path):
    if not os.path.exists(path):
        print(f"  log: {path} not found, skipping")
        return
    kept, dropped = [], 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            try:
                ts = json.loads(s).get("timestamp", "")
            except json.JSONDecodeError:
                kept.append(line)  # keep unparseable lines rather than lose data
                continue
            if ts and ts < log_cutoff:
                dropped += 1
            else:
                kept.append(line)
    tmp = path + ".prune.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(kept)
    os.replace(tmp, path)
    print(f"  log: {os.path.basename(path)}: dropped {dropped} lines older than {log_cutoff}")

prune_jsonl(cowrie_log)
prune_jsonl(deception_log)
PY

echo "=== prune complete ==="
