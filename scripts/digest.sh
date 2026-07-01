#!/usr/bin/env bash
# Trap House daily digest: SSHes into the VPS, pulls honeypot stats, saves to disk.
# Runs as a cron job. Zero token cost. Output is a dated markdown file.
# No em dashes or double hyphens in any output.

set -euo pipefail

VPS_HOST="104.248.39.157"
VPS_USER="smz"
VPS_PORT="22"
DIGEST_DIR="${HOME}/projects/trap-house/digests"
DATE=$(date +%Y-%m-%d)
OUTFILE="${DIGEST_DIR}/${DATE}.md"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=15"

mkdir -p "${DIGEST_DIR}"

# The Python script that runs on the VPS. Copied and executed remotely.
# Uses single quotes to prevent local expansion. No nested double quotes.
REMOTE_SCRIPT='
import sqlite3, os, json, datetime

db = "/opt/trap-house/data/db/trap-house.db"
if not os.path.exists(db):
    print("# Trap House Daily Digest: ERROR\n\nDB not found at", db)
    exit()

conn = sqlite3.connect(db)
c = conn.cursor()

c.execute("SELECT COUNT(*) FROM events")
total = c.fetchone()[0]
c.execute("SELECT COUNT(DISTINCT source_ip) FROM events")
uniq = c.fetchone()[0]

# Yesterday vs today comparison
today = datetime.date.today().isoformat()
yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (yesterday + "T00:00:00",))
y_events = c.fetchone()[0]
c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (today + "T00:00:00",))
t_events = c.fetchone()[0]

c.execute("SELECT source_service, COUNT(*) FROM events GROUP BY source_service ORDER BY COUNT(*) DESC")
by_svc = c.fetchall()
c.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 12")
by_type = c.fetchall()
c.execute("SELECT source_ip, COUNT(*) FROM events GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10")
top_ips = c.fetchall()
c.execute("SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1")
latest = c.fetchone()

c.execute("SELECT source_ip, event_count, session_count, risk_score, top_username, mitre_techniques FROM attackers ORDER BY risk_score DESC LIMIT 5")
profiles = c.fetchall()

c.execute("SELECT technique_id, name, COUNT(*) as cnt FROM techniques GROUP BY technique_id ORDER BY cnt DESC LIMIT 12")
techs = c.fetchall()

c.execute("SELECT COUNT(*) FROM sessions")
total_sessions = c.fetchone()[0]

c.execute("SELECT source_ip, event_type, source_service, timestamp, dest_port, username, command FROM events ORDER BY timestamp DESC LIMIT 10")
recent = c.fetchall()

print(f"# Trap House Daily Digest: {today}")
print()
now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
print(f"Generated: {now_utc}")
print()
print("## Summary")
print()
print(f"- Total events: {total}")
print(f"- Total unique attacker IPs: {uniq}")
print(f"- Total sessions: {total_sessions}")
print(f"- Events in last 24h (since {yesterday}): {y_events}")
print(f"- Events today (since {today}): {t_events}")
latest_str = latest[0] if latest else "none"
print(f"- Latest event: {latest_str}")
print()
print("## By Service")
print()
for s, n in by_svc:
    print(f"- {s}: {n}")
print()
print("## By Event Type")
print()
for t, n in by_type:
    print(f"- {t}: {n}")
print()
print("## Top 10 Attacker IPs")
print()
for ip, n in top_ips:
    print(f"- {ip}: {n} events")
print()
print("## Top 5 Attacker Profiles (by risk score)")
print()
for ip, ec, sc, rs, tu, mt in profiles:
    mt_list = json.loads(mt) if mt else []
    print(f"- **{ip}** | events={ec} sessions={sc} risk={rs} top_user={tu} mitre={len(mt_list)} techniques")
print()
print("## MITRE ATT&CK Techniques Detected")
print()
for tid, name, cnt in techs:
    print(f"- {tid}: {name} ({cnt} hits)")
print()
print("## Last 10 Events")
print()
print("| timestamp | service | port | type | source_ip | user | command |")
print("|-----------|---------|------|------|-----------|------|---------|")
for ip, t, s, ts, dp, u, cmd in recent:
    u = u or ""
    cmd = cmd or ""
    if len(cmd) > 40:
        cmd = cmd[:37] + "..."
    print(f"| {ts} | {s} | {dp} | {t} | {ip} | {u} | {cmd} |")
print()
conn.close()
'

# Copy the remote script and run it
TMP_SCRIPT="/tmp/trap_house_digest_$$.py"
echo "${REMOTE_SCRIPT}" > "${TMP_SCRIPT}"
scp ${SSH_OPTS} "${TMP_SCRIPT}" "${VPS_USER}@${VPS_HOST}:/tmp/trap_house_digest.py" 2>/dev/null
rm -f "${TMP_SCRIPT}"

DIGEST=$(ssh ${SSH_OPTS} -p "${VPS_PORT}" "${VPS_USER}@${VPS_HOST}" 'python3 /tmp/trap_house_digest.py' 2>/dev/null)

if [ -z "${DIGEST}" ]; then
    echo "# Trap House Daily Digest: ${DATE}" > "${OUTFILE}"
    echo "" >> "${OUTFILE}"
    echo "ERROR: Failed to connect to VPS or retrieve data." >> "${OUTFILE}"
    echo "Check SSH connectivity to ${VPS_HOST}" >> "${OUTFILE}"
    exit 1
fi

echo "${DIGEST}" > "${OUTFILE}"
echo "${OUTFILE}"