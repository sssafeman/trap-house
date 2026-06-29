#!/usr/bin/env python3
"""
Trap House MITRE Mapper

Reads events from SQLite, maps them to MITRE ATT&CK techniques using
both static event-type mapping and regex-based pattern matching, and
writes enriched technique data back to SQLite.

Runs as a periodic poller: every N seconds it queries for unmapped events,
maps them, and updates the database.
"""

import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

import yaml

DB_PATH = os.environ.get("DB_PATH", "/data/db/trap-house.db")
TECHNIQUES_FILE = os.environ.get("TECHNIQUES_FILE", "/config/mitre-techniques.yaml")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "5"))


def load_techniques(filepath: str) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Load the YAML technique database. Returns (static_map, pattern_list)."""
    with open(filepath, "r") as f:
        data = yaml.safe_load(f)

    static_map: dict[str, dict[str, Any]] = {}
    for tech in data.get("techniques", []):
        for event_type in tech.get("event_types", []):
            static_map[event_type] = {
                "id": tech["id"],
                "name": tech["name"],
                "subtechnique": tech.get("subtechnique", ""),
                "tactic": tech["tactic"],
                "description": tech.get("description", ""),
            }

    patterns: list[dict[str, Any]] = []
    for pat in data.get("patterns", []):
        patterns.append({
            "technique": pat["technique"],
            "name": pat["name"],
            "subtechnique": pat.get("subtechnique", ""),
            "tactic": pat["tactic"],
            "regex": re.compile(pat["regex"], re.IGNORECASE),
            "field": pat["field"],
            "description": pat.get("description", ""),
        })

    return static_map, patterns


def init_db(conn: sqlite3.Connection) -> None:
    """Create the techniques and attackers tables if they do not exist."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS techniques (
            technique_id TEXT,
            event_id TEXT,
            name TEXT,
            subtechnique TEXT,
            tactic TEXT,
            description TEXT,
            match_type TEXT,
            PRIMARY KEY (technique_id, event_id)
        );

        CREATE TABLE IF NOT EXISTS attackers (
            source_ip TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            event_count INTEGER DEFAULT 0,
            session_count INTEGER DEFAULT 0,
            tools_detected TEXT,
            mitre_techniques TEXT,
            top_username TEXT,
            protocols TEXT,
            risk_score REAL DEFAULT 0.0
        );

        CREATE INDEX IF NOT EXISTS idx_techniques_event ON techniques(event_id);
        CREATE INDEX IF NOT EXISTS idx_techniques_technique ON techniques(technique_id);
        CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attackers(source_ip);
        """
    )
    conn.commit()


def map_event(
    event: dict[str, Any],
    static_map: dict[str, dict[str, Any]],
    patterns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map a single event to MITRE techniques. Returns list of matches."""
    matches: list[dict[str, Any]] = []
    event_type = event.get("event_type", "")
    event_id = event.get("event_id", "")

    # Static event-type mapping
    if event_type in static_map:
        tech = static_map[event_type]
        matches.append({
            "technique_id": tech["id"],
            "event_id": event_id,
            "name": tech["name"],
            "subtechnique": tech.get("subtechnique", ""),
            "tactic": tech["tactic"],
            "description": tech.get("description", ""),
            "match_type": "event_type",
        })

    # Regex pattern matching against raw_data and details
    raw_data_str = event.get("raw_data", "") or ""
    details_str = event.get("details", "") or ""
    command = event.get("command", "") or ""

    # Build a combined text to search
    search_text = " ".join([raw_data_str, details_str, command])

    for pat in patterns:
        field_value = ""
        if pat["field"] == "raw_data":
            field_value = raw_data_str
        elif pat["field"] == "details":
            field_value = details_str
        else:
            field_value = search_text

        if pat["regex"].search(field_value):
            # Avoid duplicate technique matches for the same event
            existing_ids = {m["technique_id"] for m in matches}
            if pat["technique"] not in existing_ids:
                matches.append({
                    "technique_id": pat["technique"],
                    "event_id": event_id,
                    "name": pat["name"],
                    "subtechnique": pat.get("subtechnique", ""),
                    "tactic": pat["tactic"],
                    "description": pat.get("description", ""),
                    "match_type": "pattern",
                })

    return matches


def write_techniques(conn: sqlite3.Connection, matches: list[dict[str, Any]]) -> None:
    """Write technique matches to the techniques table."""
    for m in matches:
        conn.execute(
            """
            INSERT OR IGNORE INTO techniques
            (technique_id, event_id, name, subtechnique, tactic, description, match_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                m["technique_id"], m["event_id"], m["name"],
                m["subtechnique"], m["tactic"], m["description"],
                m["match_type"],
            ),
        )
    conn.commit()


def update_attackers(conn: sqlite3.Connection) -> None:
    """Aggregate attacker profiles from events."""
    # Get or update attacker records
    rows = conn.execute(
        """
        SELECT source_ip,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen,
               COUNT(*) as event_count,
               COUNT(DISTINCT session_id) as session_count,
               GROUP_CONCAT(DISTINCT username) as usernames,
               GROUP_CONCAT(DISTINCT protocol) as protocols
        FROM events
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip
        """
    ).fetchall()

    for row in rows:
        ip, first_seen, last_seen, event_count, session_count, usernames, protocols = row

        # Detect tools from fingerprints
        tools: set[str] = set()
        fp_rows = conn.execute(
            "SELECT attacker_fingerprint FROM events WHERE source_ip = ? AND attacker_fingerprint IS NOT NULL",
            (ip,),
        ).fetchall()
        for fp_row in fp_rows:
            try:
                fp = json.loads(fp_row[0])
                tool = fp.get("tool", "")
                if tool and tool != "unknown":
                    tools.add(tool)
            except (json.JSONDecodeError, TypeError):
                pass

        # Get MITRE techniques for this attacker
        tech_rows = conn.execute(
            """
            SELECT DISTINCT t.technique_id
            FROM techniques t
            JOIN events e ON t.event_id = e.event_id
            WHERE e.source_ip = ?
            """,
            (ip,),
        ).fetchall()
        techniques_list = [r[0] for r in tech_rows]

        # Risk score: weighted by technique diversity, session count, and tool detection
        risk = 0.0
        risk += len(techniques_list) * 2.0
        risk += min(session_count or 0, 10) * 1.0
        risk += len(tools) * 3.0
        risk += min(event_count or 0, 50) * 0.1
        risk = min(risk, 100.0)

        # Top username (most frequently used)
        top_username = ""
        if usernames:
            uname_list = [u for u in (usernames or "").split(",") if u]
            if uname_list:
                top_username = max(set(uname_list), key=uname_list.count)

        conn.execute(
            """
            INSERT INTO attackers
            (source_ip, first_seen, last_seen, event_count, session_count,
             tools_detected, mitre_techniques, top_username, protocols, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_ip) DO UPDATE SET
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                event_count = excluded.event_count,
                session_count = excluded.session_count,
                tools_detected = excluded.tools_detected,
                mitre_techniques = excluded.mitre_techniques,
                top_username = excluded.top_username,
                protocols = excluded.protocols,
                risk_score = excluded.risk_score
            """,
            (
                ip, first_seen, last_seen, event_count or 0, session_count or 0,
                json.dumps(sorted(tools)), json.dumps(techniques_list),
                top_username, protocols or "",
                risk,
            ),
        )
    conn.commit()


def get_unmapped_events(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Get events that have not yet been mapped to techniques."""
    rows = conn.execute(
        """
        SELECT e.event_id, e.event_type, e.raw_data, e.details, e.command,
               e.attacker_fingerprint
        FROM events e
        LEFT JOIN techniques t ON e.event_id = t.event_id
        WHERE t.event_id IS NULL
        ORDER BY e.timestamp ASC
        LIMIT 500
        """
    ).fetchall()

    events: list[dict[str, Any]] = []
    for row in rows:
        events.append({
            "event_id": row[0],
            "event_type": row[1],
            "raw_data": row[2] or "",
            "details": row[3] or "",
            "command": row[4] or "",
            "attacker_fingerprint": row[5],
        })
    return events


def main() -> None:
    print(f"[mitre-mapper] Starting. DB={DB_PATH}, techniques={TECHNIQUES_FILE}")
    static_map, patterns = load_techniques(TECHNIQUES_FILE)
    print(f"[mitre-mapper] Loaded {len(static_map)} static mappings, {len(patterns)} regex patterns")

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    print("[mitre-mapper] Database initialized (techniques, attackers tables)")

    cycle = 0
    while True:
        # Get unmapped events
        unmapped = get_unmapped_events(conn)

        if unmapped:
            all_matches: list[dict[str, Any]] = []
            for event in unmapped:
                matches = map_event(event, static_map, patterns)
                all_matches.extend(matches)
            write_techniques(conn, all_matches)
            print(f"[mitre-mapper] Cycle {cycle}: mapped {len(unmapped)} events, found {len(all_matches)} technique matches")

            # Update attacker profiles after mapping
            update_attackers(conn)
            if cycle % 6 == 0:  # Update attacker profiles every 30 seconds (6 cycles * 5s)
                update_attackers(conn)
                print(f"[mitre-mapper] Updated attacker profiles")
        else:
            # Still update attacker profiles periodically
            if cycle % 12 == 0:
                update_attackers(conn)

        cycle += 1
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()