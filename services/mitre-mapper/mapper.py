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
from typing import Any

import yaml

DB_PATH = os.environ.get("DB_PATH", "/data/db/trap-house.db")
TECHNIQUES_FILE = os.environ.get("TECHNIQUES_FILE", "/config/mitre-techniques.yaml")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "5"))
MAPPING_BATCH_SIZE = 500
ACTIVE_PROFILE_INTERVAL = 6
IDLE_PROFILE_INTERVAL = 12

TECHNIQUE_INSERT_SQL = """
INSERT OR IGNORE INTO techniques
(technique_id, event_id, name, subtechnique, tactic, description, match_type)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

ATTACKER_AGGREGATES_SQL = """
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

ATTACKER_UPSERT_SQL = """
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
"""

UNMAPPED_EVENTS_SQL = f"""
SELECT e.event_id, e.event_type, e.raw_data, e.details, e.command,
       e.attacker_fingerprint
FROM events e
LEFT JOIN mapping_state ms ON e.event_id = ms.event_id
WHERE ms.event_id IS NULL
ORDER BY e.timestamp ASC
LIMIT {MAPPING_BATCH_SIZE}
"""


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

        -- Records every event the mapper has processed, whether or not it
        -- produced a technique match. Without this, events that match no
        -- technique (session_disconnect, client_version, and similar) would
        -- never get a techniques row and would be re-fetched forever, stalling
        -- the mapper once 500 such events accumulate.
        CREATE TABLE IF NOT EXISTS mapping_state (
            event_id TEXT PRIMARY KEY
        );

        CREATE INDEX IF NOT EXISTS idx_techniques_event ON techniques(event_id);
        CREATE INDEX IF NOT EXISTS idx_techniques_technique ON techniques(technique_id);
        CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attackers(source_ip);
        """
    )
    conn.commit()


def _build_match(
    event_id: str,
    technique_id: str,
    technique: dict[str, Any],
    match_type: str,
) -> dict[str, Any]:
    """Build the common stored shape for a MITRE technique match."""
    return {
        "technique_id": technique_id,
        "event_id": event_id,
        "name": technique["name"],
        "subtechnique": technique.get("subtechnique", ""),
        "tactic": technique["tactic"],
        "description": technique.get("description", ""),
        "match_type": match_type,
    }


def _pattern_search_text(
    pattern: dict[str, Any],
    raw_data: str,
    details: str,
    combined: str,
) -> str:
    """Select the configured event text for a regex pattern."""
    if pattern["field"] == "raw_data":
        return raw_data
    if pattern["field"] == "details":
        return details
    return combined


def map_event(
    event: dict[str, Any],
    static_map: dict[str, dict[str, Any]],
    patterns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map a single event to MITRE techniques. Returns list of matches."""
    matches: list[dict[str, Any]] = []
    event_type = event.get("event_type", "")
    event_id = event.get("event_id", "")

    seen_ids: set[str] = set()
    if event_type in static_map:
        technique = static_map[event_type]
        technique_id = technique["id"]
        matches.append(
            _build_match(event_id, technique_id, technique, "event_type")
        )
        seen_ids.add(technique_id)

    # Regex pattern matching against raw_data and details
    raw_data_str = event.get("raw_data", "") or ""
    details_str = event.get("details", "") or ""
    command = event.get("command", "") or ""

    search_text = " ".join([raw_data_str, details_str, command])

    for pattern in patterns:
        field_value = _pattern_search_text(
            pattern,
            raw_data_str,
            details_str,
            search_text,
        )
        if not pattern["regex"].search(field_value):
            continue

        technique_id = pattern["technique"]
        if technique_id in seen_ids:
            continue
        matches.append(
            _build_match(event_id, technique_id, pattern, "pattern")
        )
        seen_ids.add(technique_id)

    return matches


def write_techniques(conn: sqlite3.Connection, matches: list[dict[str, Any]]) -> None:
    """Write technique matches to the techniques table."""
    for m in matches:
        conn.execute(
            TECHNIQUE_INSERT_SQL,
            (
                m["technique_id"], m["event_id"], m["name"],
                m["subtechnique"], m["tactic"], m["description"],
                m["match_type"],
            ),
        )
    conn.commit()


def _attacker_tools(conn: sqlite3.Connection, source_ip: str) -> set[str]:
    """Extract known tool labels from an attacker's event fingerprints."""
    rows = conn.execute(
        "SELECT attacker_fingerprint FROM events "
        "WHERE source_ip = ? AND attacker_fingerprint IS NOT NULL",
        (source_ip,),
    ).fetchall()
    tools: set[str] = set()
    for row in rows:
        try:
            fingerprint = json.loads(row[0])
            tool = fingerprint.get("tool", "")
            if tool and tool != "unknown":
                tools.add(tool)
        except (json.JSONDecodeError, TypeError):
            pass
    return tools


def _attacker_techniques(
    conn: sqlite3.Connection,
    source_ip: str,
) -> list[str]:
    """Return distinct mapped technique IDs for an attacker."""
    rows = conn.execute(
        """
        SELECT DISTINCT t.technique_id
        FROM techniques t
        JOIN events e ON t.event_id = e.event_id
        WHERE e.source_ip = ?
        """,
        (source_ip,),
    ).fetchall()
    return [row[0] for row in rows]


def _risk_score(
    technique_ids: list[str],
    session_count: int | None,
    tools: set[str],
    event_count: int | None,
) -> float:
    """Calculate the existing weighted attacker risk score."""
    risk = 0.0
    risk += len(technique_ids) * 2.0
    risk += min(session_count or 0, 10) * 1.0
    risk += len(tools) * 3.0
    risk += min(event_count or 0, 50) * 0.1
    return min(risk, 100.0)


def _top_username(usernames: str | None) -> str:
    """Select the top username using the existing aggregation semantics."""
    if not usernames:
        return ""
    username_list = [username for username in usernames.split(",") if username]
    if not username_list:
        return ""
    return max(set(username_list), key=username_list.count)


def _attacker_values(
    conn: sqlite3.Connection,
    row: tuple[Any, ...],
) -> tuple[Any, ...]:
    """Build the values persisted for one attacker aggregate row."""
    (
        source_ip,
        first_seen,
        last_seen,
        event_count,
        session_count,
        usernames,
        protocols,
    ) = row
    tools = _attacker_tools(conn, source_ip)
    technique_ids = _attacker_techniques(conn, source_ip)

    return (
        source_ip,
        first_seen,
        last_seen,
        event_count or 0,
        session_count or 0,
        json.dumps(sorted(tools)),
        json.dumps(technique_ids),
        _top_username(usernames),
        protocols or "",
        _risk_score(technique_ids, session_count, tools, event_count),
    )


def update_attackers(conn: sqlite3.Connection) -> None:
    """Aggregate attacker profiles from events."""
    rows = conn.execute(ATTACKER_AGGREGATES_SQL).fetchall()

    for row in rows:
        conn.execute(ATTACKER_UPSERT_SQL, _attacker_values(conn, row))
    conn.commit()


def _unmapped_event(row: tuple[Any, ...]) -> dict[str, Any]:
    """Convert a positional unmapped-event row to the mapping shape."""
    return {
        "event_id": row[0],
        "event_type": row[1],
        "raw_data": row[2] or "",
        "details": row[3] or "",
        "command": row[4] or "",
        "attacker_fingerprint": row[5],
    }


def get_unmapped_events(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Get events the mapper has not processed yet.

    "Unprocessed" means absent from mapping_state, not absent from techniques,
    so events that legitimately match no technique are still retired after one
    pass instead of being re-fetched on every cycle.
    """
    rows = conn.execute(UNMAPPED_EVENTS_SQL).fetchall()
    return [_unmapped_event(row) for row in rows]


def mark_mapped(conn: sqlite3.Connection, event_ids: list[str]) -> None:
    """Record that these events have been processed, so they are not re-fetched."""
    conn.executemany(
        "INSERT OR IGNORE INTO mapping_state (event_id) VALUES (?)",
        [(eid,) for eid in event_ids],
    )
    conn.commit()


def _map_events(
    events: list[dict[str, Any]],
    static_map: dict[str, dict[str, Any]],
    patterns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect all technique matches for an event batch in event order."""
    matches: list[dict[str, Any]] = []
    for event in events:
        matches.extend(map_event(event, static_map, patterns))
    return matches


def _store_mappings(
    conn: sqlite3.Connection,
    events: list[dict[str, Any]],
    static_map: dict[str, dict[str, Any]],
    patterns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map a batch, persist matches, then retire every processed event."""
    matches = _map_events(events, static_map, patterns)
    write_techniques(conn, matches)
    mark_mapped(conn, [event["event_id"] for event in events])
    return matches


def _update_profiles_if_due(
    conn: sqlite3.Connection,
    cycle: int,
    mapped_events: bool,
) -> None:
    """Refresh attacker profiles on the active or idle cycle cadence."""
    interval = (
        ACTIVE_PROFILE_INTERVAL if mapped_events else IDLE_PROFILE_INTERVAL
    )
    if cycle % interval != 0:
        return
    update_attackers(conn)
    if mapped_events:
        print("[mitre-mapper] Updated attacker profiles")


def main() -> None:
    print(f"[mitre-mapper] Starting. DB={DB_PATH}, techniques={TECHNIQUES_FILE}")
    static_map, patterns = load_techniques(TECHNIQUES_FILE)
    print(
        f"[mitre-mapper] Loaded {len(static_map)} static mappings, "
        f"{len(patterns)} regex patterns"
    )

    # busy_timeout lets the mapper wait out short lock windows from the
    # shipper, which writes the same database concurrently, instead of
    # raising OperationalError.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    init_db(conn)
    print(
        "[mitre-mapper] Database initialized "
        "(techniques, attackers, mapping_state tables)"
    )

    cycle = 0
    while True:
        try:
            unmapped = get_unmapped_events(conn)

            if unmapped:
                matches = _store_mappings(
                    conn,
                    unmapped,
                    static_map,
                    patterns,
                )
                print(
                    f"[mitre-mapper] Cycle {cycle}: mapped {len(unmapped)} "
                    f"events, found {len(matches)} technique matches"
                )

            _update_profiles_if_due(conn, cycle, bool(unmapped))
        except Exception as error:
            # Never let a transient DB error or a single malformed event kill
            # the poller. Log and continue to the next cycle.
            print(f"[mitre-mapper] Cycle {cycle} error (non-fatal): {error}")

        cycle += 1
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
