#!/usr/bin/env python3
"""
Trap House Log Shipper

Reads raw JSON logs from honeypot services (Cowrie, Endlessh),
normalizes them to the shared Trap House event schema (EVENT_SCHEMA.md),
writes to a SQLite database, and pushes to Loki for Grafana visualization.

Cowrie: reads JSONL from /var/log/trap-house/cowrie/cowrie.json
Endlessh: reads stdout via `docker logs` (requires Docker socket mount)
deception-gw: reads JSONL from /var/log/trap-house/deception-gw/deception-gw.json
Loki: pushes normalized events to http://loki:3100/loki/api/v1/push
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Configuration
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/trap-house"))
DB_PATH = os.environ.get("DB_PATH", "/data/db/trap-house.db")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2"))
ENDLESSH_CONTAINER = os.environ.get("ENDLESSH_CONTAINER", "trap-endlessh")
# Public-facing port attackers hit on the tarpit (22 in prod, 22222 in dev).
ENDLESSH_DEST_PORT = int(os.environ.get("ENDLESSH_DEST_PORT", "22"))
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100/loki/api/v1/push")

# Cowrie event ID to Trap House event type mapping
COWRIE_EVENT_MAP: dict[str, str] = {
    "cowrie.session.connect": "session_connect",
    "cowrie.session.closed": "session_disconnect",
    "cowrie.session.params": "session_params",
    "cowrie.login.success": "auth_success",
    "cowrie.login.failed": "auth_attempt",
    "cowrie.client.version": "client_version",
    "cowrie.client.fingerprint": "client_fingerprint",
    "cowrie.client.size": "client_size",
    "cowrie.client.kex": "client_kex",
    "cowrie.command.input": "command_exec",
    "cowrie.command.failed": "command_failed",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.session.file_download": "file_download",
    "cowrie.log.closed": "log_closed",
    "cowrie.direct-tcpip.request": "proxy_request",
    "cowrie.direct-tcpip.data": "proxy_data",
}

# MITRE ATT&CK mapping for Cowrie event types
MITRE_MAP: dict[str, tuple[str, str]] = {
    "auth_attempt": ("T1110.001", "credential-access"),
    "auth_success": ("T1078", "defense-evasion"),
    "command_exec": ("T1059", "execution"),
    "command_failed": ("T1059", "execution"),
    "file_upload": ("T1105", "command-and-control"),
    "file_download": ("T1105", "command-and-control"),
    "proxy_request": ("T1021", "lateral-movement"),
    "proxy_data": ("T1021", "lateral-movement"),
    "client_kex": ("T1049", "discovery"),
    "sql_injection": ("T1190", "initial-access"),
    "webshell_upload": ("T1505.003", "persistence"),
    "credential_use": ("T1552.001", "credential-access"),
    "file_access": ("T1083", "discovery"),
}

COWRIE_FINGERPRINT_FIELDS: tuple[tuple[str, str], ...] = (
    ("version", "ssh_client"),
    ("hassh", "hassh"),
    ("hasshAlgorithms", "hassh_algorithms"),
    ("kexAlgs", "kex_algorithms"),
    ("keyAlgs", "key_algorithms"),
)

COWRIE_DETAIL_FIELDS: tuple[tuple[str, str], ...] = (
    ("duration_ms", "duration_ms"),
    ("filename", "filename"),
    ("outfile", "outfile"),
    ("shasum", "shasum"),
    ("url", "url"),
    ("dst_ip", "dst_ip"),
    ("dst_port", "dst_port"),
    ("input", "input"),
    ("width", "terminal_width"),
    ("height", "terminal_height"),
    ("arch", "arch"),
    ("size", "size"),
    ("duplicate", "duplicate"),
)

EVENT_FIELDS: tuple[str, ...] = (
    "event_id",
    "timestamp",
    "source_service",
    "source_ip",
    "source_port",
    "dest_port",
    "event_type",
    "session_id",
    "cowrie_session",
    "protocol",
    "username",
    "command",
    "attacker_fingerprint",
    "mitre_technique",
    "mitre_tactic",
    "details",
    "raw_data",
)

DATABASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_service TEXT NOT NULL,
    source_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    event_type TEXT NOT NULL,
    session_id TEXT,
    cowrie_session TEXT,
    protocol TEXT,
    username TEXT,
    command TEXT,
    attacker_fingerprint TEXT,
    mitre_technique TEXT,
    mitre_tactic TEXT,
    details TEXT,
    raw_data TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_ip TEXT,
    source_service TEXT,
    start_time TEXT,
    end_time TEXT,
    event_count INTEGER DEFAULT 0,
    mitre_techniques TEXT,
    layers_reached TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
"""

EVENT_INSERT_SQL = f"""
INSERT OR IGNORE INTO events ({", ".join(EVENT_FIELDS)})
VALUES ({", ".join("?" for _ in EVENT_FIELDS)})
"""

SESSION_INSERT_SQL = """
INSERT INTO sessions (
    session_id, source_ip, source_service, start_time,
    end_time, event_count, mitre_techniques, layers_reached
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def stable_event_id(source: str, payload: str) -> str:
    """Derive a deterministic event_id from the raw event content.

    The shipper tracks file offsets in memory, so on restart it re-reads the
    current log file from the beginning. Using a content hash as the primary key
    (instead of a fresh UUID per read) makes re-ingestion idempotent: an
    INSERT OR IGNORE for an already-seen line is a no-op instead of a duplicate.
    """
    return hashlib.sha256(f"{source}|{payload}".encode("utf-8")).hexdigest()


def get_db() -> sqlite3.Connection:
    """Initialize SQLite database with schema."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript(DATABASE_SCHEMA)
    conn.commit()
    return conn


def _copy_present_fields(
    raw: dict[str, Any],
    fields: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    """Copy present source fields to their normalized names in order."""
    return {
        normalized_name: raw[source_name]
        for source_name, normalized_name in fields
        if source_name in raw
    }


def _detect_cowrie_tool(ssh_version: str) -> str:
    """Classify a Cowrie SSH client version using the existing heuristics."""
    normalized_version = ssh_version.lower()
    if "libssh" in normalized_version:
        return "libssh-based"
    if "openssh" in normalized_version:
        return "openssh"
    if "putty" in normalized_version:
        return "putty"
    return "unknown"


def _build_cowrie_fingerprint(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract ordered SSH fingerprint fields and the detected tool."""
    fingerprint = _copy_present_fields(raw, COWRIE_FINGERPRINT_FIELDS)
    fingerprint["tool"] = _detect_cowrie_tool(raw.get("version", ""))
    return fingerprint


def _build_cowrie_details(
    raw: dict[str, Any],
    cowrie_event_id: str,
) -> dict[str, Any]:
    """Extract event-specific Cowrie detail fields in storage order."""
    details: dict[str, Any] = {}
    if "password" in raw:
        details["password"] = "[REDACTED]"

    for source_name, normalized_name in COWRIE_DETAIL_FIELDS:
        if source_name not in raw:
            continue
        if (
            source_name == "dst_port"
            and not cowrie_event_id.startswith("cowrie.direct-tcpip")
        ):
            continue
        details[normalized_name] = raw[source_name]
    return details


def _mitre_mapping(event_type: str) -> tuple[str, str]:
    """Return the configured technique and tactic for an event type."""
    return MITRE_MAP.get(event_type, ("", ""))


def normalize_cowrie(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw Cowrie JSON event to the Trap House event schema."""
    cowrie_event_id = raw.get("eventid", "")
    event_type = COWRIE_EVENT_MAP.get(cowrie_event_id, "unknown")
    source_ip = raw.get("src_ip", "")
    session = raw.get("session", "")
    protocol = raw.get("protocol", "")

    # Use cowrie session as our session_id (it is already unique per session)
    session_id = session if session else str(uuid.uuid4())

    # Extract username and command from relevant events
    username = raw.get("username", "")
    command = raw.get("input", "")

    fingerprint = _build_cowrie_fingerprint(raw)
    details = _build_cowrie_details(raw, cowrie_event_id)
    mitre_technique, mitre_tactic = _mitre_mapping(event_type)

    return {
        "event_id": stable_event_id("cowrie", json.dumps(raw, sort_keys=True)),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_service": "cowrie",
        "source_ip": source_ip,
        "source_port": raw.get("src_port"),
        "dest_port": raw.get("dst_port"),
        "event_type": event_type,
        "session_id": session_id,
        "cowrie_session": session,
        "protocol": protocol,
        "username": username,
        "command": command,
        "attacker_fingerprint": json.dumps(fingerprint) if fingerprint else None,
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "details": json.dumps(details) if details else None,
        "raw_data": json.dumps(raw),
    }


def _parse_endlessh_connection(line: str) -> tuple[str, str]:
    """Extract the last host and port values from an Endlessh log line."""
    host = ""
    port = ""
    for part in line.split():
        if part.startswith("host="):
            host = part[5:]
        elif part.startswith("port="):
            port = part[5:]
    if host.startswith("::ffff:"):
        host = host[7:]
    return host, port


def normalize_endlessh(line: str) -> dict[str, Any] | None:
    """Parse Endlessh log lines. Endlessh logs ACCEPT and CLOSE lines to stdout,
    which the shipper reads via `docker logs` (see get_endlessh_logs)."""
    if "ACCEPT" not in line:
        return None

    host, port = _parse_endlessh_connection(line)
    return {
        "event_id": stable_event_id("endlessh", line),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_service": "endlessh",
        "source_ip": host,
        "source_port": int(port) if port else None,
        "dest_port": ENDLESSH_DEST_PORT,
        "event_type": "tarpit_connect",
        "session_id": stable_event_id("endlessh-session", line),
        "cowrie_session": None,
        "protocol": "ssh",
        "username": None,
        "command": None,
        "attacker_fingerprint": json.dumps({"tool": "unknown"}),
        "mitre_technique": "",
        "mitre_tactic": "",
        "details": json.dumps({"delay_seconds": 0, "bytes_sent": 0}),
        "raw_data": json.dumps({"raw_line": line}),
    }


def _detect_deception_tool(user_agent: str) -> str:
    """Classify a deception gateway user agent using existing labels."""
    normalized_user_agent = user_agent.lower()
    if "sqlmap" in normalized_user_agent:
        return "sqlmap"
    if "curl" in normalized_user_agent:
        return "curl"
    if "python" in normalized_user_agent:
        return "python-script"
    return "browser"


def _build_deception_fingerprint(raw_fingerprint: Any) -> dict[str, Any]:
    """Normalize the nested deception gateway fingerprint."""
    fingerprint: dict[str, Any] = {}
    user_agent = raw_fingerprint.get("user_agent", "")
    if user_agent:
        fingerprint["user_agent"] = user_agent

    tool = raw_fingerprint.get("tool", "")
    if tool:
        fingerprint["tool"] = tool
    elif user_agent:
        fingerprint["tool"] = _detect_deception_tool(user_agent)
    return fingerprint


def normalize_deception_gw(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a deception-gw JSONL event to the Trap House event schema.
    deception-gw writes events already conforming to the shared schema,
    so this is mostly a passthrough with field validation."""
    event_type = raw.get("event_type", "unknown")
    source_ip = raw.get("source_ip", "")
    session_id = raw.get("session_id", str(uuid.uuid4()))

    mitre_technique, mitre_tactic = _mitre_mapping(event_type)

    # deception-gw nests its fingerprint under "attacker_fingerprint" and its
    # per-event fields under "details" (see deception-gw/logger.py). Read from
    # those nested objects; the values are not present at the top level.
    raw_fp = raw.get("attacker_fingerprint") or {}
    details = raw.get("details") or {}

    fingerprint = _build_deception_fingerprint(raw_fp)

    return {
        "event_id": raw.get("event_id", str(uuid.uuid4())),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_service": "deception-gw",
        "source_ip": source_ip,
        "source_port": raw.get("source_port"),
        "dest_port": raw.get("dest_port", 8000),
        "event_type": event_type,
        "session_id": session_id,
        "cowrie_session": None,
        "protocol": "http",
        "username": details.get("username", ""),
        "command": details.get("command", ""),
        "attacker_fingerprint": json.dumps(fingerprint) if fingerprint else None,
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "details": json.dumps(raw.get("details", {})) if raw.get("details") else None,
        "raw_data": json.dumps(raw),
    }


def _build_loki_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Group normalized events into Loki streams by source service."""
    streams: dict[str, list[list[str]]] = {}
    for event in events:
        service = event.get("source_service", "unknown")
        timestamp_ns = str(int(time.time() * 1_000_000_000))
        log_line = json.dumps({
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "source_ip": event.get("source_ip"),
            "session_id": event.get("session_id"),
            "mitre_technique": event.get("mitre_technique"),
            "timestamp": event.get("timestamp"),
        })
        streams.setdefault(service, []).append([timestamp_ns, log_line])

    return {
        "streams": [
            {"stream": {"service": service}, "values": values}
            for service, values in streams.items()
        ]
    }


def push_to_loki(events: list[dict[str, Any]]) -> None:
    """Push a batch of normalized events to Loki for Grafana visualization.
    Failures are swallowed so Loki downtime never breaks the honeypot pipeline."""
    if not events:
        return
    try:
        data = json.dumps(_build_loki_payload(events)).encode("utf-8")
        req = urllib.request.Request(
            LOKI_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[log-shipper] Loki push failed (non-fatal): {e}")


def _update_session(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
    """Create a session row or increment its event count."""
    session_id = event["session_id"]
    session = conn.execute(
        "SELECT session_id FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()

    if session:
        conn.execute(
            "UPDATE sessions SET event_count = event_count + 1 WHERE session_id = ?",
            (session_id,),
        )
        return

    layers = [event["source_service"]]
    mitre_list = [event["mitre_technique"]] if event["mitre_technique"] else []
    conn.execute(
        SESSION_INSERT_SQL,
        (
            session_id,
            event["source_ip"],
            event["source_service"],
            event["timestamp"],
            None,
            1,
            json.dumps(mitre_list),
            json.dumps(layers),
        ),
    )


def insert_event(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
    """Insert a normalized event into SQLite.

    Uses INSERT OR IGNORE on the content-derived event_id, so re-reading an
    already-ingested log line is a no-op. Session tracking only runs when a row
    was actually inserted, so re-reads do not inflate session event counts.
    """
    values = tuple(event[field] for field in EVENT_FIELDS)
    cursor = conn.execute(EVENT_INSERT_SQL, values)

    # A duplicate (already-seen event_id) inserts no row; skip session tracking.
    if cursor.rowcount == 0:
        conn.commit()
        return

    if event["session_id"]:
        _update_session(conn, event)

    conn.commit()


def tail_file(filepath: Path, offset: int = 0) -> tuple[list[str], int]:
    """Read new lines from a file since the given offset.
    Returns (lines, new_offset)."""
    try:
        size = filepath.stat().st_size
        if size < offset:
            # File was truncated or rotated, start from beginning
            offset = 0

        with open(filepath, "r") as f:
            f.seek(offset)
            lines = f.readlines()
            new_offset = f.tell()
        return lines, new_offset
    except FileNotFoundError:
        return [], 0
    except Exception:
        return [], offset


def get_endlessh_logs(since_timestamp: float) -> list[str]:
    """Get endlessh logs since the given Unix timestamp via docker logs."""
    try:
        result = subprocess.run(
            ["docker", "logs", "--since", str(int(since_timestamp)),
             "--timestamps", ENDLESSH_CONTAINER],
            capture_output=True, text=True, timeout=10
        )
        lines = []
        for line in (result.stdout + result.stderr).splitlines():
            # Docker adds timestamp prefix: "2026-06-29T05:37:51.628Z ..."
            # Filter for ACCEPT lines only
            if "ACCEPT" in line:
                lines.append(line)
        return lines
    except Exception as e:
        print(f"[log-shipper] Error reading endlessh logs: {e}")
        return []


def _process_json_lines(
    conn: sqlite3.Connection,
    lines: list[str],
    source: str,
    normalizer: Callable[[dict[str, Any]], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize and store JSONL input while isolating malformed lines."""
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = normalizer(json.loads(line))
            insert_event(conn, event)
            events.append(event)
        except json.JSONDecodeError:
            print(f"[log-shipper] JSON parse error in {source}: {line[:100]}")
        except Exception as error:
            print(f"[log-shipper] Error processing {source} event: {error}")
    return events


def _process_endlessh_lines(
    conn: sqlite3.Connection,
    lines: list[str],
) -> list[dict[str, Any]]:
    """Normalize and store Endlessh input while isolating malformed lines."""
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            event = normalize_endlessh(line)
            if event is None:
                continue
            insert_event(conn, event)
            events.append(event)
        except Exception as error:
            print(f"[log-shipper] Error processing endlessh event: {error}")
    return events


def main() -> None:
    print(f"[log-shipper] Starting. LOG_DIR={LOG_DIR}, DB_PATH={DB_PATH}")
    conn = get_db()
    print("[log-shipper] SQLite database initialized")

    # Track file offsets for incremental reading (Cowrie and deception-gw)
    offsets: dict[str, int] = {}
    cowrie_file = LOG_DIR / "cowrie" / "cowrie.json"
    deception_gw_file = LOG_DIR / "deception-gw" / "deception-gw.json"
    json_sources = (
        ("cowrie", cowrie_file, normalize_cowrie),
        ("deception-gw", deception_gw_file, normalize_deception_gw),
    )

    # Track time for Endlessh docker logs polling
    last_endlessh_poll = time.time()

    print(
        f"[log-shipper] Watching: cowrie ({cowrie_file}), "
        f"deception-gw ({deception_gw_file}), endlessh (docker logs)"
    )
    print(f"[log-shipper] Loki push: {LOKI_URL}")

    while True:
        batch: list[dict[str, Any]] = []

        for source, filepath, normalizer in json_sources:
            lines, new_offset = tail_file(filepath, offsets.get(source, 0))
            offsets[source] = new_offset
            batch.extend(
                _process_json_lines(conn, lines, source, normalizer)
            )

        # Process Endlessh logs (docker logs poll every 10 seconds)
        now = time.time()
        if now - last_endlessh_poll > 10:
            endlessh_lines = get_endlessh_logs(last_endlessh_poll)
            batch.extend(_process_endlessh_lines(conn, endlessh_lines))
            last_endlessh_poll = now

        # Push batch to Loki
        if batch:
            push_to_loki(batch)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
