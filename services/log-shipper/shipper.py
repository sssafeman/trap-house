#!/usr/bin/env python3
"""
Trap House Log Shipper

Reads raw JSON logs from honeypot services (Cowrie, Endlessh),
normalizes them to the shared Trap House event schema (EVENT_SCHEMA.md),
and writes to a SQLite database.

Cowrie: reads JSONL from /var/log/trap-house/cowrie.json
Endlessh: reads stdout via `docker logs` (requires Docker socket mount)

Future phases will also push to Loki and trigger MITRE mapping.
"""

import json
import os
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Configuration
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/trap-house"))
DB_PATH = os.environ.get("DB_PATH", "/data/db/trap-house.db")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2"))
ENDLESSH_CONTAINER = os.environ.get("ENDLESSH_CONTAINER", "trap-endlessh")

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
    "auth_attempt": ("T1110", "credential-access"),
    "auth_success": ("T1078", "defense-evasion"),
    "command_exec": ("T1059", "execution"),
    "command_failed": ("T1059", "execution"),
    "file_upload": ("T1105", "command-and-control"),
    "file_download": ("T1105", "command-and-control"),
    "proxy_request": ("T1021", "lateral-movement"),
    "proxy_data": ("T1021", "lateral-movement"),
    "client_kex": ("T1049", "discovery"),
}


def get_db() -> sqlite3.Connection:
    """Initialize SQLite database with schema."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript(
        """
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
    )
    conn.commit()
    return conn


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

    # Build attacker fingerprint
    fingerprint: dict[str, Any] = {}
    if "version" in raw:
        fingerprint["ssh_client"] = raw["version"]
    if "hassh" in raw:
        fingerprint["hassh"] = raw["hassh"]
    if "hasshAlgorithms" in raw:
        fingerprint["hassh_algorithms"] = raw["hasshAlgorithms"]
    if "kexAlgs" in raw:
        fingerprint["kex_algorithms"] = raw["kexAlgs"]
    if "keyAlgs" in raw:
        fingerprint["key_algorithms"] = raw["keyAlgs"]

    # Tool fingerprinting (basic heuristics)
    tool = "unknown"
    ssh_version = raw.get("version", "")
    if "libssh" in ssh_version.lower():
        tool = "libssh-based"
    elif "openssh" in ssh_version.lower():
        tool = "openssh"
    elif "putty" in ssh_version.lower():
        tool = "putty"
    fingerprint["tool"] = tool

    # MITRE mapping
    mitre_technique = ""
    mitre_tactic = ""
    if event_type in MITRE_MAP:
        mitre_technique, mitre_tactic = MITRE_MAP[event_type]

    # Build details dict
    details: dict[str, Any] = {}
    if "password" in raw:
        details["password"] = "[REDACTED]"
    if "duration_ms" in raw:
        details["duration_ms"] = raw["duration_ms"]
    if "filename" in raw:
        details["filename"] = raw["filename"]
    if "outfile" in raw:
        details["outfile"] = raw["outfile"]
    if "shasum" in raw:
        details["shasum"] = raw["shasum"]
    if "url" in raw:
        details["url"] = raw["url"]
    if "dst_ip" in raw:
        details["dst_ip"] = raw["dst_ip"]
    if "dst_port" in raw and cowrie_event_id.startswith("cowrie.direct-tcpip"):
        details["dst_port"] = raw["dst_port"]
    if "input" in raw:
        details["input"] = raw["input"]
    if "width" in raw:
        details["terminal_width"] = raw["width"]
    if "height" in raw:
        details["terminal_height"] = raw["height"]
    if "arch" in raw:
        details["arch"] = raw["arch"]
    if "size" in raw:
        details["size"] = raw["size"]
    if "duplicate" in raw:
        details["duplicate"] = raw["duplicate"]

    return {
        "event_id": str(uuid.uuid4()),
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


def normalize_endlessh(line: str) -> dict[str, Any] | None:
    """Parse Endlessh log lines. Endlessh logs ACCEPT and CLOSE lines to stdout.
    The endlessh-log sidecar captures these to a file."""
    if "ACCEPT" in line:
        parts = line.split()
        host = ""
        port = ""
        for p in parts:
            if p.startswith("host="):
                host = p[5:]
            elif p.startswith("port="):
                port = p[5:]
        # Strip IPv6 prefix if present
        if host.startswith("::ffff:"):
            host = host[7:]
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_service": "endlessh",
            "source_ip": host,
            "source_port": int(port) if port else None,
            "dest_port": 2222,
            "event_type": "tarpit_connect",
            "session_id": str(uuid.uuid4()),
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
    return None


def insert_event(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
    """Insert a normalized event into SQLite."""
    conn.execute(
        """
        INSERT OR IGNORE INTO events (
            event_id, timestamp, source_service, source_ip, source_port,
            dest_port, event_type, session_id, cowrie_session, protocol,
            username, command, attacker_fingerprint, mitre_technique,
            mitre_tactic, details, raw_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["event_id"],
            event["timestamp"],
            event["source_service"],
            event["source_ip"],
            event["source_port"],
            event["dest_port"],
            event["event_type"],
            event["session_id"],
            event["cowrie_session"],
            event["protocol"],
            event["username"],
            event["command"],
            event["attacker_fingerprint"],
            event["mitre_technique"],
            event["mitre_tactic"],
            event["details"],
            event["raw_data"],
        ),
    )

    # Update session tracking
    if event["session_id"]:
        session = conn.execute(
            "SELECT session_id FROM sessions WHERE session_id = ?",
            (event["session_id"],),
        ).fetchone()

        if session:
            conn.execute(
                "UPDATE sessions SET event_count = event_count + 1 WHERE session_id = ?",
                (event["session_id"],),
            )
        else:
            layers = [event["source_service"]]
            mitre_list = [event["mitre_technique"]] if event["mitre_technique"] else []
            conn.execute(
                """
                INSERT INTO sessions (
                    session_id, source_ip, source_service, start_time,
                    end_time, event_count, mitre_techniques, layers_reached
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["session_id"],
                    event["source_ip"],
                    event["source_service"],
                    event["timestamp"],
                    None,
                    1,
                    json.dumps(mitre_list),
                    json.dumps(layers),
                ),
            )

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


def main() -> None:
    print(f"[log-shipper] Starting. LOG_DIR={LOG_DIR}, DB_PATH={DB_PATH}")
    conn = get_db()
    print("[log-shipper] SQLite database initialized")

    # Track file offsets for incremental reading (Cowrie)
    offsets: dict[str, int] = {}
    cowrie_file = LOG_DIR / "cowrie.json"

    # Track time for Endlessh docker logs polling
    last_endlessh_poll = time.time()

    print(f"[log-shipper] Watching: cowrie ({cowrie_file}), endlessh (docker logs)")

    while True:
        # Process Cowrie logs (file tail)
        offset = offsets.get("cowrie", 0)
        lines, new_offset = tail_file(cowrie_file, offset)
        offsets["cowrie"] = new_offset

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                event = normalize_cowrie(raw)
                insert_event(conn, event)
            except json.JSONDecodeError:
                print(f"[log-shipper] JSON parse error in cowrie: {line[:100]}")
            except Exception as e:
                print(f"[log-shipper] Error processing cowrie event: {e}")

        # Process Endlessh logs (docker logs poll every 10 seconds)
        now = time.time()
        if now - last_endlessh_poll > 10:
            endlessh_lines = get_endlessh_logs(last_endlessh_poll)
            for line in endlessh_lines:
                try:
                    event = normalize_endlessh(line)
                    if event is None:
                        continue
                    insert_event(conn, event)
                except Exception as e:
                    print(f"[log-shipper] Error processing endlessh event: {e}")
            last_endlessh_poll = now

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()