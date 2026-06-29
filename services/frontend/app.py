"""Trap House SOC dashboard.

FastAPI app that serves the custom threat intelligence frontend: HTML templates,
static assets, and a set of read-only JSON API endpoints backed by the shared
SQLite intel store. All database access is read-only SELECT. The app never
writes to the database.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("DB_PATH", "/data/db/trap-house.db")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(title="Trap House SOC Dashboard")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def get_conn() -> sqlite3.Connection:
    """Open a read-only connection to the intel store.

    The database may be in WAL mode on a read-only mounted volume, so first try
    a plain read-only open and fall back to an immutable open if the connection
    cannot be established (for example when the -shm file cannot be mapped).
    """
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    except sqlite3.OperationalError:
        conn = sqlite3.connect(f"file:{DB_PATH}?immutable=1", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def query(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    """Run a read-only query and return rows as a list of dicts.

    On any database error (for example a missing database during early boot)
    an empty list is returned so the dashboard degrades gracefully.
    """
    try:
        conn = get_conn()
    except sqlite3.OperationalError:
        return []
    try:
        cur = conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def query_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    """Run a read-only query expected to return a single row."""
    rows = query(sql, params)
    return rows[0] if rows else {}


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe used by docker and the verification script."""
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Serve the main dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/api/stats")
async def api_stats() -> JSONResponse:
    """Summary counts for the top stats bar: events, attackers, sessions, techniques."""
    stats = query_one(
        """
        SELECT
            (SELECT COUNT(*) FROM events) AS events,
            (SELECT COUNT(DISTINCT source_ip) FROM events
                WHERE source_ip IS NOT NULL AND source_ip != '') AS attackers,
            (SELECT COUNT(DISTINCT session_id) FROM events
                WHERE session_id IS NOT NULL AND session_id != '') AS sessions,
            (SELECT COUNT(DISTINCT technique_id) FROM techniques) AS techniques
        """
    )
    if not stats:
        stats = {"events": 0, "attackers": 0, "sessions": 0, "techniques": 0}
    return JSONResponse(stats)


@app.get("/api/attackers")
async def api_attackers() -> JSONResponse:
    """Top attackers ranked by computed risk score."""
    rows = query(
        """
        SELECT source_ip, event_count, session_count, risk_score,
               tools_detected, mitre_techniques, top_username, last_seen
        FROM attackers
        ORDER BY risk_score DESC
        LIMIT 100
        """
    )
    return JSONResponse(rows)


@app.get("/api/events")
async def api_events(limit: int = 50, offset: int = 0) -> JSONResponse:
    """Recent events with pagination via limit and offset."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    rows = query(
        """
        SELECT event_id, timestamp, source_service, source_ip, event_type,
               mitre_technique, command, username, session_id
        FROM events
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return JSONResponse(rows)


@app.get("/api/events/filter")
async def api_events_filter(
    source_service: str | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    limit: int = 200,
) -> JSONResponse:
    """Filtered events. Any combination of service, event type, and source IP."""
    limit = max(1, min(limit, 500))
    clauses: list[str] = []
    params: list[Any] = []
    if source_service:
        clauses.append("source_service = ?")
        params.append(source_service)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    rows = query(
        f"""
        SELECT event_id, timestamp, source_service, source_ip, event_type,
               mitre_technique, command, username, session_id
        FROM events
        {where}
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        tuple(params),
    )
    return JSONResponse(rows)


@app.get("/api/techniques")
async def api_techniques() -> JSONResponse:
    """Technique counts grouped by technique id, for the MITRE heatmap."""
    rows = query(
        """
        SELECT technique_id,
               MAX(name) AS name,
               MAX(tactic) AS tactic,
               COUNT(*) AS count
        FROM techniques
        GROUP BY technique_id
        ORDER BY count DESC
        """
    )
    return JSONResponse(rows)


@app.get("/api/sessions")
async def api_sessions() -> JSONResponse:
    """Recent sessions with their event counts and layers reached."""
    rows = query(
        """
        SELECT session_id, source_ip, source_service, start_time, end_time,
               event_count, mitre_techniques, layers_reached
        FROM sessions
        ORDER BY start_time DESC
        LIMIT 50
        """
    )
    return JSONResponse(rows)


@app.get("/api/sessions/{session_id}/events")
async def api_session_events(session_id: str) -> JSONResponse:
    """All events for a single session, ordered chronologically for replay."""
    rows = query(
        """
        SELECT event_id, timestamp, event_type, source_service,
               command, username, mitre_technique
        FROM events
        WHERE session_id = ?
        ORDER BY timestamp ASC
        """,
        (session_id,),
    )
    return JSONResponse(rows)


@app.get("/api/attack-map")
async def api_attack_map() -> JSONResponse:
    """Source IPs with attack counts, enriched with risk score and techniques.

    Geolocation is resolved client-side. In dev the source IPs are internal
    Docker addresses, so the map clusters; in production these are real
    attacker IPs and the map shows global attack origins.
    """
    rows = query(
        """
        SELECT e.source_ip AS source_ip,
               COUNT(*) AS attacks,
               COALESCE(a.risk_score, 0) AS risk_score,
               COALESCE(a.mitre_techniques, '') AS mitre_techniques
        FROM events e
        LEFT JOIN attackers a ON e.source_ip = a.source_ip
        WHERE e.source_ip IS NOT NULL AND e.source_ip != ''
        GROUP BY e.source_ip
        ORDER BY attacks DESC
        LIMIT 100
        """
    )
    return JSONResponse(rows)


@app.get("/api/timeline")
async def api_timeline() -> JSONResponse:
    """Last 200 events for the horizontal attack timeline."""
    rows = query(
        """
        SELECT event_id, timestamp, event_type, source_service, source_ip,
               command, username, mitre_technique
        FROM events
        ORDER BY timestamp DESC
        LIMIT 200
        """
    )
    return JSONResponse(rows)
