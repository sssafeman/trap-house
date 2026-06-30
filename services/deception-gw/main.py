"""Trap House deception-gw: fake NordTech Solutions corporate web app.

This is the attacker-facing deception middleware. It serves a believable
corporate portal whose every interactive surface is a trap: decoy logins, a
fake SQL-injectable user API, a sandboxed webshell against an in-memory
filesystem, and looping credentials. Every interaction is logged to JSONL per
EVENT_SCHEMA.md. There is no real database, no subprocess, no code execution.
"""
import asyncio
from typing import Any, Optional

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

import config
import logger
from fake_fs import WebshellSandbox
from maze import Maze

app = FastAPI(title="NordTech Solutions Portal")
templates = Jinja2Templates(directory="templates")
maze = Maze()

# Per-session webshell sandboxes, keyed by session_id. In memory only.
SANDBOXES: dict[str, WebshellSandbox] = {}

COOKIE_NAME = "session"

# Patterns that flag a search value as a SQL injection attempt.
SQLI_PATTERNS: tuple[str, ...] = (
    "'", "\"", " or ", " and ", " union ", "select ", "--", ";",
    "/*", "*/", " 1=1", "drop ", "insert ", "delete ", "sleep(", "0x",
    "information_schema", " like ", "@@", "char(",
)


def _build_fake_users() -> list[dict[str, Any]]:
    """Generate a deterministic 10,000-row fake user dataset in memory."""
    departments = ["Engineering", "Finance", "HR", "Sales", "IT", "Legal", "Support"]
    roles = ["user", "manager", "analyst", "admin", "contractor"]
    first = ["alex", "jordan", "sam", "casey", "morgan", "taylor", "riley", "jamie"]
    last = ["hansen", "olsen", "berg", "lund", "dahl", "moen", "vik", "haug"]
    users: list[dict[str, Any]] = []
    for i in range(10000):
        name = f"{first[i % len(first)].title()} {last[(i // 7) % len(last)].title()}"
        # Sprinkle canarytoken-laced email addresses through the dataset.
        if i % 250 == 0:
            email = f"testuser{i}@user.canarytokens.org"
        else:
            email = f"{first[i % len(first)]}.{last[(i // 7) % len(last)]}{i}@nordtech.no"
        users.append({
            "id": i + 1,
            "name": name,
            "email": email,
            "department": departments[i % len(departments)],
            "role": roles[i % len(roles)],
        })
    return users


FAKE_USERS: list[dict[str, Any]] = _build_fake_users()


# Request helpers ----------------------------------------------------------

def _source(request: Request) -> tuple[str, int]:
    """Return the attacker source IP and port, honoring X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    elif request.client:
        ip = request.client.host
    else:
        ip = "0.0.0.0"
    port = request.client.port if request.client else 0
    return ip, port


def _ua(request: Request) -> str:
    """Return the request User-Agent string."""
    return request.headers.get("user-agent", "")


def _session(request: Request) -> Optional[dict[str, Any]]:
    """Load the signed session from the request cookie, or None."""
    return maze.load(request.cookies.get(COOKIE_NAME))


def _require_session(request: Request) -> Optional[dict[str, Any]]:
    """Return the session if present, else None (caller redirects to /login)."""
    return _session(request)


def _persist(response: Response, session: dict[str, Any]) -> None:
    """Re-sign and attach the (possibly mutated) session cookie to a response."""
    response.set_cookie(
        COOKIE_NAME, maze.sign(session), httponly=True, samesite="lax", max_age=1800
    )


# Routes -------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "company": config.COMPANY_NAME, "error": None},
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
) -> Response:
    ip, port = _source(request)
    ua = _ua(request)
    expected = config.DECOY_CREDENTIALS.get(username)
    if expected is not None and password == expected:
        maze.reset_failures(ip)
        session = maze.new_session(username)
        logger.log_event(
            "auth_success", ip, port, session["session_id"],
            {
                "username": username,
                "password": "[REDACTED]",
                "credentials_source": config.CREDENTIAL_SOURCE.get(username, "decoy"),
            },
            user_agent=ua,
        )
        response = RedirectResponse(url="/dashboard", status_code=302)
        _persist(response, session)
        return response

    # Failed login: log, then apply progressive delay before responding.
    count = maze.record_failure(ip)
    logger.log_event(
        "auth_attempt", ip, port, None,
        {"username": username, "password": "[REDACTED]", "attempts": count},
        user_agent=ua,
    )
    delay = maze.delay_for(count)
    if delay:
        await asyncio.sleep(delay)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "company": config.COMPANY_NAME,
            "error": "Invalid username or password.",
        },
        status_code=401,
    )


@app.get("/logout")
async def logout(request: Request) -> Response:
    session = _session(request)
    if session:
        SANDBOXES.pop(session["session_id"], None)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    maze.advance(session, 2)
    stats = {
        "employees": 1284,
        "active_servers": 47,
        "open_tickets": 213,
        "revenue_q2": "NOK 84.2M",
    }
    response = templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "company": config.COMPANY_NAME,
            "username": session.get("username", "user"),
            "stats": stats,
        },
    )
    _persist(response, session)
    return response


@app.get("/admin", response_class=HTMLResponse)
async def admin_index(request: Request) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    maze.advance(session, 3)
    response = templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "company": config.COMPANY_NAME},
    )
    _persist(response, session)
    return response


@app.get("/api/users")
async def api_users(request: Request, search: str = "") -> JSONResponse:
    ip, port = _source(request)
    ua = _ua(request)
    lowered = search.lower()
    is_injection = any(pat in lowered for pat in SQLI_PATTERNS)

    if is_injection:
        rows = FAKE_USERS
        sess = _session(request)
        session_id = sess.get("session_id") if sess else None
        logger.log_event(
            "sql_injection", ip, port, session_id,
            {"endpoint": "/api/users", "payload": search, "rows_returned": len(rows)},
            user_agent=ua,
        )
    else:
        needle = lowered.strip()
        rows = [
            u for u in FAKE_USERS
            if not needle or needle in u["name"].lower() or needle in u["email"].lower()
        ][:50]

    payload: dict[str, Any] = {
        "count": len(rows),
        "results": rows,
        "_comment": "Internal note: backup_admin has access to /admin/backup",
    }
    return JSONResponse(content=payload)


@app.get("/admin/files", response_class=HTMLResponse)
async def admin_files(request: Request) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    maze.advance(session, 4)
    sandbox = SANDBOXES.setdefault(session["session_id"], WebshellSandbox())
    uploads = sandbox.fs.get("/var/www/uploads")
    response = templates.TemplateResponse(
        "admin_files.html",
        {
            "request": request,
            "company": config.COMPANY_NAME,
            "uploads": uploads if isinstance(uploads, list) else [],
            "output": None,
        },
    )
    _persist(response, session)
    return response


@app.post("/admin/upload")
async def admin_upload(request: Request, file: UploadFile) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    ip, port = _source(request)
    ua = _ua(request)
    raw = await file.read()
    content = raw.decode("utf-8", errors="replace")
    sandbox = SANDBOXES.setdefault(session["session_id"], WebshellSandbox())
    filename = file.filename or "upload.bin"
    path = sandbox.upload(filename, content)
    session["files_accessed"] = session.get("files_accessed", 0) + 1
    logger.log_event(
        "webshell_upload", ip, port, session["session_id"],
        {"filename": filename, "upload_path": path, "file_size": len(raw)},
        user_agent=ua,
    )
    response = RedirectResponse(url="/admin/files", status_code=302)
    _persist(response, session)
    return response


@app.post("/admin/shell", response_class=HTMLResponse)
async def admin_shell(request: Request, cmd: str = Form("")) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    ip, port = _source(request)
    ua = _ua(request)
    sandbox = SANDBOXES.setdefault(session["session_id"], WebshellSandbox())
    output = sandbox.execute(cmd)
    session["commands_run"] = session.get("commands_run", 0) + 1
    logger.log_event(
        "command_exec", ip, port, session["session_id"],
        {"command": cmd, "output": output, "exit_code": 0},
        user_agent=ua,
    )
    uploads = sandbox.fs.get("/var/www/uploads")
    response = templates.TemplateResponse(
        "admin_files.html",
        {
            "request": request,
            "company": config.COMPANY_NAME,
            "uploads": uploads if isinstance(uploads, list) else [],
            "output": output,
        },
    )
    _persist(response, session)
    return response


@app.get("/admin/config", response_class=HTMLResponse)
async def admin_config(request: Request) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    ip, port = _source(request)
    ua = _ua(request)
    maze.advance(session, 5)
    session["files_accessed"] = session.get("files_accessed", 0) + 1
    canary_triggered = config.ENABLE_CANARYTOKENS
    logger.log_event(
        "credential_use", ip, port, session["session_id"],
        {
            "credential_type": "aws_key",
            "credential_id": config.FAKE_AWS_CANARY_ID,
            "canarytoken_triggered": canary_triggered,
            "mode": "live" if config.ENABLE_CANARYTOKENS else "would_trigger_canary",
        },
        user_agent=ua,
    )
    response = templates.TemplateResponse(
        "admin_config.html",
        {
            "request": request,
            "company": config.COMPANY_NAME,
            "aws_access_key": config.FAKE_AWS_ACCESS_KEY,
            "aws_secret_key": config.FAKE_AWS_SECRET_KEY,
        },
    )
    _persist(response, session)
    return response


@app.get("/admin/backup", response_class=HTMLResponse)
async def admin_backup(request: Request) -> Response:
    session = _require_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    ip, port = _source(request)
    ua = _ua(request)
    session["files_accessed"] = session.get("files_accessed", 0) + 1
    logger.log_event(
        "file_access", ip, port, session["session_id"],
        {
            "file_path": "/admin/backup",
            "file_type": "decoy_credential",
            "canarytoken_id": None,
        },
        user_agent=ua,
    )
    response = templates.TemplateResponse(
        "admin_backup.html",
        {
            "request": request,
            "company": config.COMPANY_NAME,
            "db_user": "db_admin",
            "db_pass": config.DEEPER_CREDENTIALS["db_admin"],
        },
    )
    _persist(response, session)
    return response


@app.exception_handler(404)
async def not_found(request: Request, exc: Any) -> Response:
    return templates.TemplateResponse(
        "404.html",
        {"request": request, "company": config.COMPANY_NAME},
        status_code=404,
    )
