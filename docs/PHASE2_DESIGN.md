# Trap House Phase 2: Deception Middleware Design

## Overview
The deception-gw is a FastAPI fake corporate web app that attackers reach after finding decoy credentials in Cowrie. It implements a 5-layer deception maze that wastes attacker time while logging every interaction to the shared event schema.

## Goal
Feed attackers believable fake data and keep them going in circles, while producing high-value intelligence: credentials tried, SQL injection attempts, webshell uploads, file accesses, and canarytoken triggers.

## 5 Deception Layers

### Layer 1: Web Login
Route: GET/POST /login
Decoy credentials found in Cowrie's fake filesystem work here. After successful login, attacker reaches /dashboard.
Progressive delay: each failed login adds 2^n seconds (capped at 30s).

### Layer 2: Dashboard and Admin Panel
Route: GET /dashboard, /admin
Displays fake company stats and navigation to admin tools.

### Layer 3: SQL Injection in User Search
Route: GET /api/users?search=... (also accessible via /admin/users)
Intentional SQL injection vulnerability in the search parameter.
Returns 10,000 fake users. Some emails are canarytoken-laced.
Also exposes a fake "flag": comment in SQL result suggests further admin access.

### Layer 4: Webshell Upload
Route: GET/POST /admin/files
Accepts file uploads including .php, .asp, .jsp.
Uploaded "webshell" executes against an in-memory fake filesystem.
Commands are parsed and logged. No real execution.

### Layer 5: Fake AWS Keys and Maze Loop
Route: GET /admin/config
Displays fake AWS access keys and secret keys. Keys contain canarytoken triggers.
Route: GET /admin/backup
Fake backup page with DB credentials that lead back to /login (infinite loop).

## Maze State Machine

```
[SSH entry via Cowrie]
       |
       v
  /login (Layer 1)
       |
       v
  /dashboard (Layer 2)
       |
       +--> /admin/users (Layer 3: SQL injection)
       |         |
       |         +--> /api/users?search=' OR 1=1 --
       |         |
       v
       +--> /admin/files (Layer 4: webshell upload)
       |         |
       |         v
       +--> /admin/config (Layer 5: fake AWS keys + canarytokens)
       |
       v
  /admin/backup
       |
       +--> gives credentials that only work on /login
       +--> maze loops back to start
```

Sessions tracked via signed cookie: session_id, current_layer, failed_logins, commands_run, files_accessed.

## Decoy Credentials Bridge from Cowrie

Cowrie's fake filesystem contains a .env file with these credentials:
- username: admin, password: TrapH0use!2026
- username: devops, password: D3v0ps_S3cur1ty
- username: backup, password: b@ckup_s3rv3r_99

These credentials work on /login. On success, the app creates a session and logs an auth_success event.

Additional decoy credentials planted deeper in the maze:
- /admin/users reveals backup_admin / B@ckup!P@ss
- /admin/config reveals AWS keys (AKIATRAPHOUSE...)
- /admin/backup reveals db_admin / M@z3Loop#999 that loop to /login

## Routes

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| GET | / | Redirect to /login | No |
| GET | /health | Health check | No |
| GET | /login | Login page | No |
| POST | /login | Authenticate | No |
| GET | /logout | Clear session | Yes |
| GET | /dashboard | Main dashboard | Yes |
| GET | /admin | Admin index | Yes |
| GET | /admin/users | User search page | Yes |
| GET | /api/users | JSON API with SQL injection | No |
| GET | /admin/files | File manager / webshell upload page | Yes |
| POST | /admin/upload | Handle file upload | Yes |
| POST | /admin/shell | Webshell command execution (sandboxed) | Yes |
| GET | /admin/config | Configuration page with fake AWS keys | Yes |
| GET | /admin/backup | Backup page with looping credentials | Yes |

## SQL Injection Implementation (Safe)

The /api/users endpoint takes a search parameter. It detects SQL injection patterns (OR, UNION, --, ;, etc.) and returns the full fake dataset (10,000 rows). No real SQL query is constructed with attacker input. The dataset is entirely fake, stored in an in-memory list.

Result includes:
- id, name, email, department, role
- Some emails are canarytokens (e.g., testuser123@user.canarytokens.org)
- Fake comment at bottom: "Internal note: backup_admin has access to /admin/backup"

## Webshell Sandbox

Uploaded files are stored in an in-memory dictionary fake_fs keyed by path.
The /admin/shell endpoint accepts cmd and path parameters.
Command parsing (whitelist, no real execution):
- ls: list fake files in current directory
- cd: change fake directory
- cat: return fake file contents
- whoami: return root
- id: return uid=0(root)
- hostname: return corp-webapp-01
- pwd: return current fake path
- wget, curl: pretend to fetch, log attempt
- uname -a: return fake kernel string
- unknown: return "command not found" with fake bash error

No subprocess, no os.system, no eval, no exec.

## Canarytoken Integration

Controlled by environment variable ENABLE_CANARYTOKENS (default false).

If enabled: fake AWS keys trigger canarytokens.org webhook when used outside the honeypot.
If disabled: canary events logged locally as "would_trigger_canary" without network egress.

## Logging

All events written as JSONL to /var/log/trap-house/deception-gw.json per EVENT_SCHEMA.md.

Event types produced:
- auth_attempt (failed login)
- auth_success (successful login)
- command_exec (webshell command)
- file_access (file viewed or uploaded)
- sql_injection (search param contains SQL injection payload)
- credential_use (fake credential used, may trigger canary)
- webshell_upload (file uploaded)

## Tech Stack

- Python 3.12
- FastAPI
- Jinja2
- python-multipart (file uploads)
- Uvicorn
- In-memory data (no real database)
- Signed session cookies (itsdangerous)

## File Structure

```
services/deception-gw/
  Dockerfile
  requirements.txt
  main.py
  config.py
  maze.py
  logger.py
  fake_fs.py
  canary.py
  templates/
    base.html
    login.html
    dashboard.html
    admin_users.html
    admin_files.html
    admin_config.html
    admin_backup.html
    404.html
```

## Security Constraints

- No real filesystem access for webshell
- No outbound network except optional canarytokens webhook
- Runs as non-root user (UID 1000)
- Capabilities dropped
- No-new-privileges
- No subprocess, no eval, no exec, no os.system

## Testing

Verification for Phase 2:
1. Start full stack
2. GET /login returns login page (200)
3. POST /login with decoy credentials returns 302 to /dashboard
4. POST /login with wrong password triggers progressive delay
5. GET /api/users?search=' OR 1=1 -- returns 10000 rows
6. POST /admin/upload with .php file succeeds
7. POST /admin/shell with cmd=whoami returns fake root response
8. Events appear in SQLite via log-shipper
9. GET /health returns 200 OK