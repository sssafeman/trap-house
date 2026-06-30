"""In-memory fake filesystem and webshell sandbox.

There is no real filesystem access here. The "shell" matches commands against a
whitelist and returns canned fake output. There is no subprocess, eval, exec,
os.system, __import__, or compile anywhere in this module.
"""
import copy
from typing import Optional

HOSTNAME: str = "corp-webapp-01"
KERNEL: str = (
    "Linux corp-webapp-01 5.15.0-91-generic #101-Ubuntu SMP "
    "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
)

# A dict-based fake filesystem. Keys are absolute paths. Directory values are
# lists of child names. File values are strings of fake content.
INITIAL_FS: dict[str, object] = {
    "/": ["var", "etc", "home", "root", "tmp"],
    "/var": ["www"],
    "/var/www": ["html", "uploads"],
    "/var/www/html": ["index.php", "config.php"],
    "/var/www/html/index.php": "<?php include 'config.php'; ?>\n",
    "/var/www/html/config.php": (
        "<?php\n$db_host='10.0.0.12';\n$db_user='backup_admin';\n"
        "$db_pass='B@ckup!P@ss';\n?>\n"
    ),
    "/var/www/uploads": [],
    "/etc": ["passwd", "hostname"],
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "/etc/hostname": HOSTNAME + "\n",
    "/home": ["admin"],
    "/home/admin": [".env"],
    "/home/admin/.env": "DB_PASSWORD=M@z3Loop#999\nAWS_ACCESS_KEY=AKIATRAPHOUSE0000DEC0Y\n",
    "/root": ["flag.txt"],
    "/root/flag.txt": "Internal note: db_admin credentials work on the /login portal.\n",
    "/tmp": [],
}

# Whitelisted commands. Anything else returns a fake "command not found".
WHITELIST: set[str] = {
    "ls", "cd", "cat", "whoami", "id", "hostname", "pwd",
    "wget", "curl", "uname",
}


def _normalize(cwd: str, target: str) -> str:
    """Resolve a target path against the current directory, no real FS calls."""
    if target.startswith("/"):
        path = target
    elif target in ("", "."):
        path = cwd
    elif target == "..":
        path = "/" + "/".join([p for p in cwd.strip("/").split("/")[:-1] if p])
        path = path if path != "/" else "/"
    else:
        base = cwd.rstrip("/")
        path = f"{base}/{target}" if base else f"/{target}"
    if path != "/":
        path = path.rstrip("/")
    return path or "/"


class WebshellSandbox:
    """Per-session sandbox. Holds a private copy of the fake filesystem so that
    uploads by one attacker do not leak into another session."""

    def __init__(self) -> None:
        self.fs: dict[str, object] = copy.deepcopy(INITIAL_FS)
        self.cwd: str = "/var/www/html"

    def upload(self, filename: str, content: str) -> str:
        """Store an uploaded file in the fake uploads directory. Returns the
        fake path the file was 'written' to."""
        safe_name = filename.replace("/", "_").replace("..", "_")
        path = f"/var/www/uploads/{safe_name}"
        self.fs[path] = content
        listing = self.fs.get("/var/www/uploads")
        if isinstance(listing, list) and safe_name not in listing:
            listing.append(safe_name)
        return path

    def execute(self, raw: str) -> str:
        """Match a command against the whitelist and return fake output."""
        parts = raw.strip().split()
        if not parts:
            return ""
        cmd = parts[0]
        args = parts[1:]
        if cmd not in WHITELIST:
            return f"bash: {cmd}: command not found"
        handler = getattr(self, f"_cmd_{cmd}")
        return handler(args)

    def _cmd_ls(self, args: list[str]) -> str:
        target = self._normalize(args[-1]) if args and not args[-1].startswith("-") else self.cwd
        entry = self.fs.get(target)
        if entry is None:
            return f"ls: cannot access '{target}': No such file or directory"
        if isinstance(entry, list):
            return "  ".join(entry) if entry else ""
        # ls on a file just echoes the name.
        return target.rstrip("/").split("/")[-1]

    def _cmd_cd(self, args: list[str]) -> str:
        if not args:
            self.cwd = "/root"
            return ""
        target = self._normalize(args[0])
        entry = self.fs.get(target)
        if isinstance(entry, list):
            self.cwd = target
            return ""
        if entry is None:
            return f"bash: cd: {args[0]}: No such file or directory"
        return f"bash: cd: {args[0]}: Not a directory"

    def _cmd_cat(self, args: list[str]) -> str:
        if not args:
            return ""
        out: list[str] = []
        for arg in args:
            target = self._normalize(arg)
            entry = self.fs.get(target)
            if isinstance(entry, str):
                out.append(entry.rstrip("\n"))
            elif isinstance(entry, list):
                out.append(f"cat: {arg}: Is a directory")
            else:
                out.append(f"cat: {arg}: No such file or directory")
        return "\n".join(out)

    def _cmd_whoami(self, args: list[str]) -> str:
        return "root"

    def _cmd_id(self, args: list[str]) -> str:
        return "uid=0(root) gid=0(root) groups=0(root)"

    def _cmd_hostname(self, args: list[str]) -> str:
        return HOSTNAME

    def _cmd_pwd(self, args: list[str]) -> str:
        return self.cwd

    def _cmd_wget(self, args: list[str]) -> str:
        url = args[-1] if args else "(none)"
        return (
            f"--{url}--  resolving host... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address"
        )

    def _cmd_curl(self, args: list[str]) -> str:
        url = args[-1] if args else "(none)"
        return f"curl: (6) Could not resolve host: {url}"

    def _cmd_uname(self, args: list[str]) -> str:
        if args and "-a" in args:
            return KERNEL
        return "Linux"

    def _normalize(self, target: str) -> str:
        return _normalize(self.cwd, target)
