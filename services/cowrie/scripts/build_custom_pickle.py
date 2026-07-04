#!/usr/bin/env python3
"""Build a custom fs.pickle for cowrie with /home/admin/ decoy files.

Injects /home/admin/.env and /home/admin/README.md into the bundled
fs.pickle so attackers who SSH into cowrie and explore the filesystem
find planted decoy credentials.

Usage (inside the cowrie container):
    python3 /opt/scripts/build_custom_pickle.py

Or from the host:
    docker exec trap-cowrie python3 /opt/scripts/build_custom_pickle.py

The script reads the bundled fs.pickle, injects the admin home directory
with file contents from the honeyfs bind mount, and writes the result
to /cowrie/cowrie-git/var/fs.custom.pickle.

The cowrie.cfg points [shell] filesystem to this custom pickle.
"""

import calendar
import os
import pickle
import sys
import time
from typing import Any, Optional

# Entry list field indices (must match cowrie.shell.fs A_* constants exactly).
# Entry format: [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
#   [0] name: string
#   [1] type: 0=link, 1=dir, 2=file
#   [2] uid: owner user id
#   [3] gid: owner group id
#   [4] size: file size in bytes (or nominal size for dirs)
#   [5] mode: full stat mode (e.g. 33188 = 0o100644 for file, 16877 = 0o040755 for dir)
#   [6] ctime: unix timestamp
#   [7] contents: bytes (file) or list of child entries (dir)
#   [8] target: symlink target (None for non-links)
#   [9] realfile: on-disk honeyfs path (None; content is served from [7])
A_NAME = 0
A_TYPE = 1
A_UID = 2
A_GID = 3
A_SIZE = 4
A_MODE = 5
A_CTIME = 6
A_CONTENTS = 7
A_TARGET = 8
A_REALFILE = 9

# /home/admin and its decoy files are owned by the admin account (uid/gid 1000),
# matching the admin entry in honeyfs/etc/passwd so `ls -l` looks consistent.
ADMIN_UID = 1000
ADMIN_GID = 1000

T_LINK = 0
T_DIR = 1
T_FILE = 2

# stat modes
S_IFREG = 0o100000  # regular file
S_IFDIR = 0o040000  # directory
FILE_MODE_644 = S_IFREG | 0o644  # = 33188
DIR_MODE_755 = S_IFDIR | 0o755   # = 16877

# Paths
BUNDLED_PICKLE = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"
CUSTOM_PICKLE = "/cowrie/cowrie-git/var/fs.custom.pickle"
HONEYFS_HOME = "/cowrie/cowrie-git/honeyfs/home/admin"

# Files to inject into /home/admin/, each with a believable ctime that lines up
# with the maintenance log in README.md. Using fixed past dates (rather than the
# build time) avoids the tell of every planted file sharing one fresh mtime.
DECOY_FILES = [".env", "README.md"]
FILE_CTIME_DATES: dict[str, str] = {
    ".env": "2026-06-18",       # AWS backup integration added
    "README.md": "2026-06-25",  # last maintenance-log entry
}
ADMIN_DIR_DATE = "2026-06-15"   # home directory provisioned


def _epoch(date_str: str) -> int:
    """Return the UTC unix timestamp for a YYYY-MM-DD date (noon, for realism)."""
    return calendar.timegm(time.strptime(date_str + " 12:00:00", "%Y-%m-%d %H:%M:%S"))


def find(tree: Any, path: str) -> Optional[Any]:
    """Walk the pickle tree to find the entry at path."""
    parts = [p for p in path.split("/") if p]
    node = tree
    for p in parts:
        kids = node[A_CONTENTS] if isinstance(node[A_CONTENTS], list) else []
        m = next((c for c in kids if c[A_NAME] == p), None)
        if m is None:
            return None
        node = m
    return node


def find_in_tree(tree: Any, path: str) -> Optional[Any]:
    """Alias for find() used in verification."""
    return find(tree, path)


def main() -> None:
    if not os.path.exists(BUNDLED_PICKLE):
        print(f"ERROR: Bundled pickle not found at {BUNDLED_PICKLE}")
        sys.exit(1)

    with open(BUNDLED_PICKLE, "rb") as f:
        tree = pickle.load(f)

    home = find(tree, "/home")
    if home is None:
        print("ERROR: /home not found in pickle tree")
        sys.exit(1)

    # Remove existing admin entry if present (for idempotency)
    if isinstance(home[A_CONTENTS], list):
        home[A_CONTENTS] = [c for c in home[A_CONTENTS] if c[A_NAME] != "admin"]

    # Build admin directory with decoy files, each stamped with a fixed,
    # believable ctime. Match the bundled pickle's 10-element format.
    children: list[list[Any]] = []
    for filename in DECOY_FILES:
        filepath = os.path.join(HONEYFS_HOME, filename)
        if os.path.exists(filepath):
            content = open(filepath, "rb").read()
        else:
            print(f"WARNING: {filepath} not found, skipping")
            continue
        ctime = _epoch(FILE_CTIME_DATES.get(filename, ADMIN_DIR_DATE))
        # [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
        entry = [filename, T_FILE, ADMIN_UID, ADMIN_GID, len(content), FILE_MODE_644, ctime, content, None, None]
        children.append(entry)
        print(f"  Injected: /home/admin/{filename} ({len(content)} bytes)")

    # [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
    dir_ctime = _epoch(ADMIN_DIR_DATE)
    admin_entry = ["admin", T_DIR, ADMIN_UID, ADMIN_GID, 4096, DIR_MODE_755, dir_ctime, children, None, None]
    home[A_CONTENTS].append(admin_entry)

    # Ensure var directory exists
    os.makedirs(os.path.dirname(CUSTOM_PICKLE), exist_ok=True)

    with open(CUSTOM_PICKLE, "wb") as f:
        pickle.dump(tree, f)

    print(f"Custom pickle written to {CUSTOM_PICKLE} ({os.path.getsize(CUSTOM_PICKLE)} bytes)")

    # Verify
    with open(CUSTOM_PICKLE, "rb") as f:
        tree2 = pickle.load(f)
    admin2 = find(tree2, "/home/admin")
    if admin2 and isinstance(admin2[A_CONTENTS], list):
        print("Verified /home/admin contents:", [(c[A_NAME], c[A_TYPE]) for c in admin2[A_CONTENTS]])
    else:
        print("ERROR: Verification failed")
        sys.exit(1)


if __name__ == "__main__":
    main()