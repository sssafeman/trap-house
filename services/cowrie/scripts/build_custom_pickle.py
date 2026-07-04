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

import os
import pickle
import sys

# Entry tuple field indices (from cowrie.shell.fs / honeyfs analysis)
# Entry format: (name, type, st_mode_flags, uid, gid_or_size, st_mode, mtime, contents, target, extra)
#   [0] name: string
#   [1] type: 0=link, 1=dir, 2=file
#   [2] st_mode flags (0 in bundled pickle)
#   [3] uid
#   [4] gid (for dirs) or size (for files) 
#   [5] st_mode: full stat mode (e.g. 33188 = 0o100644 for file, 16877 = 0o040755 for dir)
#   [6] mtime: unix timestamp
#   [7] contents: bytes (file) or list (dir)
#   [8] target: symlink target (None for non-links)
#   [9] extra: None in bundled pickle
A_NAME = 0
A_TYPE = 1
A_FLAGS = 2
A_UID = 3
A_GID = 4
A_MODE = 5
A_MTIME = 6
A_CONTENTS = 7
A_TARGET = 8
A_EXTRA = 9

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

# Files to inject into /home/admin/
DECOY_FILES = [".env", "README.md"]


def find(tree, path):
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


def find_in_tree(tree, path):
    """Alias for find() used in verification."""
    return find(tree, path)


def main():
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

    # Build admin directory with decoy files
    # Match the bundled pickle's 10-element format
    import time as _time
    now = int(_time.time())

    children = []
    for filename in DECOY_FILES:
        filepath = os.path.join(HONEYFS_HOME, filename)
        if os.path.exists(filepath):
            content = open(filepath, "rb").read()
        else:
            print(f"WARNING: {filepath} not found, skipping")
            continue
        # (name, type, flags, uid, size, st_mode, mtime, contents, target, extra)
        entry = [filename, T_FILE, 0, 0, len(content), FILE_MODE_644, now, content, None, None]
        children.append(entry)
        print(f"  Injected: /home/admin/{filename} ({len(content)} bytes)")

    # (name, type, flags, uid, gid, st_mode, mtime, contents, target, extra)
    admin_entry = ["admin", T_DIR, 0, 0, 1000, DIR_MODE_755, now, children, None, None]
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